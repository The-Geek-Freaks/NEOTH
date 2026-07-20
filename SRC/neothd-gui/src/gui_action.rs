//! Fail-closed subprocess boundary for GUI-triggered CLI actions.
//!
//! GUI callbacks must not infer success from human-readable stdout. Every
//! mutation crosses this boundary, which requires both a successful process
//! exit and a typed JSON acknowledgement before the UI may report success or
//! refresh dependent state.

use std::path::Path;
use std::process::{Command, Output};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const MAX_DIAGNOSTIC_CHARS: usize = 400;
const EXPECTED_CATALOG_VERSION: u32 = 2;
const MAX_CATALOG_PROVIDERS: usize = 16;
const MAX_MODELS_PER_PROVIDER: usize = 4096;
const MAX_MODEL_ID_CHARS: usize = 512;
const MAX_MODEL_DISPLAY_CHARS: usize = 256;
const MAX_MODEL_SUMMARY_CHARS: usize = 200;
const MAX_CATALOG_ERROR_CHARS: usize = 512;

fn valid_catalog_text(value: &str, max_chars: usize) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.chars().count() <= max_chars
        && !value.chars().any(char::is_control)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub struct JsonReceipt<T> {
    pub acknowledgement: T,
    pub stderr: Option<String>,
}

/// Exact `neoth mcp call --output json` wire acknowledgement. MCP reports
/// tool-level failures inside an otherwise valid JSON-RPC response, so the GUI
/// must verify `isError` in addition to the child process exit status.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallAck {
    pub content: Vec<serde_json::Value>,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

impl McpToolCallAck {
    pub fn verify_success(&self) -> Result<(), String> {
        if self.is_error {
            return Err("MCP tool reported an execution failure".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CatalogRefreshResult {
    Fresh,
    Refreshed,
    Partial,
    NoDiscoverableSources,
    NoSources,
}

/// Exact `neoth catalog refresh --output json` mutation receipt. The provider
/// sets are part of the contract so an incomplete refresh cannot be presented
/// as a fully rebuilt catalog.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogRefreshAck {
    pub operation: String,
    pub path: String,
    pub catalog_version: u32,
    pub catalog_generation: Option<u64>,
    pub catalog_hash: Option<String>,
    pub catalog_changed: bool,
    pub result: CatalogRefreshResult,
    pub stale_only: bool,
    pub configured: Vec<String>,
    pub fresh: Vec<String>,
    pub refreshed: Vec<String>,
    pub failed: Vec<String>,
    pub superseded: Vec<String>,
    pub skipped_no_creds: Vec<String>,
    pub credential_failures: Vec<String>,
    pub configuration_failures: Vec<String>,
    pub unsupported: Vec<String>,
    pub blocked_no_consent: Vec<String>,
}

impl CatalogRefreshAck {
    fn verified_snapshot(&self) -> Result<Option<CatalogSnapshotAck>, String> {
        if self.catalog_version != EXPECTED_CATALOG_VERSION {
            return Err(format!(
                "catalog acknowledgement uses schema version {}, expected {}",
                self.catalog_version, EXPECTED_CATALOG_VERSION
            ));
        }
        match (&self.catalog_generation, &self.catalog_hash) {
            (None, None) => Ok(None),
            (Some(generation), Some(hash)) if valid_sha256(hash) => Ok(Some(CatalogSnapshotAck {
                generation: *generation,
                hash: hash.clone(),
            })),
            (Some(_), Some(_)) => {
                Err("catalog acknowledgement hash is not lowercase SHA-256".to_string())
            }
            _ => Err(
                "catalog acknowledgement generation and hash are not an atomic snapshot"
                    .to_string(),
            ),
        }
    }

    fn classify(
        &self,
        expected_path: &Path,
        expected_stale_only: bool,
    ) -> Result<CatalogRefreshOutcome, String> {
        require_action(&self.operation, "catalog.refresh")?;
        require_exact_path(&self.path, expected_path)?;
        if self.stale_only != expected_stale_only {
            return Err("catalog acknowledgement does not match requested stale-only mode".into());
        }
        let snapshot = self.verified_snapshot()?;

        let known_provider = |provider: &str| {
            matches!(
                provider,
                "anthropic_api"
                    | "openai_api"
                    | "gemini_api"
                    | "openai_compat"
                    | "aws_bedrock"
                    | "invalid_provider"
                    | "local_qwen"
                    | "local_ouro"
                    | "local_ollama"
                    | "recursive_mas"
                    | "azure_openai"
                    | "cohere_api"
                    | "copilot_api"
                    | "none"
            )
        };
        let mut configured = std::collections::HashSet::new();
        for provider in &self.configured {
            if !known_provider(provider) || !configured.insert(provider.as_str()) {
                return Err(
                    "catalog acknowledgement contains an invalid configured-provider set"
                        .to_string(),
                );
            }
        }

        let mut outcomes = std::collections::HashSet::new();
        for (field, values) in [
            ("fresh", &self.fresh),
            ("refreshed", &self.refreshed),
            ("failed", &self.failed),
            ("superseded", &self.superseded),
            ("skipped_no_creds", &self.skipped_no_creds),
            ("credential_failures", &self.credential_failures),
            ("configuration_failures", &self.configuration_failures),
            ("unsupported", &self.unsupported),
            ("blocked_no_consent", &self.blocked_no_consent),
        ] {
            for provider in values {
                if !known_provider(provider) {
                    return Err(format!(
                        "catalog acknowledgement contains an invalid `{field}` provider id"
                    ));
                }
                if !outcomes.insert(provider.as_str()) {
                    return Err(format!(
                        "catalog acknowledgement repeats provider `{provider}` across result sets"
                    ));
                }
            }
        }
        if configured != outcomes {
            return Err(
                "catalog acknowledgement outcomes do not cover its configured provider scope"
                    .to_string(),
            );
        }
        if !self.stale_only && !self.fresh.is_empty() {
            return Err(
                "full catalog refresh unexpectedly acknowledged an already-fresh provider"
                    .to_string(),
            );
        }

        let has_incomplete_provider = !self.failed.is_empty()
            || !self.superseded.is_empty()
            || !self.skipped_no_creds.is_empty()
            || !self.credential_failures.is_empty()
            || !self.configuration_failures.is_empty()
            || !self.blocked_no_consent.is_empty();
        if (!self.fresh.is_empty() || !self.refreshed.is_empty() || !self.failed.is_empty())
            && snapshot.is_none()
        {
            return Err(
                "catalog acknowledgement references stored providers without a committed snapshot"
                    .to_string(),
            );
        }
        if self.catalog_changed && snapshot.is_none() {
            return Err(
                "catalog acknowledgement reports a durable change without a committed snapshot"
                    .to_string(),
            );
        }
        if (!self.refreshed.is_empty() || !self.failed.is_empty()) && !self.catalog_changed {
            return Err(
                "catalog acknowledgement persisted provider outcomes without marking the catalog changed"
                    .to_string(),
            );
        }
        let unsupported_note = if self.unsupported.is_empty() {
            String::new()
        } else {
            format!(
                " {} configured adapter(s) do not expose a remote model catalog.",
                self.unsupported.len()
            )
        };

        match self.result {
            CatalogRefreshResult::Fresh
                if self.stale_only
                    && !self.catalog_changed
                    && !self.configured.is_empty()
                    && self.fresh.len() + self.unsupported.len() == self.configured.len()
                    && self.refreshed.is_empty()
                    && self.failed.is_empty()
                    && self.skipped_no_creds.is_empty()
                    && self.credential_failures.is_empty()
                    && self.configuration_failures.is_empty()
                    && self.blocked_no_consent.is_empty() =>
            {
                Ok(CatalogRefreshOutcome::Complete {
                    message: format!("Model catalog is already fresh.{unsupported_note}"),
                    changed: false,
                    snapshot,
                })
            }
            CatalogRefreshResult::Refreshed
                if self.catalog_changed
                    && !self.refreshed.is_empty()
                    && !has_incomplete_provider =>
            {
                let already_fresh = if self.fresh.is_empty() {
                    String::new()
                } else {
                    format!(", {} already fresh", self.fresh.len())
                };
                let provider_label = if self.refreshed.len() == 1 {
                    "provider"
                } else {
                    "providers"
                };
                Ok(CatalogRefreshOutcome::Complete {
                    message: format!(
                        "Model catalog refreshed from {} {provider_label}{already_fresh}.{unsupported_note}",
                        self.refreshed.len(),
                    ),
                    changed: true,
                    snapshot,
                })
            }
            CatalogRefreshResult::Partial if has_incomplete_provider => {
                let mut causes = Vec::new();
                if !self.failed.is_empty() {
                    causes.push(format!("fetch failed: {}", self.failed.join(", ")));
                }
                if !self.superseded.is_empty() {
                    causes.push(format!(
                        "superseded by a newer refresh or clear: {}",
                        self.superseded.join(", ")
                    ));
                }
                if !self.skipped_no_creds.is_empty() {
                    causes.push(format!(
                        "credentials missing: {}",
                        self.skipped_no_creds.join(", ")
                    ));
                }
                if !self.credential_failures.is_empty() {
                    causes.push(format!(
                        "credential resolution failed: {}",
                        self.credential_failures.join(", ")
                    ));
                }
                if !self.configuration_failures.is_empty() {
                    causes.push(format!(
                        "required configuration missing: {}",
                        self.configuration_failures.join(", ")
                    ));
                }
                if !self.unsupported.is_empty() {
                    causes.push(format!(
                        "model discovery unsupported: {}",
                        self.unsupported.join(", ")
                    ));
                }
                if !self.blocked_no_consent.is_empty() {
                    causes.push(format!(
                        "instance consent missing: {}",
                        self.blocked_no_consent.join(", ")
                    ));
                }
                Ok(CatalogRefreshOutcome::Incomplete {
                    message: format!(
                        "Catalog refresh incomplete ({}). Existing catalog entries were not assumed fresh.",
                        causes.join("; ")
                    ),
                    changed: self.catalog_changed,
                    snapshot,
                })
            }
            CatalogRefreshResult::NoDiscoverableSources
                if !self.configured.is_empty()
                    && self.unsupported.len() == self.configured.len() =>
            {
                Ok(CatalogRefreshOutcome::Complete {
                    message: if self.unsupported.len() == 1 {
                        "The configured provider adapter does not expose a remote model catalog; no refresh is needed."
                            .to_string()
                    } else {
                        "The configured provider adapters do not expose a remote model catalog; no refresh is needed."
                            .to_string()
                    },
                    changed: self.catalog_changed,
                    snapshot,
                })
            }
            CatalogRefreshResult::NoSources
                if self.configured.is_empty() && outcomes.is_empty() =>
            {
                Ok(CatalogRefreshOutcome::Incomplete {
                    message:
                        "No model-provider source is configured. Configure a provider, then retry."
                            .to_string(),
                    changed: self.catalog_changed,
                    snapshot,
                })
            }
            _ => Err("catalog acknowledgement result contradicts its provider sets".to_string()),
        }
    }

    #[cfg(test)]
    pub fn verify(
        &self,
        expected_path: &Path,
        expected_stale_only: bool,
    ) -> Result<String, String> {
        match self.classify(expected_path, expected_stale_only)? {
            CatalogRefreshOutcome::Complete { message, .. } => Ok(message),
            CatalogRefreshOutcome::Incomplete { message, .. } => Err(message),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogRefreshOutcome {
    Complete {
        message: String,
        changed: bool,
        snapshot: Option<CatalogSnapshotAck>,
    },
    Incomplete {
        message: String,
        changed: bool,
        snapshot: Option<CatalogSnapshotAck>,
    },
}

/// Strict readback contract for `neoth catalog list --output json`. A refresh
/// result is never presented as loaded state until this read-only subprocess
/// exits successfully and every nested field matches the CLI schema.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogListAck {
    operation: String,
    path: String,
    state: CatalogListState,
    catalog_version: u32,
    catalog_generation: Option<u64>,
    catalog_hash: Option<String>,
    providers: std::collections::BTreeMap<String, CatalogProviderAck>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CatalogListState {
    Present,
    Missing,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogProviderAck {
    fetched_at_unix: u64,
    source: CatalogSourceAck,
    last_error: Option<String>,
    models: Vec<CatalogModelAck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogSnapshotAck {
    generation: u64,
    hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum CatalogSourceAck {
    Cli,
    Api,
    Bundled,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogModelAck {
    id: String,
    display_name: Option<String>,
    summary: Option<String>,
    deprecated: bool,
}

impl CatalogListAck {
    fn verify(
        &self,
        expected_path: &Path,
        expected_generation: Option<u64>,
        expected_hash: Option<&str>,
    ) -> Result<(), String> {
        require_action(&self.operation, "catalog.list")?;
        require_exact_path(&self.path, expected_path)?;
        if self.catalog_version != EXPECTED_CATALOG_VERSION {
            return Err(format!(
                "catalog list uses schema version {}, expected {}",
                self.catalog_version, EXPECTED_CATALOG_VERSION
            ));
        }
        if expected_generation.is_some() != expected_hash.is_some() {
            return Err(
                "catalog readback expectation does not describe one atomic snapshot".to_string(),
            );
        }

        match self.state {
            CatalogListState::Missing => {
                if self.catalog_generation.is_some()
                    || self.catalog_hash.is_some()
                    || !self.providers.is_empty()
                {
                    return Err(
                        "missing catalog acknowledgement contains persisted state".to_string()
                    );
                }
                if expected_generation.is_some() {
                    return Err(
                        "catalog disappeared before the committed refresh snapshot was read back"
                            .to_string(),
                    );
                }
            }
            CatalogListState::Present => {
                let (Some(generation), Some(hash)) =
                    (self.catalog_generation, self.catalog_hash.as_deref())
                else {
                    return Err(
                        "present catalog acknowledgement is missing its atomic snapshot"
                            .to_string(),
                    );
                };
                if !valid_sha256(hash) {
                    return Err("catalog list hash is not lowercase SHA-256".to_string());
                }
                if let Some(expected) = expected_generation
                    && generation != expected
                {
                    return Err(format!(
                        "catalog readback generation {generation} does not match committed generation {expected}"
                    ));
                }
                if let Some(expected) = expected_hash
                    && hash != expected
                {
                    return Err(
                        "catalog readback hash does not match the committed refresh snapshot"
                            .to_string(),
                    );
                }
            }
        }

        if self.providers.len() > MAX_CATALOG_PROVIDERS {
            return Err("catalog list contains too many providers".to_string());
        }
        for (provider, entry) in &self.providers {
            if !matches!(
                provider.as_str(),
                "anthropic_api" | "openai_api" | "gemini_api" | "openai_compat" | "aws_bedrock"
            ) {
                return Err(format!(
                    "catalog list contains unknown provider key `{provider}`"
                ));
            }
            if !entry.models.is_empty() && entry.fetched_at_unix == 0 {
                return Err(format!(
                    "catalog provider `{provider}` has models without a fetch timestamp"
                ));
            }
            if entry.models.len() > MAX_MODELS_PER_PROVIDER {
                return Err(format!(
                    "catalog provider `{provider}` contains too many models"
                ));
            }
            if entry
                .last_error
                .as_deref()
                .is_some_and(|error| !valid_catalog_text(error, MAX_CATALOG_ERROR_CHARS))
            {
                return Err(format!(
                    "catalog provider `{provider}` contains an invalid error"
                ));
            }
            let mut model_ids = std::collections::HashSet::new();
            for model in &entry.models {
                if !valid_catalog_text(&model.id, MAX_MODEL_ID_CHARS) {
                    return Err(format!(
                        "catalog provider `{provider}` contains an invalid model id"
                    ));
                }
                if !model_ids.insert(model.id.as_str()) {
                    return Err(format!(
                        "catalog provider `{provider}` repeats model id `{}`",
                        model.id
                    ));
                }
                if model
                    .display_name
                    .as_deref()
                    .is_some_and(|display| !valid_catalog_text(display, MAX_MODEL_DISPLAY_CHARS))
                {
                    return Err(format!(
                        "catalog provider `{provider}` contains an invalid model display name"
                    ));
                }
                if model
                    .summary
                    .as_deref()
                    .is_some_and(|summary| !valid_catalog_text(summary, MAX_MODEL_SUMMARY_CHARS))
                {
                    return Err(format!(
                        "catalog provider `{provider}` contains an overlong model summary"
                    ));
                }
            }
        }
        Ok(())
    }
}

impl CatalogRefreshOutcome {
    pub fn message(&self) -> &str {
        match self {
            Self::Complete { message, .. } | Self::Incomplete { message, .. } => message,
        }
    }

    pub fn catalog_changed(&self) -> bool {
        match self {
            Self::Complete { changed, .. } | Self::Incomplete { changed, .. } => *changed,
        }
    }

    pub fn committed_snapshot(&self) -> Option<(u64, &str)> {
        let snapshot = match self {
            Self::Complete { snapshot, .. } | Self::Incomplete { snapshot, .. } => snapshot,
        };
        snapshot
            .as_ref()
            .map(|snapshot| (snapshot.generation, snapshot.hash.as_str()))
    }

    pub fn toast_kind(&self) -> &'static str {
        match self {
            Self::Complete { .. } => "success",
            Self::Incomplete { .. } => "warn",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundtruthAddAck {
    pub operation: String,
    pub id: i64,
    pub scope: String,
    pub statement: String,
    pub path: String,
}

impl GroundtruthAddAck {
    pub fn verify(
        &self,
        expected_statement: &str,
        expected_scope: &str,
        expected_path: &Path,
    ) -> Result<(), String> {
        require_action(&self.operation, "groundtruth.add")?;
        if self.id <= 0 {
            return Err("ground-truth acknowledgement is missing its row id".to_string());
        }
        if self.statement != expected_statement {
            return Err(
                "ground-truth acknowledgement does not match the submitted statement".to_string(),
            );
        }
        require_id(&self.scope, expected_scope)?;
        require_exact_path(&self.path, expected_path)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundtruthRevokeAck {
    pub operation: String,
    pub revoked: i64,
    pub path: String,
}

impl GroundtruthRevokeAck {
    pub fn verify(&self, expected_id: &str, expected_path: &Path) -> Result<(), String> {
        require_action(&self.operation, "groundtruth.revoke")?;
        require_task_id(self.revoked, expected_id)?;
        require_exact_path(&self.path, expected_path)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaSetCapAck {
    pub operation: String,
    pub provider: String,
    pub estimated_daily_cap: u32,
    pub path: String,
}

impl QuotaSetCapAck {
    pub fn verify(
        &self,
        expected_provider: &str,
        expected_cap: &str,
        expected_path: &Path,
    ) -> Result<(), String> {
        require_action(&self.operation, "quota.set-cap")?;
        require_id(&self.provider, expected_provider)?;
        let cap = expected_cap.parse::<u32>().map_err(|_| {
            format!("expected quota cap `{expected_cap}` is not an unsigned integer")
        })?;
        if self.estimated_daily_cap != cap {
            return Err(format!(
                "acknowledged quota cap `{}`, expected `{cap}`",
                self.estimated_daily_cap
            ));
        }
        require_exact_path(&self.path, expected_path)
    }
}

/// Exact `neoth backup --output json` acknowledgement.
///
/// The receipt is self-identifying (`operation`) and the GUI reads the named
/// archive back off disk before reporting success, so a success-looking exit
/// with no real tarball cannot be mistaken for a completed backup.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupAck {
    pub operation: String,
    pub wrote: String,
    pub entries: u64,
    pub include_wal: bool,
    pub includes_plaintext_credentials: bool,
}

impl BackupAck {
    /// Verify the typed receipt, then confirm the acknowledged archive is a
    /// non-empty file on disk. Returns the confirmed archive path on success.
    pub fn verify_and_read_back(&self) -> Result<&str, String> {
        require_action(&self.operation, "backup.create")?;
        let path = self.wrote.trim();
        if path.is_empty() {
            return Err("backup acknowledgement is missing its archive path".to_string());
        }
        if self.entries == 0 {
            return Err("backup acknowledgement reports zero archived entries".to_string());
        }
        // The GUI "Backup now" action never passes `--include-credentials`, so a
        // receipt claiming the tarball bundled plaintext secrets is a contract
        // violation (wrong binary, tampered CLI, arg injection) — refuse it
        // rather than silently produce an unencrypted credential archive.
        if self.includes_plaintext_credentials {
            return Err(
                "backup acknowledgement reports bundled plaintext credentials, which the GUI \
                 backup never requests"
                    .to_string(),
            );
        }
        let metadata = std::fs::metadata(Path::new(path)).map_err(|error| {
            format!("backup acknowledged `{path}` but it is not on disk: {error}")
        })?;
        if !metadata.is_file() {
            return Err(format!(
                "backup acknowledged `{path}`, but it is not a file"
            ));
        }
        if metadata.len() == 0 {
            return Err(format!(
                "backup acknowledged `{path}`, but the archive is empty"
            ));
        }
        Ok(path)
    }
}

/// Exact `neoth hemispheres set --output json` acknowledgement — only the
/// fields the GUI verifies. `prior_provider`/`mode` are intentionally ignored
/// (no invariant), so this deliberately omits `deny_unknown_fields`. A shape
/// test pins the full CLI receipt; renaming a required consumed field
/// (`role`/`new_provider`/`audit_segment`) fails decode outright, while the
/// optional `model` is cross-checked at rebind time whenever the GUI requested
/// a specific model.
#[derive(Debug, Deserialize)]
pub struct HemisphereSetAck {
    pub role: String,
    pub new_provider: String,
    pub model: Option<String>,
    pub audit_segment: String,
}

impl HemisphereSetAck {
    /// Confirm the acknowledged role/provider (and model, when a specific one
    /// was requested) match the rebind, then read the WAL `0x1F
    /// HEMISPHERE_REBOUND` audit segment back off disk. A success-looking exit
    /// that never durably rebound is refused.
    pub fn verify_and_read_back(
        &self,
        expected_role: &str,
        expected_provider: &str,
        expected_model: Option<&str>,
    ) -> Result<(), String> {
        if self.role != expected_role {
            return Err(format!(
                "hemisphere rebind acknowledged role `{}`, expected `{expected_role}`",
                self.role
            ));
        }
        if self.new_provider != expected_provider {
            return Err(format!(
                "hemisphere rebind acknowledged provider `{}`, expected `{expected_provider}`",
                self.new_provider
            ));
        }
        if let Some(model) = expected_model {
            match self.model.as_deref() {
                Some(actual) if actual == model => {}
                other => {
                    return Err(format!(
                        "hemisphere rebind acknowledged model `{}`, expected `{model}`",
                        other.unwrap_or("(default)")
                    ));
                }
            }
        }
        let segment = self.audit_segment.trim();
        if segment.is_empty() {
            return Err(
                "hemisphere rebind acknowledgement is missing its audit segment".to_string(),
            );
        }
        let metadata = std::fs::metadata(Path::new(segment)).map_err(|error| {
            format!(
                "hemisphere rebind acknowledged audit segment `{segment}` but it is not on disk: {error}"
            )
        })?;
        if !metadata.is_file() {
            return Err(format!(
                "hemisphere rebind acknowledged audit segment `{segment}`, but it is not a file"
            ));
        }
        Ok(())
    }
}

/// Exact `neoth skills --enable|--disable <id> --output json` acknowledgement.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillToggleAck {
    pub id: String,
    pub state: String,
}

impl SkillToggleAck {
    /// Confirm the daemon acknowledged the exact skill and target state the GUI
    /// requested. The CLI lowercases the id, so the id match is case-insensitive.
    pub fn verify(&self, expected_id: &str, expected_state: &str) -> Result<(), String> {
        if !self.id.eq_ignore_ascii_case(expected_id) {
            return Err(format!(
                "skill toggle acknowledged id `{}`, expected `{expected_id}`",
                self.id
            ));
        }
        if self.state != expected_state {
            return Err(format!(
                "skill toggle acknowledged state `{}`, expected `{expected_state}`",
                self.state
            ));
        }
        Ok(())
    }
}

/// Exact `neoth plugin enable|disable <id> --output json` acknowledgement —
/// the fields the GUI verifies. The changed path also emits optional
/// `granted_capability`/`manifest_sha256`/`wasm_sha256`, which carry no GUI
/// invariant, so this omits `deny_unknown_fields`; a shape test pins the receipt.
#[derive(Debug, Deserialize)]
pub struct PluginToggleAck {
    pub id: String,
    pub new: String,
    pub changed: bool,
}

impl PluginToggleAck {
    /// Confirm the acknowledged plugin id and resulting activation state match
    /// the request. `enable`/`disable` are idempotent, so `changed: false`
    /// (already in the target state) is a benign success. Returns whether the
    /// activation actually changed.
    pub fn verify(&self, expected_id: &str, expected_state: &str) -> Result<bool, String> {
        if self.id != expected_id {
            return Err(format!(
                "plugin toggle acknowledged id `{}`, expected `{expected_id}`",
                self.id
            ));
        }
        if self.new != expected_state {
            return Err(format!(
                "plugin toggle acknowledged state `{}`, expected `{expected_state}`",
                self.new
            ));
        }
        Ok(self.changed)
    }
}

/// Exact `neoth skills --uninstall <id> --output json` acknowledgement.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillUninstallAck {
    pub id: String,
    pub removed: bool,
}

impl SkillUninstallAck {
    /// Confirm the acknowledged id matches; return whether a skill was actually
    /// removed. `neoth skills --uninstall` is idempotent, so `removed: false`
    /// (already absent) is a benign success — the desired end state holds — not
    /// a failure. Only an id mismatch (wrong skill acknowledged) is an error.
    pub fn verify(&self, expected_id: &str) -> Result<bool, String> {
        if !self.id.eq_ignore_ascii_case(expected_id) {
            return Err(format!(
                "skill uninstall acknowledged id `{}`, expected `{expected_id}`",
                self.id
            ));
        }
        Ok(self.removed)
    }
}

/// Exact `neoth omi resume --output json` acknowledgement.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmiResumeAck {
    pub operation: String,
    pub resumed: bool,
    pub review_evidence_retained: bool,
}

impl OmiResumeAck {
    pub fn verify(&self) -> Result<(), String> {
        require_action(&self.operation, "resume")?;
        if self.resumed != self.review_evidence_retained {
            return Err(
                "OMI resume acknowledgement has inconsistent review-evidence state".to_string(),
            );
        }
        Ok(())
    }
}

/// Shared exact wire shape for `omi purge` and `omi enforce-retention`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmiDeletionAck {
    pub operation: String,
    pub conversation_id: Option<String>,
    pub conversations: usize,
    pub segments: usize,
    pub media: usize,
    pub actions: usize,
    pub tasks: usize,
    pub groundtruth: usize,
}

impl OmiDeletionAck {
    pub fn verify(
        &self,
        expected_operation: &str,
        expected_conversation_id: Option<&str>,
    ) -> Result<(), String> {
        require_action(&self.operation, expected_operation)?;
        match (self.conversation_id.as_deref(), expected_conversation_id) {
            (Some(actual), Some(expected)) => require_id(actual, expected),
            (None, None) => Ok(()),
            (Some(actual), None) => Err(format!(
                "OMI {expected_operation} unexpectedly acknowledged conversation `{actual}`"
            )),
            (None, Some(expected)) => Err(format!(
                "OMI {expected_operation} acknowledgement is missing conversation `{expected}`"
            )),
        }
    }

    pub fn total_removed(&self) -> usize {
        [
            self.conversations,
            self.segments,
            self.media,
            self.actions,
            self.tasks,
            self.groundtruth,
        ]
        .into_iter()
        .fold(0, usize::saturating_add)
    }
}

/// Exact `neoth omi allow-reimport --output json` acknowledgement.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmiAllowReimportAck {
    pub operation: String,
    pub conversation_id: String,
    pub tombstone_cleared: bool,
    pub stale_native_receipt_removed: bool,
    pub reconciliation_state_cleared: bool,
}

impl OmiAllowReimportAck {
    pub fn verify(&self, expected_conversation_id: &str) -> Result<(), String> {
        require_action(&self.operation, "allow_reimport")?;
        require_id(&self.conversation_id, expected_conversation_id)?;
        if !self.reconciliation_state_cleared {
            return Err(
                "OMI allow-reimport did not confirm cleared reconciliation state".to_string(),
            );
        }
        Ok(())
    }
}

/// Exact readback contract for `neoth omi status --output json`.
///
/// Fields not rendered by the current panel are intentionally retained: the
/// GUI must reject a changed CLI wire contract instead of silently accepting a
/// partial status object and publishing defaults as live state.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct OmiStatusAck {
    pub enabled: bool,
    pub mode: String,
    pub configuration_valid: bool,
    pub configuration_error: Option<String>,
    pub developer_api_credential_present: bool,
    pub native_ingest_credential_present: bool,
    pub endpoint: String,
    pub listen_addr: String,
    pub retention_days: u64,
    pub poll_interval_secs: u64,
    pub retain_transcripts: bool,
    pub audio_enabled: bool,
    pub visual_enabled: bool,
    pub video_enabled: bool,
    pub allow_cloud_api: bool,
    pub allow_cloud_summary: bool,
    pub create_actions: bool,
    pub seed_groundtruth: bool,
    pub summary_enabled: bool,
    pub ledger_initialized: bool,
    pub conversations: u64,
    pub segments: u64,
    pub media: u64,
    pub actions: u64,
    pub tombstones: u64,
    pub pending_audits: u64,
    pub runtime_state: String,
    pub runtime_persisted_state: Option<String>,
    pub runtime_detail: Option<String>,
    pub runtime_pid: Option<u32>,
    pub runtime_updated_ns: Option<i64>,
    pub daemon_pid: Option<u32>,
    pub sanitizer_halted: bool,
    pub last_success_ns: Option<i64>,
    pub last_error: Option<String>,
    pub last_retention_purge_ns: Option<i64>,
    pub last_retention_error: Option<String>,
}

impl OmiStatusAck {
    pub fn verify(&self) -> Result<(), String> {
        if !matches!(
            self.mode.as_str(),
            "developer_api" | "native_ingest" | "both" | "legacy_memories"
        ) {
            return Err(format!(
                "OMI status acknowledged unsupported mode `{}`",
                self.mode
            ));
        }
        if self.endpoint.trim().is_empty() || self.listen_addr.trim().is_empty() {
            return Err("OMI status is missing its configured endpoint or listener".to_string());
        }
        if self.retention_days == 0 || self.poll_interval_secs == 0 {
            return Err(
                "OMI status acknowledged an invalid zero retention/poll window".to_string(),
            );
        }
        if !matches!(
            self.runtime_state.as_str(),
            "starting"
                | "healthy"
                | "disabled"
                | "degraded"
                | "failed"
                | "stopped"
                | "inactive"
                | "unknown"
        ) {
            return Err(format!(
                "OMI status acknowledged unsupported runtime state `{}`",
                self.runtime_state
            ));
        }
        if let Some(state) = self.runtime_persisted_state.as_deref()
            && !matches!(
                state,
                "starting" | "healthy" | "disabled" | "degraded" | "failed" | "stopped"
            )
        {
            return Err(format!(
                "OMI status acknowledged unsupported persisted runtime state `{state}`"
            ));
        }
        if self.runtime_pid == Some(0) || self.daemon_pid == Some(0) {
            return Err("OMI status acknowledged an invalid zero process id".to_string());
        }

        // Core never publishes the persisted worker state directly unless the
        // live daemon PID owns that exact status generation. Stale health must
        // remain visibly inactive/unknown instead of becoming a false-green GUI.
        let expected_runtime_state = if !self.enabled {
            "disabled"
        } else if self.daemon_pid.is_none() {
            "inactive"
        } else if self.runtime_pid != self.daemon_pid {
            "unknown"
        } else {
            self.runtime_persisted_state.as_deref().unwrap_or("unknown")
        };
        if self.runtime_state != expected_runtime_state {
            return Err(format!(
                "OMI status runtime state `{}` contradicts the effective Core state `{expected_runtime_state}`",
                self.runtime_state
            ));
        }
        if self.enabled
            && self.configuration_valid
            && matches!(self.mode.as_str(), "developer_api" | "both")
            && !self.developer_api_credential_present
        {
            return Err(
                "OMI status claims a valid enabled Developer API mode without its credential"
                    .to_string(),
            );
        }
        if self.enabled
            && self.configuration_valid
            && matches!(self.mode.as_str(), "native_ingest" | "both")
            && !self.native_ingest_credential_present
        {
            return Err(
                "OMI status claims a valid enabled native-ingest mode without its token"
                    .to_string(),
            );
        }
        match (
            self.configuration_valid,
            self.configuration_error.as_deref().map(str::trim),
        ) {
            (true, Some(error)) if !error.is_empty() => {
                Err("OMI status claims valid configuration while reporting an error".to_string())
            }
            (false, None | Some("")) => {
                Err("OMI invalid configuration is missing its diagnostic".to_string())
            }
            _ => Ok(()),
        }
    }
}

/// Exact `neoth omi probe --output json` acknowledgement. This keeps the last
/// remaining OMI helper off human-stdout inference as well.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmiProbeAck {
    pub mode: String,
    pub local_endpoint: Option<String>,
    pub native_listener: Option<String>,
    pub public_api: Option<String>,
}

impl OmiProbeAck {
    pub fn verify(&self) -> Result<(), String> {
        if !matches!(
            self.mode.as_str(),
            "developer_api" | "native_ingest" | "both" | "legacy_memories"
        ) {
            return Err(format!(
                "OMI probe acknowledged unsupported mode `{}`",
                self.mode
            ));
        }
        if let Some(outcome) = self.local_endpoint.as_deref()
            && !matches!(
                outcome,
                "reachable" | "port_closed" | "timeout" | "forbidden"
            )
        {
            return Err(format!(
                "OMI probe acknowledged unsupported local-endpoint outcome `{outcome}`"
            ));
        }
        if let Some(outcome) = self.native_listener.as_deref()
            && !matches!(outcome, "reachable" | "port_closed" | "timeout")
        {
            return Err(format!(
                "OMI probe acknowledged unsupported native-listener outcome `{outcome}`"
            ));
        }
        if let Some(outcome) = self.public_api.as_deref()
            && outcome != "not_probed_auth_required"
        {
            return Err(format!(
                "OMI probe acknowledged unsupported public-API outcome `{outcome}`"
            ));
        }

        let local = self.local_endpoint.is_some();
        let native = self.native_listener.is_some();
        let public = self.public_api.is_some();
        let polling = local ^ public;
        let valid_shape = match self.mode.as_str() {
            "developer_api" => polling && !native,
            "native_ingest" => !local && native && !public,
            "both" => polling && native,
            "legacy_memories" => local && !native && !public,
            _ => unreachable!("unsupported OMI mode returned above"),
        };
        if !valid_shape {
            return Err(format!(
                "OMI probe outcome fields contradict `{}` mode",
                self.mode
            ));
        }
        Ok(())
    }

    pub fn summary(&self) -> String {
        let checks = [
            self.local_endpoint
                .as_deref()
                .map(|value| format!("endpoint {value}")),
            self.native_listener
                .as_deref()
                .map(|value| format!("listener {value}")),
            self.public_api
                .as_deref()
                .map(|value| format!("public API {value}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        if checks.is_empty() {
            format!(
                "OMI probe ({}) completed; no endpoint check required.",
                self.mode
            )
        } else {
            format!("OMI probe ({}): {}.", self.mode, checks.join(", "))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OmiConfigureSettingsAck {
    pub enabled: bool,
    pub mode: String,
    pub endpoint: String,
    pub listen_addr: String,
    pub retention_days: u64,
    pub retain_transcripts: bool,
    pub audio_enabled: bool,
    pub visual_enabled: bool,
    pub video_enabled: bool,
    pub allow_cloud_api: bool,
    pub allow_cloud_summary: bool,
    pub create_actions: bool,
    pub seed_groundtruth: bool,
    pub summary_enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryForgetAck {
    pub operation: String,
    pub confirmed: bool,
    pub topic: String,
    pub episode_rows: i64,
    pub consolidated_rows: i64,
    pub longterm_rows: i64,
    pub raw_turn_rows: i64,
    pub groundtruth_revoked: i64,
    pub embedding_rows: i64,
    pub profile_rows: i64,
    pub profile_pending_rows: i64,
    pub profile_outbox_rows: i64,
    pub entity_rows: i64,
    pub relation_rows: i64,
    pub link_rows: i64,
    pub contradiction_rows: i64,
    pub foreign_event_rows: i64,
    pub people_rows: i64,
    pub commit: MemoryForgetCommitAck,
    pub anti_resurrection_sentinel: MemoryForgetSentinelAck,
    pub audit: MemoryForgetAuditAck,
    pub communication_profile: MemoryForgetCommunicationProfileAck,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryForgetCommitAck {
    pub database_path: String,
    pub sqlite_cascade_committed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryForgetSentinelAck {
    pub field: String,
    pub active: bool,
    pub never_recreate: bool,
    pub asserted_by: String,
    pub asserted_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryForgetAuditAck {
    pub event_type: String,
    pub segment_path: String,
    pub segment_sha256: String,
    pub persisted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryForgetCommunicationProfileAck {
    pub subjects_deleted: usize,
    pub topic_addressable: bool,
    pub reason: String,
    pub erase_with: String,
}

impl MemoryForgetAck {
    pub fn deleted_total(&self) -> Result<i64, String> {
        self.counts().into_iter().try_fold(0_i64, |total, count| {
            if count < 0 {
                return Err(
                    "memory forget acknowledgement contains a negative mutation count".into(),
                );
            }
            total.checked_add(count).ok_or_else(|| {
                "memory forget acknowledgement mutation count overflowed".to_string()
            })
        })
    }

    fn counts(&self) -> [i64; 15] {
        [
            self.episode_rows,
            self.consolidated_rows,
            self.longterm_rows,
            self.raw_turn_rows,
            self.groundtruth_revoked,
            self.embedding_rows,
            self.profile_rows,
            self.profile_pending_rows,
            self.profile_outbox_rows,
            self.entity_rows,
            self.relation_rows,
            self.link_rows,
            self.contradiction_rows,
            self.foreign_event_rows,
            self.people_rows,
        ]
    }

    pub fn verify(
        &self,
        expected_topic: &str,
        expected_database: &Path,
        expected_wal_dir: &Path,
    ) -> Result<(), String> {
        require_action(&self.operation, "memory.forget")?;
        require_id(&self.topic, expected_topic)?;
        if !self.confirmed || !self.commit.sqlite_cascade_committed {
            return Err("memory forget did not acknowledge a committed confirmed mutation".into());
        }
        require_exact_path(&self.commit.database_path, expected_database)?;
        self.deleted_total()?;
        let expected_sentinel = format!("_tombstone.{}", expected_topic.trim().to_lowercase());
        if self.anti_resurrection_sentinel.field != expected_sentinel
            || !self.anti_resurrection_sentinel.active
            || !self.anti_resurrection_sentinel.never_recreate
            || self
                .anti_resurrection_sentinel
                .asserted_by
                .trim()
                .is_empty()
            || self.anti_resurrection_sentinel.asserted_at <= 0
        {
            return Err(
                "memory forget acknowledgement has invalid anti-resurrection evidence".into(),
            );
        }
        require_action(&self.audit.event_type, "TOMBSTONE_REQUESTED")?;
        if !self.audit.persisted || !is_sha256(&self.audit.segment_sha256) {
            return Err("memory forget acknowledgement has invalid durable audit evidence".into());
        }
        let audit_path = Path::new(&self.audit.segment_path);
        let expected_parent = std::path::absolute(expected_wal_dir)
            .map_err(|error| format!("could not normalize expected WAL directory: {error}"))?;
        let actual_parent = audit_path
            .parent()
            .ok_or_else(|| "memory forget audit receipt has no parent directory".to_string())?;
        require_exact_path(actual_parent.to_string_lossy().as_ref(), &expected_parent)?;
        if !audit_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(valid_memory_forget_segment_name)
        {
            return Err("memory forget audit receipt has an unexpected segment name".into());
        }
        require_regular_file_sha256(
            audit_path,
            &self.audit.segment_sha256,
            "memory forget audit segment",
        )?;
        if self.communication_profile.subjects_deleted != 0
            || self.communication_profile.topic_addressable
            || self.communication_profile.reason
                != "typed_communication_evidence_is_not_topic_addressable"
            || self.communication_profile.erase_with
                != "neoth memory erase-communication-profile --confirm"
        {
            return Err("memory forget communication-profile boundary is inconsistent".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmiConfigureCredentialAck {
    pub backend: String,
    pub updated_fields: Vec<String>,
    pub developer_api_key_present: bool,
    pub native_ingest_token_present: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmiConfigureAck {
    pub operation: String,
    pub operation_id: String,
    pub path: String,
    pub settings_sha256: String,
    pub config_sha256: String,
    pub reload_requested: bool,
    pub reload_ts_unix: u64,
    pub settings: OmiConfigureSettingsAck,
    pub credentials: OmiConfigureCredentialAck,
}

impl OmiConfigureAck {
    pub fn verify(
        &self,
        expected: &OmiConfigureSettingsAck,
        expected_path: &Path,
        developer_key_submitted: bool,
        native_token_submitted: bool,
    ) -> Result<(), String> {
        require_action(&self.operation, "omi.configure")?;
        require_exact_path(&self.path, expected_path)?;
        require_lower_hex(&self.operation_id, 32, "OMI operation id")?;
        require_lower_hex(&self.settings_sha256, 64, "OMI settings SHA-256")?;
        require_lower_hex(&self.config_sha256, 64, "OMI config SHA-256")?;
        let expected_settings = serde_json::to_vec(expected)
            .map_err(|error| format!("could not encode expected OMI settings: {error}"))?;
        if self.settings_sha256 != sha256_hex(&expected_settings) {
            return Err("OMI acknowledgement settings digest does not match the submission".into());
        }
        require_regular_file_sha256(
            expected_path,
            &self.config_sha256,
            "OMI configuration generation",
        )?;
        if !self.reload_requested || self.reload_ts_unix == 0 {
            return Err("OMI acknowledgement does not bind a reload request".to_string());
        }
        if self.settings != *expected {
            return Err(
                "OMI acknowledgement settings do not match the submitted snapshot".to_string(),
            );
        }
        if !matches!(self.credentials.backend.as_str(), "file" | "keychain") {
            return Err(format!(
                "OMI acknowledgement returned unknown credential backend `{}`",
                self.credentials.backend
            ));
        }
        let mut expected_fields = Vec::with_capacity(2);
        if developer_key_submitted {
            expected_fields.push("omi_developer_api_key".to_string());
        }
        if native_token_submitted {
            expected_fields.push("omi_ingest_token".to_string());
        }
        if self.credentials.updated_fields != expected_fields {
            return Err(
                "OMI acknowledgement credential fields do not match the private submission"
                    .to_string(),
            );
        }
        if developer_key_submitted && !self.credentials.developer_api_key_present {
            return Err("OMI acknowledgement did not verify the submitted Developer key".into());
        }
        if native_token_submitted && !self.credentials.native_ingest_token_present {
            return Err("OMI acknowledgement did not verify the submitted native token".into());
        }
        if expected.enabled
            && matches!(expected.mode.as_str(), "developer_api" | "both")
            && !self.credentials.developer_api_key_present
        {
            return Err("enabled OMI Developer API mode has no verified credential".into());
        }
        if expected.enabled
            && matches!(expected.mode.as_str(), "native_ingest" | "both")
            && !self.credentials.native_ingest_token_present
        {
            return Err("enabled native OMI mode has no verified credential".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Keep the complete status wire shape fail-closed as it evolves.
pub struct ClusterStatusAck {
    pub mode: String,
    pub policy: String,
    pub peer_count: usize,
    pub conflict_count: usize,
    pub operator_id: String,
    pub node_id: String,
    pub cluster_name: Option<String>,
    pub cluster_passphrase_set: bool,
    pub cluster_identity_configured: bool,
    pub cluster_enabled: bool,
    pub restart_required: bool,
    pub transport_active: bool,
    pub transport: String,
    pub listen_port: u16,
    pub mdns_enabled: bool,
    pub trusted_ssids: Vec<String>,
    pub peers: Vec<ClusterPeerAck>,
    pub gossip: ClusterGossipAck,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterPeerAck {
    pub id: String,
    pub label: String,
    pub last_seen: String,
    pub last_seen_unix: i64,
    pub reachable: bool,
}

impl ClusterStatusAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.peer_count != self.peers.len() {
            return Err(format!(
                "cluster status reports {} peers but returned {} peer rows",
                self.peer_count,
                self.peers.len()
            ));
        }
        let mut peer_ids = std::collections::HashSet::with_capacity(self.peers.len());
        for peer in &self.peers {
            if peer.id.trim().is_empty()
                || peer.label.trim().is_empty()
                || peer.last_seen.trim().is_empty()
            {
                return Err("cluster status returned an incomplete peer identity".into());
            }
            if !peer_ids.insert(peer.id.as_str()) {
                return Err(format!(
                    "cluster status returned duplicate peer `{}`",
                    peer.id
                ));
            }
            if peer.reachable && peer.last_seen_unix <= 0 {
                return Err(format!(
                    "cluster status marked peer `{}` reachable without a durable last-seen time",
                    peer.id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterPeerRevokeAck {
    pub operation: String,
    pub requested_peer: String,
    pub canonical_peer: Option<String>,
    pub removed: bool,
    pub noop: bool,
    pub post_state: ClusterPeerRevokePostStateAck,
    pub audit: ClusterPeerRevokeAuditAck,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterPeerRevokePostStateAck {
    pub registry_path: String,
    pub registry_file_present: bool,
    pub registry_sha256: Option<String>,
    pub peer_count: usize,
    pub canonical_peer_absent: bool,
    pub verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterPeerRevokeAuditAck {
    pub required: bool,
    pub state: String,
    pub event_type: Option<String>,
    pub sidecar_path: Option<String>,
    pub durable_handoff_persisted: bool,
}

impl ClusterPeerRevokeAck {
    pub fn verify(&self, expected_peer: &str, expected_home: &Path) -> Result<(), String> {
        require_action(&self.operation, "cluster.peer.revoke")?;
        require_id(&self.requested_peer, expected_peer)?;
        if self.removed == self.noop
            || !self.post_state.verified
            || !self.post_state.canonical_peer_absent
        {
            return Err("cluster revoke acknowledgement has inconsistent mutation state".into());
        }
        let registry_path = expected_home.join("cluster.yaml");
        require_exact_path(&self.post_state.registry_path, &registry_path)?;
        match (
            self.post_state.registry_file_present,
            self.post_state.registry_sha256.as_deref(),
        ) {
            (true, Some(hash)) if is_sha256(hash) => {
                require_regular_file_sha256(&registry_path, hash, "cluster registry")?;
            }
            (false, None) if self.noop => match std::fs::symlink_metadata(&registry_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(
                        "cluster revoke receipt claims the registry is absent, but it exists"
                            .into(),
                    );
                }
                Err(error) => {
                    return Err(format!(
                        "could not verify absent cluster registry `{}`: {error}",
                        registry_path.display()
                    ));
                }
            },
            _ => return Err("cluster revoke acknowledgement has invalid registry evidence".into()),
        }
        if self.removed {
            let canonical = self
                .canonical_peer
                .as_deref()
                .ok_or_else(|| "cluster revoke omitted the canonical peer".to_string())?;
            if canonical.len() != 64
                || !canonical
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("cluster revoke returned an invalid canonical peer key".into());
            }
            let requested_key = expected_peer.trim().to_ascii_lowercase();
            if !requested_key.is_empty()
                && requested_key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && !canonical.starts_with(&requested_key)
            {
                return Err(
                    "cluster revoke canonical peer does not match the requested key prefix".into(),
                );
            }
            if !self.audit.required
                || self.audit.state != "sidecar_committed_for_wal_ingest"
                || self.audit.event_type.as_deref() != Some("CLUSTER_PEER_REVOKED")
                || !self.audit.durable_handoff_persisted
            {
                return Err(
                    "cluster revoke acknowledgement has invalid audit handoff evidence".into(),
                );
            }
            let sidecar = self
                .audit
                .sidecar_path
                .as_deref()
                .ok_or_else(|| "cluster revoke omitted its audit sidecar path".to_string())?;
            let sidecar = Path::new(sidecar);
            let parent = sidecar
                .parent()
                .ok_or_else(|| "cluster revoke audit sidecar has no parent".to_string())?;
            require_exact_path(
                parent.to_string_lossy().as_ref(),
                &expected_home.join("pending_audit"),
            )?;
            if !sidecar
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(valid_cluster_revoke_sidecar_name)
            {
                return Err("cluster revoke audit sidecar name is invalid".into());
            }
        } else if self.canonical_peer.is_some()
            || self.audit.required
            || self.audit.state != "not_required_noop"
            || self.audit.event_type.is_some()
            || self.audit.sidecar_path.is_some()
            || self.audit.durable_handoff_persisted
        {
            return Err("cluster revoke no-op acknowledgement claims mutation evidence".into());
        }
        Ok(())
    }

    pub fn verify_readback(&self, status: &ClusterStatusAck) -> Result<(), String> {
        status.verify()?;
        if status.peer_count != self.post_state.peer_count {
            return Err(format!(
                "cluster revoke readback returned {} peers, receipt committed {}",
                status.peer_count, self.post_state.peer_count
            ));
        }
        if let Some(canonical) = self.canonical_peer.as_deref()
            && status.peers.iter().any(|peer| peer.id == canonical)
        {
            return Err(format!(
                "cluster revoke readback still contains peer `{canonical}`"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConflictListAck {
    pub unresolved_count: usize,
    pub include_resolved: bool,
    pub conflicts: Vec<ClusterConflictAck>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConflictAck {
    pub id: i64,
    pub content_id: String,
    pub incumbent_origin: String,
    pub incoming_origin: String,
    pub incumbent_sha256: String,
    pub incoming_sha256: String,
    pub policy: String,
    pub observed_at: i64,
    pub resolved_at: Option<i64>,
    pub preferred_origin: Option<String>,
}

impl ClusterConflictListAck {
    pub fn verify_unresolved(&self) -> Result<(), String> {
        if self.include_resolved {
            return Err("cluster returned forensic history instead of unresolved conflicts".into());
        }
        if self.unresolved_count < self.conflicts.len() {
            return Err("cluster unresolved count is smaller than its returned rows".into());
        }
        let mut row_ids = std::collections::HashSet::with_capacity(self.conflicts.len());
        for conflict in &self.conflicts {
            if conflict.id <= 0 || !row_ids.insert(conflict.id) {
                return Err("cluster returned a missing or duplicate conflict row id".into());
            }
            if conflict.resolved_at.is_some() || conflict.preferred_origin.is_some() {
                return Err(format!(
                    "cluster returned resolved state for unresolved conflict `{}`",
                    conflict.content_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConflictResolveAck {
    pub operation: String,
    pub content_id: String,
    pub preferred_origin: String,
    pub resolved_count: usize,
    pub unresolved_remaining: usize,
}

impl ClusterConflictResolveAck {
    pub fn verify(&self, content_id: &str, preferred_origin: &str) -> Result<(), String> {
        if self.operation != "cluster.conflicts.resolve"
            || self.content_id != content_id
            || self.preferred_origin != preferred_origin
            || self.resolved_count == 0
        {
            return Err("cluster conflict receipt does not match the requested decision".into());
        }
        Ok(())
    }
}

/// Exact `neoth cluster request-sync --peer <peer> --output json` receipt.
/// The GUI may refresh mesh state only after this receipt is bound to the
/// requested peer and the durable queue's initial state.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterRequestSyncAck {
    pub operation: String,
    pub peer_pk: String,
    pub state: String,
    pub requested_at: i64,
    pub expires_at: i64,
    pub updated_at: i64,
    pub last_attempt_at: Option<i64>,
    pub send_attempts: u64,
    pub last_error: Option<String>,
}

impl ClusterRequestSyncAck {
    pub fn verify(&self, expected_peer: &str) -> Result<(), String> {
        if self.operation != "cluster.request-sync" {
            return Err(format!(
                "mesh sync receipt has unexpected operation `{}`",
                self.operation
            ));
        }
        if self.peer_pk != expected_peer {
            return Err(format!(
                "mesh sync receipt peer `{}` does not match requested peer `{expected_peer}`",
                self.peer_pk
            ));
        }
        if self.state != "queued" {
            return Err(format!(
                "mesh sync receipt has unexpected state `{}`",
                self.state
            ));
        }
        if self.requested_at <= 0
            || self.updated_at != self.requested_at
            || self.expires_at <= self.requested_at
        {
            return Err("mesh sync receipt contains invalid timestamps".to_string());
        }
        if self.last_attempt_at.is_some() || self.send_attempts != 0 || self.last_error.is_some() {
            return Err("mesh sync receipt contains impossible queue progress".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterMdnsAck {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterPolicyAck {
    pub announce_on_untrusted_wifi: bool,
    pub trusted_ssids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterGossipAck {
    pub replicate_raw_ingress: bool,
    pub replay_budget_days: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterSnapshotAck {
    pub name: Option<String>,
    pub enabled: bool,
    pub transport: String,
    pub peers: Vec<String>,
    pub mdns: ClusterMdnsAck,
    pub policy: ClusterPolicyAck,
    pub gossip: ClusterGossipAck,
    pub listen_port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfigureAck {
    pub operation: String,
    pub path: String,
    pub reload_requested: bool,
    pub reload_error: Option<String>,
    pub restart_required: bool,
    pub cluster_passphrase_set: bool,
    pub cluster: ClusterSnapshotAck,
}

pub struct ExpectedClusterConfig<'a> {
    pub name: Option<&'a str>,
    pub enabled: bool,
    pub transport: &'a str,
    pub peers: &'a [String],
    pub mdns_enabled: bool,
    pub announce_on_untrusted_wifi: bool,
    pub trusted_ssids: &'a [String],
    pub replicate_raw_ingress: bool,
    pub replay_budget_days: u32,
    pub listen_port: u16,
    /// `Some(true)` when the submitted operation requires a usable secret;
    /// `None` when the GUI intentionally left the existing store untouched.
    pub cluster_passphrase_set: Option<bool>,
}

impl ClusterConfigureAck {
    pub fn verify(
        &self,
        expected: &ExpectedClusterConfig<'_>,
        expected_path: &Path,
    ) -> Result<(), String> {
        require_action(&self.operation, "cluster.configure")?;
        require_exact_path(&self.path, expected_path)?;
        if self.reload_requested == self.reload_error.is_some() {
            return Err(
                "cluster acknowledgement has inconsistent reload_requested/reload_error fields"
                    .to_string(),
            );
        }
        let checks = [
            (
                self.cluster.name.as_deref() == expected.name,
                "cluster.name",
            ),
            (self.cluster.enabled == expected.enabled, "cluster.enabled"),
            (
                self.cluster.transport == expected.transport,
                "cluster.transport",
            ),
            (
                self.cluster.peers.as_slice() == expected.peers,
                "cluster.peers",
            ),
            (
                self.cluster.mdns.enabled == expected.mdns_enabled,
                "cluster.mdns.enabled",
            ),
            (
                self.cluster.policy.announce_on_untrusted_wifi
                    == expected.announce_on_untrusted_wifi,
                "cluster.policy.announce_on_untrusted_wifi",
            ),
            (
                self.cluster.policy.trusted_ssids.as_slice() == expected.trusted_ssids,
                "cluster.policy.trusted_ssids",
            ),
            (
                self.cluster.gossip.replicate_raw_ingress == expected.replicate_raw_ingress,
                "cluster.gossip.replicate_raw_ingress",
            ),
            (
                self.cluster.gossip.replay_budget_days == expected.replay_budget_days,
                "cluster.gossip.replay_budget_days",
            ),
            (
                self.cluster.listen_port == expected.listen_port,
                "cluster.listen_port",
            ),
        ];
        if let Some((_, field)) = checks.into_iter().find(|(matches, _)| !matches) {
            return Err(format!(
                "cluster acknowledgement does not match submitted `{field}`"
            ));
        }
        if let Some(expected_set) = expected.cluster_passphrase_set
            && self.cluster_passphrase_set != expected_set
        {
            return Err(
                "cluster acknowledgement does not match required `cluster_passphrase_set`"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub fn run_json<T>(command: &mut Command, action: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    run_json_receipt(command, action).map(|receipt| receipt.acknowledgement)
}

/// Catalog refresh deliberately returns a non-zero exit for typed `partial`
/// and `no_sources` outcomes. Decode that one receipt before evaluating the
/// exit status so the GUI can show the exact provider IDs, while still
/// requiring success receipts to exit zero and incomplete receipts to exit
/// non-zero.
pub fn run_catalog_refresh(
    command: &mut Command,
    action: &str,
    expected_path: &Path,
    expected_stale_only: bool,
) -> Result<CatalogRefreshOutcome, String> {
    let output = command
        .output()
        .map_err(|error| format!("could not start {action}: {error}"))?;
    decode_catalog_refresh_output(&output, action, expected_path, expected_stale_only)
}

pub fn run_catalog_list(
    command: &mut Command,
    action: &str,
    expected_path: &Path,
    expected_generation: Option<u64>,
    expected_hash: Option<&str>,
) -> Result<String, String> {
    let acknowledgement: CatalogListAck = run_json(command, action)?;
    acknowledgement.verify(expected_path, expected_generation, expected_hash)?;
    serde_json::to_string(&acknowledgement)
        .map_err(|error| format!("could not render verified {action} response: {error}"))
}

pub fn run_json_receipt<T>(command: &mut Command, action: &str) -> Result<JsonReceipt<T>, String>
where
    T: DeserializeOwned,
{
    let output = command
        .output()
        .map_err(|error| format!("could not start {action}: {error}"))?;
    let acknowledgement = decode_json_output(&output, action)?;
    let stderr = bounded_text(&output.stderr, MAX_DIAGNOSTIC_CHARS * 2);
    Ok(JsonReceipt {
        acknowledgement,
        stderr,
    })
}

/// Execute a typed mutation while sending secret material only over the
/// child's private stdin. The caller-owned buffer is zeroed immediately after
/// the write attempt, before waiting for or decoding the acknowledgement.
pub fn run_json_with_private_stdin<T>(
    command: &mut Command,
    action: &str,
    stdin_body: &mut [u8],
) -> Result<T, String>
where
    T: DeserializeOwned,
{
    use std::io::Write as _;
    use std::process::Stdio;

    let child_result = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child_result {
        Ok(child) => child,
        Err(error) => {
            stdin_body.fill(0);
            return Err(format!("could not start {action}: {error}"));
        }
    };
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| format!("could not open private stdin for {action}"))
        .and_then(|mut stdin| {
            stdin
                .write_all(stdin_body)
                .map_err(|error| format!("could not send private input for {action}: {error}"))
        });
    stdin_body.fill(0);
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("could not wait for {action}: {error}"))?;
    decode_json_output(&output, action)
}

fn decode_json_output<T>(output: &Output, action: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    if !output.status.success() {
        let exit = output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "?".to_string());
        return Err(format!(
            "{action} failed (exit {exit}): {}",
            diagnostic(output)
        ));
    }
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        return Err(format!(
            "{action} returned no acknowledgement; state was not assumed"
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{action} returned an invalid acknowledgement: {error}"))
}

fn decode_catalog_refresh_output(
    output: &Output,
    action: &str,
    expected_path: &Path,
    expected_stale_only: bool,
) -> Result<CatalogRefreshOutcome, String> {
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        return if output.status.success() {
            Err(format!(
                "{action} returned no acknowledgement; state was not assumed"
            ))
        } else {
            let exit = output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "?".to_string());
            Err(format!(
                "{action} failed (exit {exit}) without a typed receipt: {}",
                diagnostic(output)
            ))
        };
    }
    let acknowledgement: CatalogRefreshAck = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{action} returned an invalid acknowledgement: {error}"))?;
    match (
        output.status.success(),
        acknowledgement.classify(expected_path, expected_stale_only)?,
    ) {
        (true, complete @ CatalogRefreshOutcome::Complete { .. }) => Ok(complete),
        (false, incomplete @ CatalogRefreshOutcome::Incomplete { .. }) => Ok(incomplete),
        (false, CatalogRefreshOutcome::Complete { .. }) => Err(format!(
            "{action} returned a success receipt with a non-zero process exit; state was not assumed"
        )),
        (true, CatalogRefreshOutcome::Incomplete { message, .. }) => Err(format!(
            "{message} The command incorrectly returned a successful process exit."
        )),
    }
}

fn diagnostic(output: &Output) -> String {
    // R4-09 error-UX: pick the first line that is meaningful to a NON-technical
    // operator after scrubbing internal noise (panic headers, anyhow chain
    // continuations, absolute file paths, redundant "Error:" prefixes). If
    // nothing survives, point at Doctor instead of dumping a stack trace.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    stderr
        .lines()
        .chain(stdout.lines())
        .filter_map(scrub_diagnostic)
        .next()
        .unwrap_or_else(|| "NEOTH reported an error — run neoth doctor for details.".to_string())
}

/// Turn one raw CLI stderr/stdout line into an operator-safe message, or `None`
/// if the line is pure internal noise (panic header, anyhow "caused by:" chain
/// continuation, or empty after scrubbing).
fn scrub_diagnostic(line: &str) -> Option<String> {
    let mut s = line.trim();
    // The caller's format string already names the action → drop the prefix.
    for p in ["Error: ", "error: ", "ERROR: "] {
        if let Some(rest) = s.strip_prefix(p) {
            s = rest.trim();
        }
    }
    // A Rust panic header / anyhow chain continuation is never user-actionable.
    if (s.starts_with("thread '") && s.contains("panicked"))
        || s.starts_with("caused by:")
        || s.is_empty()
    {
        return None;
    }
    let scrubbed = redact_windows_paths(s);
    let scrubbed = scrubbed.trim();
    if scrubbed.is_empty() {
        None
    } else {
        Some(scrubbed.chars().take(MAX_DIAGNOSTIC_CHARS).collect())
    }
}

/// Replace absolute Windows paths (`X:\…` / `X:/…`) with `<path>` so the GUI
/// never leaks internal file layout into a user-facing toast.
fn redact_windows_paths(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if i + 2 < chars.len()
            && chars[i].is_ascii_alphabetic()
            && chars[i + 1] == ':'
            && (chars[i + 2] == '\\' || chars[i + 2] == '/')
        {
            out.push_str("<path>");
            i += 3;
            while i < chars.len() && !chars[i].is_whitespace() {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn bounded_text(bytes: &[u8], max_chars: usize) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.chars().take(max_chars).collect())
}

fn require_action(actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "acknowledged action `{actual}`, expected `{expected}`"
        ))
    }
}

fn require_lower_hex(value: &str, length: usize, label: &str) -> Result<(), String> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "{label} must contain exactly {length} lowercase hexadecimal characters"
        ))
    }
}

fn require_id(actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("acknowledged id `{actual}`, expected `{expected}`"))
    }
}

fn require_task_id(actual: i64, expected: &str) -> Result<(), String> {
    let expected = expected
        .parse::<i64>()
        .map_err(|_| format!("expected task id `{expected}` is not an integer"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "acknowledged task id `{actual}`, expected `{expected}`"
        ))
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn valid_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[14] == b'7'
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        })
}

fn valid_memory_forget_segment_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".wal") else {
        return false;
    };
    let Some((writer_id, sequence)) = stem.split_once("-memory-forget-") else {
        return false;
    };
    valid_uuid_v7(writer_id) && sequence == "000001"
}

fn valid_cluster_revoke_sidecar_name(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix("cluster_peer_revoked_")
        .and_then(|value| value.strip_suffix(".json"))
    else {
        return false;
    };
    let mut parts = stem.split('_');
    let (Some(seconds), Some(nanos), Some(writer_id), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !seconds.is_empty()
        && seconds.bytes().all(|byte| byte.is_ascii_digit())
        && nanos.len() == 38
        && nanos.bytes().all(|byte| byte.is_ascii_digit())
        && writer_id.len() == 32
        && writer_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_regular_file_sha256(path: &Path, expected: &str, label: &str) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {label} `{}`: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} `{}` is not a regular non-symlink file",
            path.display()
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("could not read {label} `{}`: {error}", path.display()))?;
    let actual = sha256_hex(&bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} `{}` no longer matches its acknowledgement digest",
            path.display()
        ))
    }
}

fn require_exact_path(actual: &str, expected_path: &Path) -> Result<(), String> {
    if actual.trim().is_empty() {
        return Err("acknowledgement is missing its target path".to_string());
    }
    let actual = std::path::absolute(actual).map_err(|error| {
        format!("could not normalize acknowledged config path `{actual}`: {error}")
    })?;
    let expected = std::path::absolute(expected_path).map_err(|error| {
        format!(
            "could not normalize expected config path `{}`: {error}",
            expected_path.display()
        )
    })?;
    #[cfg(windows)]
    let matches = actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy());
    #[cfg(not(windows))]
    let matches = actual == expected;
    if matches {
        Ok(())
    } else {
        Err(format!(
            "acknowledged target path `{}`, expected `{}`",
            actual.display(),
            expected.display()
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionMutationAck {
    pub operation: String,
    pub action: String,
    pub decision: Option<String>,
    pub path: String,
}

impl PermissionMutationAck {
    pub fn verify_set(
        &self,
        action: &str,
        decision: &str,
        expected_path: &Path,
    ) -> Result<(), String> {
        require_action(&self.operation, "set")?;
        require_id(&self.action, action)?;
        if self.decision.as_deref() != Some(decision) {
            return Err(format!(
                "acknowledged decision `{:?}`, expected `{decision}`",
                self.decision
            ));
        }
        self.require_path(expected_path)
    }

    pub fn verify_clear(&self, action: &str, expected_path: &Path) -> Result<(), String> {
        require_action(&self.operation, "cleared")?;
        require_id(&self.action, action)?;
        if self.decision.is_some() {
            return Err("clear acknowledgement unexpectedly retained a decision".to_string());
        }
        self.require_path(expected_path)
    }

    fn require_path(&self, expected_path: &Path) -> Result<(), String> {
        require_exact_path(&self.path, expected_path)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanMoveAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub status: String,
}

impl KanbanMoveAck {
    pub fn verify(&self, task_id: &str, status: &str) -> Result<(), String> {
        if !self.ok {
            return Err("Kanban move did not acknowledge success".to_string());
        }
        require_action(&self.action, "move")?;
        require_task_id(self.task_id, task_id)?;
        if self.status == status {
            Ok(())
        } else {
            Err(format!(
                "acknowledged status `{}`, expected `{status}`",
                self.status
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanAssignAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub hemisphere: String,
    pub worker: Option<String>,
}

impl KanbanAssignAck {
    pub fn verify(
        &self,
        task_id: &str,
        hemisphere: &str,
        worker: Option<&str>,
    ) -> Result<(), String> {
        if !self.ok {
            return Err("Kanban assignment did not acknowledge success".to_string());
        }
        require_action(&self.action, "assign")?;
        require_task_id(self.task_id, task_id)?;
        if self.hemisphere != hemisphere {
            return Err(format!(
                "acknowledged hemisphere `{}`, expected `{hemisphere}`",
                self.hemisphere
            ));
        }
        if self.worker.as_deref() != worker {
            return Err(format!(
                "acknowledged worker `{:?}`, expected `{worker:?}`",
                self.worker
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanAddAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub session_id: i64,
    pub status: String,
    pub title: String,
    pub task_type: String,
}

impl KanbanAddAck {
    pub fn verify(&self, title: &str, task_type: &str) -> Result<(), String> {
        if !self.ok {
            return Err("Kanban add did not acknowledge success".to_string());
        }
        require_action(&self.action, "add")?;
        if self.task_id <= 0 || self.session_id <= 0 {
            return Err("Kanban add acknowledgement is missing task/session ids".to_string());
        }
        if self.status != "backlog" {
            return Err(format!(
                "acknowledged status `{}`, expected `backlog`",
                self.status
            ));
        }
        if self.title != title {
            return Err(format!(
                "acknowledged title `{}`, expected `{title}`",
                self.title
            ));
        }
        if self.task_type != task_type {
            return Err(format!(
                "acknowledged task type `{}`, expected `{task_type}`",
                self.task_type
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanCommentAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub comment_id: i64,
    pub author: String,
}

impl KanbanCommentAck {
    pub fn verify(&self, task_id: &str, author: &str) -> Result<(), String> {
        if !self.ok {
            return Err("Kanban comment did not acknowledge success".to_string());
        }
        require_action(&self.action, "comment")?;
        require_task_id(self.task_id, task_id)?;
        if self.comment_id <= 0 {
            return Err("Kanban comment acknowledgement is missing its id".to_string());
        }
        if self.author != author {
            return Err(format!(
                "acknowledged author `{}`, expected `{author}`",
                self.author
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanFinishAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub status: String,
    pub verified_tests: bool,
}

impl KanbanFinishAck {
    pub fn verify(&self, task_id: &str, verified_tests: bool) -> Result<(), String> {
        if !self.ok {
            return Err("Kanban finish did not acknowledge success".to_string());
        }
        require_action(&self.action, "finish")?;
        require_task_id(self.task_id, task_id)?;
        if self.status != "done" {
            return Err(format!(
                "acknowledged status `{}`, expected `done`",
                self.status
            ));
        }
        if self.verified_tests != verified_tests {
            return Err(format!(
                "acknowledged verified-tests `{}`, expected `{verified_tests}`",
                self.verified_tests
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KanbanPromoteAck {
    pub ok: bool,
    pub action: String,
    pub task_id: i64,
    pub from_status: String,
    pub status: String,
    pub promoted: bool,
    pub blocker: Option<String>,
}

impl KanbanPromoteAck {
    pub fn verify(&self, task_id: &str) -> Result<(), String> {
        if !self.ok {
            return Err(self
                .blocker
                .clone()
                .unwrap_or_else(|| "Kanban promote did not acknowledge success".to_string()));
        }
        require_action(&self.action, "promote")?;
        require_task_id(self.task_id, task_id)?;
        if self.from_status != "review" || self.status != "done" || !self.promoted {
            return Err(format!(
                "Kanban promote acknowledged {} -> {} (promoted={})",
                self.from_status, self.status, self.promoted
            ));
        }
        if self.blocker.is_some() {
            return Err("successful Kanban promote unexpectedly included a blocker".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CronMutationAck {
    pub ok: bool,
    pub action: String,
    pub id: String,
}

impl CronMutationAck {
    pub fn verify(&self, action: &str, id: &str) -> Result<(), String> {
        if !self.ok {
            return Err("Cron mutation did not acknowledge success".to_string());
        }
        require_action(&self.action, action)?;
        require_id(&self.id, id)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Retain the complete wire contract even when the current toast uses a subset.
pub struct CronRunAck {
    pub job_id: String,
    pub success: bool,
    pub duration_ms: u64,
    pub output_bytes: u64,
    pub delivery_queued: bool,
    pub delivery_id: Option<String>,
    pub delivery_status: Option<String>,
    pub error: Option<String>,
}

impl CronRunAck {
    pub fn verify(&self, id: &str) -> Result<(), String> {
        require_id(&self.job_id, id)?;
        if self.success {
            Ok(())
        } else {
            Err(self
                .error
                .clone()
                .unwrap_or_else(|| "Cron run acknowledged failure".to_string()))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToggleAck {
    pub ok: bool,
    pub action: String,
    pub enabled: bool,
}

impl ToggleAck {
    pub fn verify(&self, action: &str, enabled: bool) -> Result<(), String> {
        if !self.ok {
            return Err(format!("{action} did not acknowledge success"));
        }
        require_action(&self.action, action)?;
        if self.enabled == enabled {
            Ok(())
        } else {
            Err(format!(
                "acknowledged enabled={}, expected {enabled}",
                self.enabled
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuddySelfActivationAck {
    pub ok: bool,
    pub action: String,
    pub self_activation_enabled: bool,
}

impl BuddySelfActivationAck {
    pub fn verify(&self, enabled: bool) -> Result<(), String> {
        if !self.ok {
            return Err("Buddy self-activation did not acknowledge success".to_string());
        }
        require_action(&self.action, "set_self_activation")?;
        if self.self_activation_enabled == enabled {
            Ok(())
        } else {
            Err(format!(
                "acknowledged self_activation_enabled={}, expected {enabled}",
                self.self_activation_enabled
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuddyProactiveAck {
    pub ok: bool,
    pub action: String,
    pub proactive_enabled: bool,
}

impl BuddyProactiveAck {
    pub fn verify(&self, enabled: bool) -> Result<(), String> {
        if !self.ok {
            return Err("Buddy proactive mode did not acknowledge success".to_string());
        }
        require_action(&self.action, "set_proactive")?;
        if self.proactive_enabled == enabled {
            Ok(())
        } else {
            Err(format!(
                "acknowledged proactive_enabled={}, expected {enabled}",
                self.proactive_enabled
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmartApproveAck {
    pub ok: bool,
    pub action: String,
    pub smart_approve: bool,
    pub changed: bool,
}

impl SmartApproveAck {
    pub fn verify(&self, enabled: bool) -> Result<(), String> {
        if !self.ok {
            return Err("Smart-Approve mutation did not acknowledge success".to_string());
        }
        require_action(&self.action, "set_smart_approve")?;
        if self.smart_approve != enabled {
            return Err(format!(
                "acknowledged smart_approve={}, expected {enabled}",
                self.smart_approve
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SovereignDisableAck {
    pub mode: String,
    pub sovereign_buddy: bool,
    pub previous_autonomy: String,
}

impl SovereignDisableAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.sovereign_buddy {
            return Err("Sovereign disable acknowledgement kept the mode enabled".to_string());
        }
        if self.mode.trim().is_empty() || self.previous_autonomy.trim().is_empty() {
            return Err("Sovereign disable acknowledgement is incomplete".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfImproveToggleAck {
    pub ok: bool,
    pub action: String,
    pub enabled: bool,
    pub auto: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfImproveDryRunAck {
    pub ok: bool,
    pub action: String,
    pub enabled: bool,
    pub staged: bool,
    pub persona: String,
    pub skill_path: Option<String>,
    pub diff: String,
    pub message: String,
}

impl SelfImproveDryRunAck {
    pub fn verify(&self) -> Result<(), String> {
        if !self.ok {
            return Err("Self-Improve dry-run did not acknowledge success".to_string());
        }
        require_action(&self.action, "dry_run")?;
        if self.staged {
            return Err("Self-Improve dry-run unexpectedly staged a proposal".to_string());
        }
        if self.persona.trim().is_empty() || self.message.trim().is_empty() {
            return Err("Self-Improve dry-run acknowledgement is incomplete".to_string());
        }
        if self.enabled && self.skill_path.as_deref().is_none_or(str::is_empty) {
            return Err("enabled Self-Improve dry-run did not bind its skill path".to_string());
        }
        Ok(())
    }
}

impl SelfImproveToggleAck {
    pub fn verify(&self, action: &str, enabled: bool, auto: bool) -> Result<(), String> {
        if !self.ok {
            return Err("Self-Improve toggle did not acknowledge success".to_string());
        }
        require_action(&self.action, action)?;
        if self.enabled != enabled || self.auto != auto {
            return Err(format!(
                "acknowledged enabled={} auto={}, expected enabled={enabled} auto={auto}",
                self.enabled, self.auto
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalMutationAck {
    pub ok: bool,
    pub action: String,
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub upstream_pr_available: Option<bool>,
}

impl ProposalMutationAck {
    pub fn verify(&self, action: &str, id: &str, status: &str) -> Result<(), String> {
        if !self.ok {
            return Err(format!("{action} did not acknowledge success"));
        }
        require_action(&self.action, action)?;
        require_id(&self.id, id)?;
        if self.status == status {
            Ok(())
        } else {
            Err(format!(
                "acknowledged status `{}`, expected `{status}`",
                self.status
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfDevScanAck {
    pub ok: bool,
    pub action: String,
    pub signals: usize,
    pub proposals_staged: usize,
    pub proposals_skipped_deployed: usize,
    pub proposals_skipped_not_auto_safe: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfEditAck {
    pub status: String,
    pub paths: Vec<String>,
    pub diff_hash: String,
    pub dry_run: bool,
}

impl SelfEditAck {
    pub fn verify_applied(&self, expected_hash: &str) -> Result<(), String> {
        if self.status != "applied" || self.dry_run {
            return Err(format!(
                "Self-Edit acknowledged status `{}` with dry_run={}",
                self.status, self.dry_run
            ));
        }
        if self.diff_hash != expected_hash {
            return Err(format!(
                "Self-Edit acknowledged hash `{}`, expected `{expected_hash}`",
                self.diff_hash
            ));
        }
        if self.paths.is_empty() {
            return Err("Self-Edit acknowledgement contains no target paths".to_string());
        }
        Ok(())
    }
}

impl SelfDevScanAck {
    pub fn verify(&self) -> Result<(), String> {
        if !self.ok {
            return Err("Self-Dev scan did not acknowledge success".to_string());
        }
        require_action(&self.action, "scan")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarAddAck {
    pub ok: bool,
    pub action: String,
    pub outcome: String,
    pub uid: String,
}

impl CalendarAddAck {
    pub fn verify(&self) -> Result<(), String> {
        if !self.ok {
            return Err("Calendar add did not acknowledge success".to_string());
        }
        require_action(&self.action, "add")?;
        if !matches!(self.outcome.as_str(), "created" | "already_exists") {
            return Err(format!(
                "Calendar add returned unknown outcome `{}`",
                self.outcome
            ));
        }
        if self.uid.trim().is_empty() {
            return Err("Calendar add acknowledgement is missing `uid`".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // The typed sync receipt intentionally mirrors every CLI field.
pub struct ObsidianSyncAck {
    pub considered: usize,
    pub copied: usize,
    pub skipped_identical: usize,
    pub skipped_dry_run: usize,
    pub blocked_sync_conflict: bool,
    pub conflict_files: usize,
    pub core_sync_enabled: bool,
}

impl ObsidianSyncAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.blocked_sync_conflict {
            Err(format!(
                "Obsidian sync was blocked by {} conflict(s)",
                self.conflict_files
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // The typed wiki receipt intentionally mirrors every CLI field.
pub struct WikiBuildAck {
    pub sources: usize,
    pub pages_planned: usize,
    pub pages_written: usize,
    pub dry_run: bool,
    pub out_dir: String,
    pub pages: Vec<String>,
}

impl WikiBuildAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.dry_run {
            return Err("Obsidian wiki build unexpectedly acknowledged a dry-run".to_string());
        }
        if self.pages_written == self.pages_planned {
            Ok(())
        } else {
            Err(format!(
                "Obsidian wiki wrote {} of {} planned pages",
                self.pages_written, self.pages_planned
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamNowAck {
    pub day: String,
    pub events_considered: usize,
    pub dreams_written: usize,
    pub path: String,
    pub path_taken: String,
}

impl DreamNowAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.day.trim().is_empty()
            || self.path.trim().is_empty()
            || self.path_taken.trim().is_empty()
        {
            Err("Dream acknowledgement is missing required fields".to_string())
        } else {
            Ok(())
        }
    }
}

/// I13 — one row from `neoth jobs --bg --output json`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgJobListRowAck {
    pub id: String,
    pub status: String,
    pub exit_code: Option<i32>,
}

impl BgJobListRowAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("Background-job list contains an empty id".to_string());
        }
        match (self.status.as_str(), self.exit_code) {
            ("running", None) | ("completed", Some(_)) => Ok(()),
            ("running", Some(_)) => {
                Err("A running background job unexpectedly has an exit code".to_string())
            }
            ("completed", None) => Err("A completed background job has no exit code".to_string()),
            (status, _) => Err(format!(
                "Background-job list contains unknown status `{status}`"
            )),
        }
    }
}

pub fn verify_bg_job_list(rows: &[BgJobListRowAck]) -> Result<(), String> {
    let mut ids = std::collections::HashSet::with_capacity(rows.len());
    for row in rows {
        row.verify()?;
        if !ids.insert(row.id.as_str()) {
            return Err(format!(
                "Background-job list contains duplicate id `{}`",
                row.id
            ));
        }
    }
    Ok(())
}

/// I13 — `neoth jobs --run "<command>" --label <l> --output json` ack.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgRunApprovalAck {
    pub action: String,
    pub approved: bool,
    pub request_binding_sha256: String,
    pub token: String,
}

impl BgRunApprovalAck {
    pub fn verify(&self) -> Result<(), String> {
        if self.action != "jobs_approve_run" || !self.approved {
            return Err("Background-run approval was not granted".to_string());
        }
        if !valid_lower_sha256(&self.request_binding_sha256) {
            return Err("Background-run approval has a malformed request binding".to_string());
        }
        // Daemon tokens are exactly 32 random bytes encoded as unpadded
        // base64url (43 ASCII chars). Reject every other wire shape.
        if self.token.len() != 43
            || !self
                .token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("Background-run approval has no valid single-use token".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgRunAck {
    pub action: String,
    pub started: bool,
    pub id: String,
    pub pid: u32,
    pub log_path: String,
    pub request_binding_sha256: String,
}

impl BgRunAck {
    pub fn verify(
        &self,
        expected_request_binding_sha256: &str,
        neoth_home: &Path,
    ) -> Result<(), String> {
        if self.action != "jobs_run" {
            return Err(format!(
                "Background-run acknowledgement has wrong action `{}`",
                self.action
            ));
        }
        if !self.started || self.pid == 0 || !valid_bg_job_id(&self.id) {
            return Err("Background job did not confirm a valid started id".to_string());
        }
        if !valid_lower_sha256(&self.request_binding_sha256)
            || self.request_binding_sha256 != expected_request_binding_sha256
        {
            return Err(
                "Background-run acknowledgement does not match the approved request".to_string(),
            );
        }

        let expected_log = neoth_home.join("bgjobs").join(format!("{}.log", self.id));
        let acknowledged_log = Path::new(&self.log_path);
        let expected_canonical = std::fs::canonicalize(&expected_log).map_err(|error| {
            format!(
                "Background job did not publish its expected log {}: {error}",
                expected_log.display()
            )
        })?;
        let acknowledged_canonical = std::fs::canonicalize(acknowledged_log).map_err(|error| {
            format!(
                "Background-run acknowledgement references an unreadable log {}: {error}",
                acknowledged_log.display()
            )
        })?;
        if expected_canonical != acknowledged_canonical {
            return Err("Background-run acknowledgement references the wrong log path".to_string());
        }
        let metadata = std::fs::metadata(&expected_canonical).map_err(|error| {
            format!(
                "Background job log {} cannot be inspected: {error}",
                expected_canonical.display()
            )
        })?;
        if !metadata.is_file() {
            return Err("Background job log is not a regular file".to_string());
        }
        Ok(())
    }

    pub fn verify_listed(&self, rows: &[BgJobListRowAck]) -> Result<(), String> {
        verify_bg_job_list(rows)?;
        if rows.iter().any(|row| row.id == self.id) {
            Ok(())
        } else {
            Err(format!(
                "Started background job `{}` is absent from verified post-state",
                self.id
            ))
        }
    }
}

fn valid_bg_job_id(value: &str) -> bool {
    let Some((prefix, nonce)) = value.rsplit_once('-') else {
        return false;
    };
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return false;
    }
    let Some((label, timestamp)) = prefix.rsplit_once('-') else {
        return false;
    };
    !label.is_empty()
        && label.len() <= 64
        && label.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
        && timestamp.parse::<u64>().is_ok_and(|value| value > 0)
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReflectionAck {
    pub kind: String,
    pub tag: String,
    pub written: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub obsidian: Option<String>,
}

impl ReflectionAck {
    pub fn verify_daily(&self) -> Result<(), String> {
        if self.kind != "daily" {
            return Err(format!(
                "reflection acknowledged kind `{}`, expected `daily`",
                self.kind
            ));
        }
        if self.tag.trim().is_empty() {
            return Err("reflection acknowledgement is missing `tag`".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionInviteAck {
    pub ok: bool,
    pub action: String,
    pub pair_url: String,
    pub expires_in_secs: u64,
    pub handed_to_daemon: bool,
}

impl CompanionInviteAck {
    pub fn verify(&self) -> Result<(), String> {
        if !self.ok {
            return Err("Companion invite did not acknowledge success".to_string());
        }
        require_action(&self.action, "pair_phone")?;
        if !self.handed_to_daemon {
            return Err("Companion invite was not handed to the daemon".to_string());
        }
        if self.expires_in_secs == 0 {
            return Err("Companion invite has no usable lifetime".to_string());
        }
        let Some(payload) = self.pair_url.strip_prefix("neoth://companion/pair?") else {
            return Err("Companion invite URL has an unexpected route".to_string());
        };
        if payload.trim().is_empty() {
            return Err("Companion invite URL is missing its payload".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::process::{ExitStatus, Output};

    use super::*;

    #[cfg(windows)]
    fn status(code: i32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(code as u32)
    }

    #[cfg(unix)]
    fn status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(code << 8)
    }

    fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: status(code),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn backup_ack_json(wrote: &str) -> String {
        serde_json::json!({
            "operation": "backup.create",
            "wrote": wrote,
            "entries": 7,
            "include_wal": true,
            "includes_plaintext_credentials": false,
        })
        .to_string()
    }

    #[test]
    fn backup_ack_matches_the_exact_cli_receipt_shape() {
        // Guards CLI (cli/backup.rs) ↔ struct drift: deny_unknown_fields makes
        // any added/renamed CLI field fail this decode.
        let ack: BackupAck =
            serde_json::from_str(&backup_ack_json("/tmp/x.tar.gz")).expect("decode backup receipt");
        assert_eq!(ack.operation, "backup.create");
        assert_eq!(ack.entries, 7);
        assert!(ack.include_wal);
    }

    #[test]
    fn backup_ack_confirms_a_real_non_empty_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("neoth-backup.tar.gz");
        std::fs::write(&archive, b"tarball-bytes").unwrap();
        let ack: BackupAck =
            serde_json::from_str(&backup_ack_json(archive.to_str().unwrap())).unwrap();
        assert_eq!(
            ack.verify_and_read_back().unwrap(),
            archive.to_str().unwrap()
        );
    }

    #[test]
    fn backup_ack_rejects_an_archive_that_is_not_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("missing.tar.gz");
        let ack: BackupAck =
            serde_json::from_str(&backup_ack_json(archive.to_str().unwrap())).unwrap();
        assert!(ack.verify_and_read_back().is_err());
    }

    #[test]
    fn backup_ack_rejects_an_empty_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("empty.tar.gz");
        std::fs::write(&archive, b"").unwrap();
        let ack: BackupAck =
            serde_json::from_str(&backup_ack_json(archive.to_str().unwrap())).unwrap();
        assert!(ack.verify_and_read_back().is_err());
    }

    #[test]
    fn backup_ack_rejects_a_foreign_operation() {
        let ack = BackupAck {
            operation: "catalog.refresh".to_string(),
            wrote: "/tmp/x.tar.gz".to_string(),
            entries: 7,
            include_wal: true,
            includes_plaintext_credentials: false,
        };
        assert!(ack.verify_and_read_back().is_err());
    }

    #[test]
    fn backup_ack_rejects_unexpected_plaintext_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("creds.tar.gz");
        std::fs::write(&archive, b"tarball-bytes").unwrap();
        let ack = BackupAck {
            operation: "backup.create".to_string(),
            wrote: archive.to_str().unwrap().to_string(),
            entries: 7,
            include_wal: true,
            includes_plaintext_credentials: true,
        };
        assert!(ack.verify_and_read_back().is_err());
    }

    #[test]
    fn backup_ack_rejects_zero_entries() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("real.tar.gz");
        std::fs::write(&archive, b"tarball-bytes").unwrap();
        let ack = BackupAck {
            operation: "backup.create".to_string(),
            wrote: archive.to_str().unwrap().to_string(),
            entries: 0,
            include_wal: true,
            includes_plaintext_credentials: false,
        };
        assert!(ack.verify_and_read_back().is_err());
    }

    #[test]
    fn skill_toggle_ack_verifies_id_and_state() {
        let ack: SkillToggleAck =
            serde_json::from_str(r#"{"id":"my-skill","state":"enabled"}"#).unwrap();
        // CLI lowercases the id → case-insensitive match.
        assert!(ack.verify("My-Skill", "enabled").is_ok());
        assert!(ack.verify("my-skill", "disabled").is_err()); // wrong state
        assert!(ack.verify("other", "enabled").is_err()); // wrong id
    }

    #[test]
    fn plugin_toggle_ack_verifies_id_and_state() {
        // Changed path with the optional approval fields — tolerated (no
        // deny_unknown_fields); pins the full receipt shape.
        let changed: PluginToggleAck = serde_json::from_str(
            r#"{"id":"wasm-hello","previous":"pending","new":"active","changed":true,"granted_capability":"none","manifest_sha256":"ab","wasm_sha256":"cd"}"#,
        )
        .unwrap();
        assert_eq!(changed.verify("wasm-hello", "active"), Ok(true));
        // Idempotent no-op (already active) is a benign success.
        let noop: PluginToggleAck = serde_json::from_str(
            r#"{"id":"wasm-hello","previous":"active","new":"active","changed":false}"#,
        )
        .unwrap();
        assert_eq!(noop.verify("wasm-hello", "active"), Ok(false));
        assert!(changed.verify("other", "active").is_err()); // wrong id
        assert!(changed.verify("wasm-hello", "disabled").is_err()); // wrong state
    }

    #[test]
    fn skill_uninstall_ack_reports_removal_and_rejects_wrong_id() {
        let removed: SkillUninstallAck =
            serde_json::from_str(r#"{"id":"gone","removed":true}"#).unwrap();
        assert_eq!(removed.verify("gone"), Ok(true));
        // Idempotent no-op (already absent) is a benign success, not an error.
        let noop: SkillUninstallAck =
            serde_json::from_str(r#"{"id":"gone","removed":false}"#).unwrap();
        assert_eq!(noop.verify("gone"), Ok(false));
        assert!(removed.verify("other").is_err()); // wrong id
    }

    fn hemisphere_set_ack_json(segment: &str) -> String {
        // The exact shape `cli/hemispheres.rs::run_set` emits (all six fields);
        // pins CLI<->struct drift for the four the GUI consumes.
        serde_json::json!({
            "role": "logic",
            "prior_provider": "anthropic",
            "new_provider": "local_qwen",
            "model": "qwen2.5",
            "mode": "multi",
            "audit_segment": segment,
        })
        .to_string()
    }

    #[test]
    fn hemisphere_ack_confirms_matching_rebind_and_audit_segment() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("seg-0001.wal");
        std::fs::write(&segment, b"wal-bytes").unwrap();
        let ack: HemisphereSetAck =
            serde_json::from_str(&hemisphere_set_ack_json(segment.to_str().unwrap())).unwrap();
        assert_eq!(ack.role, "logic");
        assert_eq!(ack.new_provider, "local_qwen");
        assert!(
            ack.verify_and_read_back("logic", "local_qwen", Some("qwen2.5"))
                .is_ok()
        );
        // A specific model was not requested — the ack's model is not checked.
        assert!(
            ack.verify_and_read_back("logic", "local_qwen", None)
                .is_ok()
        );
    }

    #[test]
    fn hemisphere_ack_rejects_role_provider_model_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("seg-0002.wal");
        std::fs::write(&segment, b"wal-bytes").unwrap();
        let ack: HemisphereSetAck =
            serde_json::from_str(&hemisphere_set_ack_json(segment.to_str().unwrap())).unwrap();
        assert!(
            ack.verify_and_read_back("memory", "local_qwen", None)
                .is_err()
        );
        assert!(
            ack.verify_and_read_back("logic", "anthropic", None)
                .is_err()
        );
        assert!(
            ack.verify_and_read_back("logic", "local_qwen", Some("gpt-4o"))
                .is_err()
        );
    }

    #[test]
    fn hemisphere_ack_rejects_absent_audit_segment() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("never-written.wal");
        let ack: HemisphereSetAck =
            serde_json::from_str(&hemisphere_set_ack_json(segment.to_str().unwrap())).unwrap();
        assert!(
            ack.verify_and_read_back("logic", "local_qwen", None)
                .is_err()
        );
    }

    #[test]
    fn hemisphere_rebind_stays_on_the_typed_receipt_boundary() {
        // Guards against regressing set_hemisphere_via_subprocess back to the
        // unchecked spawn_neothd_plain(...).output() + status.success() probe.
        let source = include_str!("main.rs");
        let start = source
            .find("fn set_hemisphere_via_subprocess(")
            .expect("hemisphere rebind function");
        let end = source[start..]
            .find("\nfn fetch_hemisphere_model_ids(")
            .map(|offset| start + offset)
            .expect("function following hemisphere rebind");
        let body = &source[start..end];
        assert!(
            body.contains("run_neothd_json_action::<gui_action::HemisphereSetAck>"),
            "hemisphere rebind must dispatch through the typed receipt boundary"
        );
        assert!(
            body.contains("verify_and_read_back"),
            "hemisphere rebind must verify the receipt and read the audit segment back"
        );
        assert!(
            !body.contains("spawn_neothd_plain"),
            "hemisphere rebind must not fall back to the unchecked subprocess probe"
        );
    }

    fn valid_catalog_refresh_json(path: &Path) -> serde_json::Value {
        serde_json::json!({
            "operation": "catalog.refresh",
            "path": path.display().to_string(),
            "catalog_version": 2,
            "catalog_generation": 7,
            "catalog_hash": "0".repeat(64),
            "catalog_changed": false,
            "result": "fresh",
            "stale_only": true,
            "configured": ["openai_api"],
            "fresh": ["openai_api"],
            "refreshed": [],
            "failed": [],
            "superseded": [],
            "skipped_no_creds": [],
            "credential_failures": [],
            "configuration_failures": [],
            "unsupported": [],
            "blocked_no_consent": [],
        })
    }

    #[test]
    fn failed_exit_never_parses_success_looking_stdout() {
        let error = decode_json_output::<ToggleAck>(
            &output(
                7,
                r#"{"ok":true,"action":"enable","enabled":true}"#,
                "permission denied",
            ),
            "Babel enable",
        )
        .unwrap_err();
        assert!(error.contains("exit 7"));
        assert!(error.contains("permission denied"));
    }

    #[test]
    fn successful_exit_without_ack_fails_closed() {
        let error =
            decode_json_output::<ToggleAck>(&output(0, "  \n", ""), "Babel enable").unwrap_err();
        assert!(error.contains("no acknowledgement"));
    }

    #[test]
    fn malformed_or_extended_ack_is_rejected() {
        assert!(decode_json_output::<ToggleAck>(&output(0, "not json", ""), "Babel").is_err());
        assert!(
            decode_json_output::<ToggleAck>(
                &output(
                    0,
                    r#"{"ok":true,"action":"enable","enabled":true,"surprise":1}"#,
                    "",
                ),
                "Babel",
            )
            .is_err()
        );
    }

    #[test]
    fn omi_resume_receipt_binds_operation_and_review_state() {
        let acknowledgement = decode_json_output::<OmiResumeAck>(
            &output(
                0,
                r#"{"operation":"resume","resumed":true,"review_evidence_retained":true}"#,
                "",
            ),
            "OMI resume",
        )
        .unwrap();
        acknowledgement.verify().unwrap();

        let inconsistent = decode_json_output::<OmiResumeAck>(
            &output(
                0,
                r#"{"operation":"resume","resumed":true,"review_evidence_retained":false}"#,
                "",
            ),
            "OMI resume",
        )
        .unwrap();
        assert!(inconsistent.verify().is_err());

        let wrong_operation = decode_json_output::<OmiResumeAck>(
            &output(
                0,
                r#"{"operation":"purge","resumed":true,"review_evidence_retained":true}"#,
                "",
            ),
            "OMI resume",
        )
        .unwrap();
        assert!(wrong_operation.verify().is_err());
    }

    #[test]
    fn omi_deletion_receipt_binds_operation_and_conversation() {
        let purge = decode_json_output::<OmiDeletionAck>(
            &output(
                0,
                r#"{"operation":"purge","conversation_id":"conv-7","conversations":1,"segments":2,"media":3,"actions":4,"tasks":5,"groundtruth":6}"#,
                "",
            ),
            "OMI purge",
        )
        .unwrap();
        purge.verify("purge", Some("conv-7")).unwrap();
        assert_eq!(purge.total_removed(), 21);
        assert!(purge.verify("purge", Some("conv-8")).is_err());
        assert!(purge.verify("retention", None).is_err());

        let retention = decode_json_output::<OmiDeletionAck>(
            &output(
                0,
                r#"{"operation":"retention","conversation_id":null,"conversations":0,"segments":0,"media":0,"actions":0,"tasks":0,"groundtruth":0}"#,
                "",
            ),
            "OMI retention",
        )
        .unwrap();
        retention.verify("retention", None).unwrap();
        assert!(retention.verify("retention", Some("conv-7")).is_err());
    }

    #[test]
    fn omi_allow_reimport_receipt_binds_conversation_and_terminal_state() {
        let acknowledgement = decode_json_output::<OmiAllowReimportAck>(
            &output(
                0,
                r#"{"operation":"allow_reimport","conversation_id":"conv-7","tombstone_cleared":true,"stale_native_receipt_removed":false,"reconciliation_state_cleared":true}"#,
                "",
            ),
            "OMI allow-reimport",
        )
        .unwrap();
        acknowledgement.verify("conv-7").unwrap();
        assert!(acknowledgement.verify("conv-8").is_err());

        let incomplete = decode_json_output::<OmiAllowReimportAck>(
            &output(
                0,
                r#"{"operation":"allow_reimport","conversation_id":"conv-7","tombstone_cleared":true,"stale_native_receipt_removed":false,"reconciliation_state_cleared":false}"#,
                "",
            ),
            "OMI allow-reimport",
        )
        .unwrap();
        assert!(incomplete.verify("conv-7").is_err());
    }

    #[test]
    fn omi_status_readback_is_complete_strict_and_semantically_valid() {
        let valid = r#"{
            "enabled":true,"mode":"both","configuration_valid":true,
            "configuration_error":null,"developer_api_credential_present":true,
            "native_ingest_credential_present":true,"endpoint":"https://api.omi.me",
            "listen_addr":"127.0.0.1:8003","retention_days":30,"poll_interval_secs":30,
            "retain_transcripts":false,"audio_enabled":true,"visual_enabled":true,
            "video_enabled":false,"allow_cloud_api":true,"allow_cloud_summary":false,
            "create_actions":true,"seed_groundtruth":true,"summary_enabled":true,
            "ledger_initialized":true,"conversations":2,"segments":3,"media":4,
            "actions":5,"tombstones":1,"pending_audits":0,"runtime_state":"healthy",
            "runtime_persisted_state":"healthy","runtime_detail":"ready","runtime_pid":12,
            "runtime_updated_ns":13,"daemon_pid":12,"sanitizer_halted":false,
            "last_success_ns":14,"last_error":null,"last_retention_purge_ns":15,
            "last_retention_error":null
        }"#;
        let acknowledgement =
            decode_json_output::<OmiStatusAck>(&output(0, valid, ""), "OMI status").unwrap();
        acknowledgement.verify().unwrap();
        let verify_status = |body: &str| {
            decode_json_output::<OmiStatusAck>(&output(0, body, ""), "OMI status")?.verify()
        };

        let extended = valid.replacen(
            "\"last_retention_error\":null",
            "\"last_retention_error\":null,\"surprise\":true",
            1,
        );
        assert!(
            decode_json_output::<OmiStatusAck>(&output(0, &extended, ""), "OMI status").is_err()
        );

        let contradictory = valid.replacen(
            "\"configuration_error\":null",
            "\"configuration_error\":\"broken\"",
            1,
        );
        let acknowledgement =
            decode_json_output::<OmiStatusAck>(&output(0, &contradictory, ""), "OMI status")
                .unwrap();
        assert!(acknowledgement.verify().is_err());

        let unknown_runtime = valid.replacen(
            "\"runtime_state\":\"healthy\"",
            "\"runtime_state\":\"future_state\"",
            1,
        );
        let acknowledgement =
            decode_json_output::<OmiStatusAck>(&output(0, &unknown_runtime, ""), "OMI status")
                .unwrap();
        assert!(acknowledgement.verify().is_err());

        let missing_required_credential = valid.replacen(
            "\"developer_api_credential_present\":true",
            "\"developer_api_credential_present\":false",
            1,
        );
        let acknowledgement = decode_json_output::<OmiStatusAck>(
            &output(0, &missing_required_credential, ""),
            "OMI status",
        )
        .unwrap();
        assert!(acknowledgement.verify().is_err());

        let disabled_wrong = valid.replacen("\"enabled\":true", "\"enabled\":false", 1);
        assert!(verify_status(&disabled_wrong).is_err());
        let disabled = disabled_wrong.replacen(
            "\"runtime_state\":\"healthy\"",
            "\"runtime_state\":\"disabled\"",
            1,
        );
        verify_status(&disabled).unwrap();

        let no_daemon_wrong = valid.replacen("\"daemon_pid\":12", "\"daemon_pid\":null", 1);
        assert!(verify_status(&no_daemon_wrong).is_err());
        let no_daemon = no_daemon_wrong.replacen(
            "\"runtime_state\":\"healthy\"",
            "\"runtime_state\":\"inactive\"",
            1,
        );
        verify_status(&no_daemon).unwrap();

        let stale_pid_wrong = valid.replacen("\"daemon_pid\":12", "\"daemon_pid\":13", 1);
        assert!(verify_status(&stale_pid_wrong).is_err());
        let stale_pid = stale_pid_wrong.replacen(
            "\"runtime_state\":\"healthy\"",
            "\"runtime_state\":\"unknown\"",
            1,
        );
        verify_status(&stale_pid).unwrap();

        let persisted_mismatch = valid.replacen(
            "\"runtime_persisted_state\":\"healthy\"",
            "\"runtime_persisted_state\":\"failed\"",
            1,
        );
        assert!(verify_status(&persisted_mismatch).is_err());
        let persisted_failure = persisted_mismatch.replacen(
            "\"runtime_state\":\"healthy\"",
            "\"runtime_state\":\"failed\"",
            1,
        );
        verify_status(&persisted_failure).unwrap();

        let missing_persisted = valid.replacen(
            "\"runtime_persisted_state\":\"healthy\"",
            "\"runtime_persisted_state\":null",
            1,
        );
        assert!(verify_status(&missing_persisted).is_err());
        let missing_persisted_unknown = missing_persisted.replacen(
            "\"runtime_state\":\"healthy\"",
            "\"runtime_state\":\"unknown\"",
            1,
        );
        verify_status(&missing_persisted_unknown).unwrap();

        let invalid_persisted = valid
            .replacen(
                "\"runtime_persisted_state\":\"healthy\"",
                "\"runtime_persisted_state\":\"inactive\"",
                1,
            )
            .replacen(
                "\"runtime_state\":\"healthy\"",
                "\"runtime_state\":\"inactive\"",
                1,
            );
        assert!(verify_status(&invalid_persisted).is_err());

        let zero_daemon_pid = valid.replacen("\"daemon_pid\":12", "\"daemon_pid\":0", 1);
        assert!(verify_status(&zero_daemon_pid).is_err());
        let zero_runtime_pid = valid.replacen("\"runtime_pid\":12", "\"runtime_pid\":0", 1);
        assert!(verify_status(&zero_runtime_pid).is_err());
    }

    #[test]
    fn omi_probe_receipt_enforces_core_mode_and_outcome_partition() {
        let probe = |mode: &str,
                     local_endpoint: Option<&str>,
                     native_listener: Option<&str>,
                     public_api: Option<&str>| OmiProbeAck {
            mode: mode.to_string(),
            local_endpoint: local_endpoint.map(str::to_string),
            native_listener: native_listener.map(str::to_string),
            public_api: public_api.map(str::to_string),
        };

        for outcome in ["reachable", "port_closed", "timeout", "forbidden"] {
            probe("developer_api", Some(outcome), None, None)
                .verify()
                .unwrap();
        }
        probe(
            "developer_api",
            None,
            None,
            Some("not_probed_auth_required"),
        )
        .verify()
        .unwrap();
        for outcome in ["reachable", "port_closed", "timeout"] {
            probe("native_ingest", None, Some(outcome), None)
                .verify()
                .unwrap();
        }
        probe("both", Some("reachable"), Some("timeout"), None)
            .verify()
            .unwrap();
        probe(
            "both",
            None,
            Some("port_closed"),
            Some("not_probed_auth_required"),
        )
        .verify()
        .unwrap();
        probe("legacy_memories", Some("reachable"), None, None)
            .verify()
            .unwrap();

        for mode in ["developer_api", "native_ingest", "both", "legacy_memories"] {
            assert!(probe(mode, None, None, None).verify().is_err());
        }
        assert!(
            probe(
                "developer_api",
                Some("reachable"),
                None,
                Some("not_probed_auth_required"),
            )
            .verify()
            .is_err()
        );
        assert!(
            probe("developer_api", Some("reachable"), Some("reachable"), None)
                .verify()
                .is_err()
        );
        assert!(
            probe("native_ingest", Some("reachable"), Some("reachable"), None)
                .verify()
                .is_err()
        );
        assert!(
            probe(
                "both",
                Some("reachable"),
                Some("reachable"),
                Some("not_probed_auth_required"),
            )
            .verify()
            .is_err()
        );
        assert!(
            probe(
                "legacy_memories",
                None,
                None,
                Some("not_probed_auth_required"),
            )
            .verify()
            .is_err()
        );
        assert!(
            probe("developer_api", Some("future_outcome"), None, None)
                .verify()
                .is_err()
        );
        assert!(
            probe("native_ingest", None, Some("forbidden"), None)
                .verify()
                .is_err()
        );
        assert!(
            probe("developer_api", None, None, Some("reachable"))
                .verify()
                .is_err()
        );
        assert!(
            probe("future_mode", Some("reachable"), None, None)
                .verify()
                .is_err()
        );
    }

    #[test]
    fn mcp_tool_error_is_a_failed_typed_receipt() {
        let success = decode_json_output::<McpToolCallAck>(
            &output(
                0,
                r#"{"content":[{"type":"text","text":"done"}],"isError":false}"#,
                "",
            ),
            "MCP call",
        )
        .unwrap();
        success.verify_success().unwrap();

        let tool_error = decode_json_output::<McpToolCallAck>(
            &output(
                0,
                r#"{"content":[{"type":"text","text":"denied"}],"isError":true}"#,
                "",
            ),
            "MCP call",
        )
        .unwrap();
        assert!(tool_error.verify_success().is_err());
        assert!(
            decode_json_output::<McpToolCallAck>(&output(0, r#"{"content":[]}"#, ""), "MCP call",)
                .is_err(),
            "missing isError must fail closed"
        );
        assert!(
            decode_json_output::<McpToolCallAck>(
                &output(0, r#"{"content":[],"isError":false,"unexpected":true}"#, "",),
                "MCP call",
            )
            .is_err(),
            "uncontracted MCP fields must fail closed"
        );
    }

    #[test]
    fn mcp_gui_callback_cannot_infer_success_from_exit_status() {
        let source = include_str!("main.rs");
        let start = source.find("C4 — MCP call:").expect("MCP callback marker");
        let end = source[start..]
            .find("Research P0 — hooks probe")
            .map(|offset| start + offset)
            .expect("MCP callback end marker");
        let callback = &source[start..end];
        assert!(callback.contains("run_neothd_json_action::<gui_action::McpToolCallAck>"));
        assert!(callback.contains("acknowledgement.verify_success()?"));
        for unchecked in ["spawn_neothd_plain", ".output()", "status.success()"] {
            assert!(
                !callback.contains(unchecked),
                "MCP callback regressed to unchecked boundary: {unchecked}"
            );
        }
    }

    #[test]
    fn catalog_refresh_receipt_binds_operation_path_result_and_provider_sets() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("models_catalog.json");
        let receipt = |value| serde_json::from_value::<CatalogRefreshAck>(value).unwrap();
        let refreshed = receipt(serde_json::json!({
            "operation": "catalog.refresh",
            "path": path.display().to_string(),
            "catalog_version": 2,
            "catalog_generation": 7,
            "catalog_hash": "0".repeat(64),
            "catalog_changed": true,
            "result": "refreshed",
            "stale_only": false,
            "configured": ["openai_api"],
            "fresh": [],
            "refreshed": ["openai_api"],
            "failed": [],
            "superseded": [],
            "skipped_no_creds": [],
            "credential_failures": [],
            "configuration_failures": [],
            "unsupported": [],
            "blocked_no_consent": [],
        }));
        let summary = refreshed.verify(&path, false).unwrap();
        assert!(summary.contains("1 provider"));
        assert!(
            refreshed
                .verify(&home.path().join("other_catalog.json"), false)
                .is_err()
        );
        assert!(refreshed.verify(&path, true).is_err());

        let stale_mixed = receipt(serde_json::json!({
            "operation": "catalog.refresh",
            "path": path.display().to_string(),
            "catalog_version": 2,
            "catalog_generation": 7,
            "catalog_hash": "0".repeat(64),
            "catalog_changed": true,
            "result": "refreshed",
            "stale_only": true,
            "configured": ["anthropic_api", "openai_api"],
            "fresh": ["anthropic_api"],
            "refreshed": ["openai_api"],
            "failed": [],
            "superseded": [],
            "skipped_no_creds": [],
            "credential_failures": [],
            "configuration_failures": [],
            "unsupported": [],
            "blocked_no_consent": [],
        }));
        assert!(
            stale_mixed
                .verify(&path, true)
                .unwrap()
                .contains("1 already fresh")
        );

        let partial = receipt(serde_json::json!({
            "operation": "catalog.refresh",
            "path": path.display().to_string(),
            "catalog_version": 2,
            "catalog_generation": 7,
            "catalog_hash": "0".repeat(64),
            "catalog_changed": true,
            "result": "partial",
            "stale_only": false,
            "configured": [
                "openai_api",
                "anthropic_api",
                "gemini_api",
                "aws_bedrock",
                "openai_compat"
            ],
            "fresh": [],
            "refreshed": ["openai_api"],
            "failed": ["anthropic_api"],
            "superseded": [],
            "skipped_no_creds": ["gemini_api"],
            "credential_failures": ["aws_bedrock"],
            "configuration_failures": ["openai_compat"],
            "unsupported": [],
            "blocked_no_consent": [],
        }));
        let error = partial.verify(&path, false).unwrap_err();
        for provider in [
            "anthropic_api",
            "gemini_api",
            "aws_bedrock",
            "openai_compat",
        ] {
            assert!(error.contains(provider));
        }
        let partial_wire = serde_json::to_vec(&serde_json::json!({
            "operation": "catalog.refresh",
            "path": path.display().to_string(),
            "catalog_version": 2,
            "catalog_generation": 7,
            "catalog_hash": "0".repeat(64),
            "catalog_changed": true,
            "result": "partial",
            "stale_only": false,
            "configured": ["openai_api", "gemini_api"],
            "fresh": [],
            "refreshed": ["openai_api"],
            "failed": [],
            "superseded": [],
            "skipped_no_creds": ["gemini_api"],
            "credential_failures": [],
            "configuration_failures": [],
            "unsupported": [],
            "blocked_no_consent": [],
        }))
        .unwrap();
        let partial_output = Output {
            status: status(7),
            stdout: partial_wire.clone(),
            stderr: b"Error: generic catalog refresh incomplete".to_vec(),
        };
        let typed_outcome =
            decode_catalog_refresh_output(&partial_output, "Catalog refresh", &path, false)
                .unwrap();
        assert!(matches!(
            typed_outcome,
            CatalogRefreshOutcome::Incomplete { changed: true, .. }
        ));
        assert!(typed_outcome.message().contains("gemini_api"));
        assert!(
            !typed_outcome
                .message()
                .contains("generic catalog refresh incomplete")
        );
        let zero_exit_partial = Output {
            status: status(0),
            stdout: partial_wire,
            stderr: Vec::new(),
        };
        assert!(
            decode_catalog_refresh_output(&zero_exit_partial, "Catalog refresh", &path, false,)
                .unwrap_err()
                .contains("incorrectly returned a successful process exit")
        );

        let superseded_after_clear = receipt(serde_json::json!({
            "operation": "catalog.refresh",
            "path": path.display().to_string(),
            "catalog_version": 2,
            "catalog_generation": null,
            "catalog_hash": null,
            "catalog_changed": false,
            "result": "partial",
            "stale_only": false,
            "configured": ["openai_api"],
            "fresh": [],
            "refreshed": [],
            "failed": [],
            "superseded": ["openai_api"],
            "skipped_no_creds": [],
            "credential_failures": [],
            "configuration_failures": [],
            "unsupported": [],
            "blocked_no_consent": [],
        }));
        let error = superseded_after_clear.verify(&path, false).unwrap_err();
        assert!(error.contains("superseded"));
        assert!(error.contains("openai_api"));

        let no_sources = receipt(serde_json::json!({
            "operation": "catalog.refresh",
            "path": path.display().to_string(),
            "catalog_version": 2,
            "catalog_generation": null,
            "catalog_hash": null,
            "catalog_changed": false,
            "result": "no_sources",
            "stale_only": false,
            "configured": [],
            "fresh": [],
            "refreshed": [],
            "failed": [],
            "superseded": [],
            "skipped_no_creds": [],
            "credential_failures": [],
            "configuration_failures": [],
            "unsupported": [],
            "blocked_no_consent": [],
        }));
        assert!(
            no_sources
                .verify(&path, false)
                .unwrap_err()
                .contains("configured")
        );
        let unsupported_only = receipt(serde_json::json!({
            "operation": "catalog.refresh",
            "path": path.display().to_string(),
            "catalog_version": 2,
            "catalog_generation": null,
            "catalog_hash": null,
            "catalog_changed": false,
            "result": "no_discoverable_sources",
            "stale_only": false,
            "configured": ["local_ollama"],
            "fresh": [],
            "refreshed": [],
            "failed": [],
            "superseded": [],
            "skipped_no_creds": [],
            "credential_failures": [],
            "configuration_failures": [],
            "unsupported": ["local_ollama"],
            "blocked_no_consent": [],
        }));
        assert!(
            unsupported_only
                .verify(&path, false)
                .unwrap()
                .contains("no refresh is needed")
        );
        let no_sources_output = Output {
            status: status(2),
            stdout: serde_json::to_vec(&serde_json::json!({
                "operation": "catalog.refresh",
                "path": path.display().to_string(),
                "catalog_version": 2,
                "catalog_generation": null,
                "catalog_hash": null,
                "catalog_changed": false,
                "result": "no_sources",
                "stale_only": false,
                "configured": [],
                "fresh": [],
                "refreshed": [],
                "failed": [],
                "superseded": [],
                "skipped_no_creds": [],
                "credential_failures": [],
                "configuration_failures": [],
                "unsupported": [],
                "blocked_no_consent": [],
            }))
            .unwrap(),
            stderr: Vec::new(),
        };
        let no_sources_outcome =
            decode_catalog_refresh_output(&no_sources_output, "Catalog refresh", &path, false)
                .unwrap();
        assert!(matches!(
            no_sources_outcome,
            CatalogRefreshOutcome::Incomplete { changed: false, .. }
        ));
        assert!(
            no_sources_outcome
                .message()
                .contains("No model-provider source")
        );

        let success_wire = serde_json::to_vec(&valid_catalog_refresh_json(&path)).unwrap();
        let nonzero_success = Output {
            status: status(9),
            stdout: success_wire,
            stderr: Vec::new(),
        };
        assert!(
            decode_catalog_refresh_output(&nonzero_success, "Catalog refresh", &path, true,)
                .unwrap_err()
                .contains("success receipt with a non-zero")
        );

        let valid_fresh = valid_catalog_refresh_json(&path);
        let mut wrong_action = valid_fresh.clone();
        wrong_action["operation"] = serde_json::json!("catalog.clear");
        let mut uncovered_provider = valid_fresh.clone();
        uncovered_provider["configured"] = serde_json::json!(["openai_api", "gemini_api"]);
        let mut duplicate_outcome = valid_fresh.clone();
        duplicate_outcome["refreshed"] = serde_json::json!(["openai_api"]);
        let mut unknown_provider = valid_fresh.clone();
        unknown_provider["configured"] = serde_json::json!(["future_provider"]);
        unknown_provider["fresh"] = serde_json::json!(["future_provider"]);
        let mut future_result = valid_fresh.clone();
        future_result["result"] = serde_json::json!("future_result");
        let mut wrong_version = valid_fresh.clone();
        wrong_version["catalog_version"] = serde_json::json!(3);
        let mut malformed_hash = valid_fresh.clone();
        malformed_hash["catalog_hash"] = serde_json::json!("not-a-sha256");
        let mut torn_snapshot = valid_fresh.clone();
        torn_snapshot["catalog_generation"] = serde_json::Value::Null;
        let mut unexpected = valid_fresh.clone();
        unexpected["unexpected"] = serde_json::json!(true);
        for invalid in [
            wrong_action,
            uncovered_provider,
            duplicate_outcome,
            unknown_provider,
            future_result,
            wrong_version,
            malformed_hash,
            torn_snapshot,
            unexpected,
        ] {
            if let Ok(acknowledgement) = serde_json::from_value::<CatalogRefreshAck>(invalid) {
                assert!(
                    acknowledgement
                        .verify(&path, acknowledgement.stale_only)
                        .is_err()
                )
            }
        }
    }

    #[test]
    fn catalog_refresh_gui_reports_and_reloads_only_after_verified_receipt() {
        let source = include_str!("main.rs");
        let start = source
            .find("L97 — rebuild the model catalog")
            .expect("catalog refresh callback marker");
        let end = source[start..]
            .find("Research P0 — quota probe")
            .map(|offset| start + offset)
            .expect("catalog refresh callback end marker");
        let callback = &source[start..end];

        assert!(callback.contains("neothd_json_command(&[\"catalog\", \"refresh\"])"));
        assert!(callback.contains("gui_action::run_catalog_refresh("));
        assert!(callback.contains("default_neoth_home().join(\"models_catalog.json\")"));
        assert!(callback.contains("Ok(outcome)"));
        assert!(callback.contains("outcome.catalog_changed()"));
        assert!(callback.contains("outcome.committed_snapshot()"));
        assert!(callback.contains("gui_action::run_catalog_list("));
        assert!(callback.contains("Some(generation)"));
        assert!(callback.contains("Some(hash)"));
        assert!(!callback.contains("run_neothd_probe"));
        assert!(callback.contains("compare_exchange("));
        assert!(callback.contains("Err(error)"));
        assert!(callback.contains("(\"error\", error, None)"));
        assert!(callback.contains("if let Some(output) = output"));
        assert!(callback.contains("w.set_catalog_running(false)"));

        let verified = callback.find("gui_action::run_catalog_refresh(").unwrap();
        let success = callback.find("Ok(outcome)").unwrap();
        let reload = callback.find("gui_action::run_catalog_list(").unwrap();
        let error = callback.find("(\"error\", error, None)").unwrap();
        let toast = callback.find("push_toast(&weak, kind").unwrap();
        let spinner_stop = callback.find("w.set_catalog_running(false)").unwrap();
        assert!(verified < success && success < reload && reload < toast);
        assert!(error < spinner_stop, "error paths must stop the spinner");
        for unchecked in [
            "spawn_neothd_plain",
            ".output()",
            "status.success()",
            "which_neothd",
        ] {
            assert!(
                !callback.contains(unchecked),
                "catalog refresh regressed to unchecked boundary: {unchecked}"
            );
        }
    }

    #[test]
    fn catalog_readback_requires_successful_exit_and_exact_nested_schema() {
        let path = std::env::current_dir().unwrap().join("models_catalog.json");
        let valid = serde_json::json!({
            "operation": "catalog.list",
            "path": path.display().to_string(),
            "state": "present",
            "catalog_version": 2,
            "catalog_generation": 11,
            "catalog_hash": "a".repeat(64),
            "providers": {
                "openai_api": {
                    "fetched_at_unix": 42,
                    "source": "api",
                    "last_error": null,
                    "models": [{
                        "id": "gpt-test",
                        "display_name": null,
                        "summary": null,
                        "deprecated": false
                    }]
                }
            }
        })
        .to_string();
        let parsed =
            decode_json_output::<CatalogListAck>(&output(0, &valid, ""), "Catalog readback")
                .unwrap();
        parsed
            .verify(&path, Some(11), Some(&"a".repeat(64)))
            .unwrap();
        assert_eq!(parsed.providers.len(), 1);

        assert!(
            decode_json_output::<CatalogListAck>(
                &output(9, &valid, "read failed"),
                "Catalog readback",
            )
            .is_err()
        );
        let extended = valid.replace(
            "\"deprecated\":false",
            "\"deprecated\":false,\"unbound\":true",
        );
        assert!(
            decode_json_output::<CatalogListAck>(&output(0, &extended, ""), "Catalog readback",)
                .is_err()
        );

        assert!(
            parsed
                .verify(&path, Some(12), Some(&"a".repeat(64)))
                .is_err(),
            "readback must bind the exact committed generation"
        );
        assert!(
            parsed
                .verify(&path, Some(11), Some(&"b".repeat(64)))
                .is_err(),
            "readback must bind the exact committed content hash"
        );

        let missing: CatalogListAck = serde_json::from_value(serde_json::json!({
            "operation": "catalog.list",
            "path": path.display().to_string(),
            "state": "missing",
            "catalog_version": 2,
            "catalog_generation": null,
            "catalog_hash": null,
            "providers": {}
        }))
        .unwrap();
        missing.verify(&path, None, None).unwrap();
        assert!(
            missing
                .verify(&path, Some(11), Some(&"a".repeat(64)))
                .is_err()
        );
    }

    #[test]
    fn groundtruth_and_quota_receipts_bind_submitted_effect_and_instance() {
        let home = tempfile::tempdir().unwrap();
        let views = home.path().join("views.db");
        let quota = home.path().join("quota.json");
        let views_json = serde_json::to_string(&views).unwrap();
        let quota_json = serde_json::to_string(&quota).unwrap();

        let add: GroundtruthAddAck = serde_json::from_str(&format!(
            r#"{{"operation":"groundtruth.add","id":17,"scope":"global","statement":"operator fact","path":{views_json}}}"#
        ))
        .unwrap();
        add.verify("operator fact", "global", &views).unwrap();
        assert!(add.verify("different fact", "global", &views).is_err());
        assert!(add.verify("operator fact", "host:other", &views).is_err());

        let revoke: GroundtruthRevokeAck = serde_json::from_str(&format!(
            r#"{{"operation":"groundtruth.revoke","revoked":17,"path":{views_json}}}"#
        ))
        .unwrap();
        revoke.verify("17", &views).unwrap();
        assert!(revoke.verify("18", &views).is_err());

        let set_cap: QuotaSetCapAck = serde_json::from_str(&format!(
            r#"{{"operation":"quota.set-cap","provider":"openai_api","estimated_daily_cap":200,"path":{quota_json}}}"#
        ))
        .unwrap();
        set_cap.verify("openai_api", "200", &quota).unwrap();
        assert!(set_cap.verify("gemini_api", "200", &quota).is_err());
        assert!(set_cap.verify("openai_api", "201", &quota).is_err());
        assert!(
            set_cap
                .verify("openai_api", "200", &home.path().join("other.json"))
                .is_err()
        );

        assert!(
            serde_json::from_str::<GroundtruthAddAck>(&format!(
                r#"{{"operation":"groundtruth.add","id":17,"scope":"global","statement":"operator fact","path":{views_json},"unexpected":true}}"#
            ))
            .is_err()
        );
    }

    #[test]
    fn sensitive_receipts_bind_forget_and_revoke_to_durable_evidence() {
        use sha2::Digest as _;

        let home = tempfile::tempdir().unwrap();
        let views = home.path().join("views.db");
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let audit_path = wal.join("01890f9e-7b34-7cc0-8000-000000000001-memory-forget-000001.wal");
        let audit_bytes = b"durable forget audit";
        std::fs::write(&audit_path, audit_bytes).unwrap();
        let audit_sha256 = hex::encode(sha2::Sha256::digest(audit_bytes));
        let forget_value = serde_json::json!({
            "operation": "memory.forget",
            "confirmed": true,
            "topic": "AcmeCorp",
            "episode_rows": 1,
            "consolidated_rows": 2,
            "longterm_rows": 3,
            "raw_turn_rows": 4,
            "groundtruth_revoked": 5,
            "embedding_rows": 6,
            "profile_rows": 7,
            "profile_pending_rows": 8,
            "profile_outbox_rows": 9,
            "entity_rows": 10,
            "relation_rows": 11,
            "link_rows": 12,
            "contradiction_rows": 13,
            "foreign_event_rows": 14,
            "people_rows": 15,
            "commit": {
                "database_path": views,
                "sqlite_cascade_committed": true
            },
            "anti_resurrection_sentinel": {
                "field": "_tombstone.acmecorp",
                "active": true,
                "never_recreate": true,
                "asserted_by": "cli",
                "asserted_at": 1_700_000_000_i64
            },
            "audit": {
                "event_type": "TOMBSTONE_REQUESTED",
                "segment_path": audit_path.clone(),
                "segment_sha256": audit_sha256,
                "persisted": true
            },
            "communication_profile": {
                "subjects_deleted": 0,
                "topic_addressable": false,
                "reason": "typed_communication_evidence_is_not_topic_addressable",
                "erase_with": "neoth memory erase-communication-profile --confirm"
            }
        });
        let forget: MemoryForgetAck = serde_json::from_value(forget_value.clone()).unwrap();
        forget.verify("AcmeCorp", &views, &wal).unwrap();
        assert_eq!(forget.deleted_total().unwrap(), (1..=15).sum::<i64>());
        assert!(forget.verify("Other", &views, &wal).is_err());
        std::fs::write(&audit_path, b"tampered").unwrap();
        assert!(forget.verify("AcmeCorp", &views, &wal).is_err());
        let mut unknown_forget = forget_value;
        unknown_forget["uncontracted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<MemoryForgetAck>(unknown_forget).is_err());

        let canonical = "cd".repeat(32);
        let registry_path = home.path().join("cluster.yaml");
        let registry_bytes = b"peers: []\n";
        std::fs::write(&registry_path, registry_bytes).unwrap();
        let registry_sha256 = hex::encode(sha2::Sha256::digest(registry_bytes));
        let sidecar_name = format!(
            "cluster_peer_revoked_1700000000_{:038}_{}.json",
            1,
            "ab".repeat(16)
        );
        let revoke_value = serde_json::json!({
            "operation": "cluster.peer.revoke",
            "requested_peer": "cdcd",
            "canonical_peer": canonical.clone(),
            "removed": true,
            "noop": false,
            "post_state": {
                "registry_path": registry_path.clone(),
                "registry_file_present": true,
                "registry_sha256": registry_sha256,
                "peer_count": 1,
                "canonical_peer_absent": true,
                "verified": true
            },
            "audit": {
                "required": true,
                "state": "sidecar_committed_for_wal_ingest",
                "event_type": "CLUSTER_PEER_REVOKED",
                "sidecar_path": home.path().join("pending_audit").join(sidecar_name),
                "durable_handoff_persisted": true
            }
        });
        let revoke: ClusterPeerRevokeAck = serde_json::from_value(revoke_value).unwrap();
        revoke.verify("cdcd", home.path()).unwrap();
        std::fs::write(&registry_path, b"tampered registry").unwrap();
        assert!(revoke.verify("cdcd", home.path()).is_err());
        std::fs::write(&registry_path, registry_bytes).unwrap();

        let status_value = serde_json::json!({
            "mode": "cluster",
            "policy": "trusted-only",
            "peer_count": 1,
            "conflict_count": 0,
            "operator_id": "operator",
            "node_id": "node",
            "cluster_name": "test",
            "cluster_passphrase_set": true,
            "cluster_identity_configured": true,
            "cluster_enabled": true,
            "restart_required": false,
            "transport_active": true,
            "transport": "active",
            "listen_port": 4242,
            "mdns_enabled": true,
            "trusted_ssids": [],
            "peers": [{
                "id": "ef".repeat(32),
                "label": "survivor",
                "last_seen": "now",
                "last_seen_unix": 1_700_000_000_i64,
                "reachable": true
            }],
            "gossip": {"replicate_raw_ingress": false, "replay_budget_days": 7}
        });
        let status: ClusterStatusAck = serde_json::from_value(status_value.clone()).unwrap();
        revoke.verify_readback(&status).unwrap();
        let mut stale = status_value;
        stale["peers"][0]["id"] = serde_json::json!(canonical);
        let stale: ClusterStatusAck = serde_json::from_value(stale).unwrap();
        assert!(revoke.verify_readback(&stale).is_err());
    }

    #[test]
    fn sensitive_gui_mutations_cannot_infer_success_from_process_exit() {
        let source = include_str!("main.rs");
        let revoke_start = source
            .find("L73 — mesh peer context menu: revoke")
            .expect("cluster revoke callback marker");
        let revoke_end = source[revoke_start..]
            .find("let weak_conflict_resolve")
            .map(|offset| revoke_start + offset)
            .expect("cluster revoke callback end marker");
        let revoke = &source[revoke_start..revoke_end];
        assert!(revoke.contains("run_neothd_json_action::<gui_action::ClusterPeerRevokeAck>"));
        assert!(revoke.contains("ack.verify(&peer, &expected_home)?"));
        assert!(revoke.contains("ack.verify_readback(&readback)?"));

        let forget_start = source
            .find("GUI-overhaul feature parity — Memory \"forget a topic\", permanent")
            .expect("memory forget callback marker");
        let forget_end = source[forget_start..]
            .find("GUI-overhaul (gap panel")
            .map(|offset| forget_start + offset)
            .expect("memory forget callback end marker");
        let forget = &source[forget_start..forget_end];
        assert!(forget.contains("run_neothd_json_action::<gui_action::MemoryForgetAck>"));
        assert!(forget.contains("ack.verify(&topic, &expected_database, &expected_wal_dir)?"));

        for (name, callback) in [("cluster revoke", revoke), ("memory forget", forget)] {
            for unchecked in ["spawn_neothd_plain", ".output()", "status.success()"] {
                assert!(
                    !callback.contains(unchecked),
                    "{name} mutation regressed to unchecked boundary: {unchecked}"
                );
            }
        }
    }

    #[test]
    fn groundtruth_and_quota_gui_mutations_require_typed_receipts() {
        let source = include_str!("main.rs");
        let groundtruth_start = source
            .find("L93 — add a ground-truth statement")
            .expect("groundtruth mutation marker");
        let groundtruth_end = source[groundtruth_start..]
            .find("Research P0 — catalog probe")
            .map(|offset| groundtruth_start + offset)
            .expect("groundtruth mutation end marker");
        let groundtruth = &source[groundtruth_start..groundtruth_end];
        for receipt in ["GroundtruthAddAck", "GroundtruthRevokeAck"] {
            assert!(
                groundtruth.contains(&format!("run_neothd_json_action::<gui_action::{receipt}>")),
                "missing typed groundtruth receipt {receipt}"
            );
        }
        assert!(groundtruth.matches("acknowledgement.verify(").count() >= 2);

        let quota_start = source
            .find("R4-05 — set a per-provider daily quota cap")
            .expect("quota mutation marker");
        let quota_end = source[quota_start..]
            .find("Research P0 — tweaks probe")
            .map(|offset| quota_start + offset)
            .expect("quota mutation end marker");
        let quota = &source[quota_start..quota_end];
        assert!(quota.contains("run_neothd_json_action::<gui_action::QuotaSetCapAck>"));
        assert!(quota.contains("acknowledgement.verify(&provider, &cap, &expected_path)?"));

        for (name, callback) in [("groundtruth", groundtruth), ("quota", quota)] {
            for unchecked in ["spawn_neothd_plain", ".output()", "status.success()"] {
                assert!(
                    !callback.contains(unchecked),
                    "{name} mutation regressed to unchecked boundary: {unchecked}"
                );
            }
        }
    }

    #[test]
    fn permission_and_kanban_receipts_fail_closed_on_process_or_schema_errors() {
        let success_looking = r#"{"ok":true,"action":"move","task_id":42,"status":"done"}"#;
        assert!(
            decode_json_output::<KanbanMoveAck>(
                &output(9, success_looking, "database is locked"),
                "Kanban move",
            )
            .unwrap_err()
            .contains("exit 9")
        );
        assert!(
            decode_json_output::<KanbanMoveAck>(&output(0, "not-json", ""), "Kanban move",)
                .unwrap_err()
                .contains("invalid acknowledgement")
        );
        assert!(
            decode_json_output::<PermissionMutationAck>(&output(0, "", ""), "Permission set",)
                .unwrap_err()
                .contains("no acknowledgement")
        );
    }

    #[test]
    fn permission_receipts_bind_operation_action_and_decision() {
        let expected_path = std::env::current_dir().unwrap().join("freedom.yaml");
        let set: PermissionMutationAck = serde_json::from_str(
            r#"{"operation":"set","action":"shell_exec","decision":"confirm","path":"freedom.yaml"}"#,
        )
        .unwrap();
        set.verify_set("shell_exec", "confirm", &expected_path)
            .unwrap();
        assert!(
            set.verify_set("file_write", "confirm", &expected_path)
                .is_err()
        );
        assert!(
            set.verify_set("shell_exec", "allow", &expected_path)
                .is_err()
        );
        assert!(
            set.verify_set(
                "shell_exec",
                "confirm",
                &expected_path.with_file_name("other.yaml"),
            )
            .is_err()
        );

        let wrong_operation: PermissionMutationAck = serde_json::from_str(
            r#"{"operation":"cleared","action":"shell_exec","decision":null,"path":"freedom.yaml"}"#,
        )
        .unwrap();
        assert!(
            wrong_operation
                .verify_set("shell_exec", "confirm", &expected_path)
                .is_err()
        );
        wrong_operation
            .verify_clear("shell_exec", &expected_path)
            .unwrap();
        assert!(
            wrong_operation
                .verify_clear("file_write", &expected_path)
                .is_err()
        );
    }

    #[test]
    fn kanban_receipts_bind_action_task_and_target() {
        let added: KanbanAddAck = serde_json::from_str(
            r#"{"ok":true,"action":"add","task_id":42,"session_id":7,"status":"backlog","title":"Ship it","task_type":"feature"}"#,
        )
        .unwrap();
        added.verify("Ship it", "feature").unwrap();
        assert!(added.verify("Wrong title", "feature").is_err());
        assert!(added.verify("Ship it", "bug").is_err());

        let missing_session: KanbanAddAck = serde_json::from_str(
            r#"{"ok":true,"action":"add","task_id":42,"session_id":0,"status":"backlog","title":"Ship it","task_type":"feature"}"#,
        )
        .unwrap();
        assert!(missing_session.verify("Ship it", "feature").is_err());

        let moved: KanbanMoveAck = serde_json::from_str(
            r#"{"ok":true,"action":"move","task_id":42,"status":"in_progress"}"#,
        )
        .unwrap();
        moved.verify("42", "in_progress").unwrap();
        assert!(moved.verify("41", "in_progress").is_err());
        assert!(moved.verify("42", "done").is_err());

        let wrong_action: KanbanMoveAck = serde_json::from_str(
            r#"{"ok":true,"action":"assign","task_id":42,"status":"in_progress"}"#,
        )
        .unwrap();
        assert!(wrong_action.verify("42", "in_progress").is_err());

        let assigned: KanbanAssignAck = serde_json::from_str(
            r#"{"ok":true,"action":"assign","task_id":42,"hemisphere":"left","worker":null}"#,
        )
        .unwrap();
        assigned.verify("42", "left", None).unwrap();
        assert!(assigned.verify("42", "right", None).is_err());
        assert!(assigned.verify("42", "left", Some("worker-a")).is_err());

        let comment: KanbanCommentAck = serde_json::from_str(
            r#"{"ok":true,"action":"comment","task_id":42,"comment_id":9,"author":"operator"}"#,
        )
        .unwrap();
        comment.verify("42", "operator").unwrap();
        assert!(comment.verify("41", "operator").is_err());
        assert!(comment.verify("42", "buddy").is_err());

        let finished: KanbanFinishAck = serde_json::from_str(
            r#"{"ok":true,"action":"finish","task_id":42,"status":"done","verified_tests":false}"#,
        )
        .unwrap();
        finished.verify("42", false).unwrap();
        assert!(finished.verify("41", false).is_err());
        assert!(finished.verify("42", true).is_err());

        let promoted: KanbanPromoteAck = serde_json::from_str(
            r#"{"ok":true,"action":"promote","task_id":42,"from_status":"review","status":"done","promoted":true,"blocker":null}"#,
        )
        .unwrap();
        promoted.verify("42").unwrap();
        assert!(promoted.verify("41").is_err());

        let blocked: KanbanPromoteAck = serde_json::from_str(
            r#"{"ok":false,"action":"promote","task_id":42,"from_status":"review","status":"review","promoted":false,"blocker":"tests failing"}"#,
        )
        .unwrap();
        assert_eq!(blocked.verify("42").unwrap_err(), "tests failing");
    }

    #[test]
    fn typed_toggle_ack_binds_action_and_state() {
        let ack = decode_json_output::<ToggleAck>(
            &output(0, r#"{"ok":true,"action":"enable","enabled":true}"#, ""),
            "Babel enable",
        )
        .unwrap();
        ack.verify("enable", true).unwrap();
        assert!(ack.verify("disable", true).is_err());
        assert!(ack.verify("enable", false).is_err());
    }

    #[test]
    fn buddy_policy_acks_bind_exact_action_and_target_state() {
        let self_activation: BuddySelfActivationAck = serde_json::from_str(
            r#"{"ok":true,"action":"set_self_activation","self_activation_enabled":true}"#,
        )
        .unwrap();
        self_activation.verify(true).unwrap();
        assert!(self_activation.verify(false).is_err());

        let proactive: BuddyProactiveAck = serde_json::from_str(
            r#"{"ok":true,"action":"set_proactive","proactive_enabled":false}"#,
        )
        .unwrap();
        proactive.verify(false).unwrap();
        assert!(proactive.verify(true).is_err());

        let wrong_action: BuddyProactiveAck = serde_json::from_str(
            r#"{"ok":true,"action":"set_self_activation","proactive_enabled":true}"#,
        )
        .unwrap();
        assert!(wrong_action.verify(true).is_err());
        assert!(
            serde_json::from_str::<BuddySelfActivationAck>(
                r#"{"ok":true,"action":"set_self_activation","self_activation_enabled":true,"surprise":1}"#,
            )
            .is_err(),
            "Buddy ACKs must reject uncontracted fields"
        );
    }

    #[test]
    fn bounded_text_preserves_success_warnings_without_changing_the_ack() {
        assert_eq!(
            bounded_text(b" warn [collision]: overlaps morning\n", 400).as_deref(),
            Some("warn [collision]: overlaps morning")
        );
        assert_eq!(bounded_text(b" \n", 400), None);
    }

    #[test]
    fn proposal_ack_binds_id_and_final_status() {
        let ack: ProposalMutationAck =
            serde_json::from_str(r#"{"ok":true,"action":"accept","id":"p42","status":"accepted"}"#)
                .unwrap();
        ack.verify("accept", "p42", "accepted").unwrap();
        assert!(ack.verify("accept", "p41", "accepted").is_err());
    }

    #[test]
    fn companion_ack_requires_exact_neoth_pair_route() {
        let good: CompanionInviteAck = serde_json::from_str(
            r#"{"ok":true,"action":"pair_phone","pair_url":"neoth://companion/pair?invite=abc","expires_in_secs":300,"handed_to_daemon":true}"#,
        )
        .unwrap();
        good.verify().unwrap();

        let bad: CompanionInviteAck = serde_json::from_str(
            r#"{"ok":true,"action":"pair_phone","pair_url":"https://example.test/pair?invite=abc","expires_in_secs":300,"handed_to_daemon":true}"#,
        )
        .unwrap();
        assert!(bad.verify().is_err());
    }

    #[test]
    fn background_run_ack_must_match_the_confirmed_request_binding() {
        let home = tempfile::tempdir().unwrap();
        let bgjobs = home.path().join("bgjobs");
        std::fs::create_dir(&bgjobs).unwrap();
        let binding = "ab".repeat(32);
        let approval: BgRunApprovalAck = serde_json::from_value(serde_json::json!({
            "action": "jobs_approve_run",
            "approved": true,
            "request_binding_sha256": binding,
            "token": "t".repeat(43),
        }))
        .unwrap();
        approval.verify().unwrap();

        let id = format!("gui-42-{}", "ab".repeat(16));
        let log_path = bgjobs.join(format!("{id}.log"));
        std::fs::write(&log_path, b"").unwrap();
        let ack: BgRunAck = serde_json::from_value(serde_json::json!({
            "action": "jobs_run",
            "started": true,
            "id": id,
            "pid": 42,
            "log_path": log_path,
            "request_binding_sha256": approval.request_binding_sha256.clone(),
        }))
        .unwrap();
        ack.verify(&approval.request_binding_sha256, home.path())
            .unwrap();
        let rows = vec![BgJobListRowAck {
            id: ack.id.clone(),
            status: "running".to_string(),
            exit_code: None,
        }];
        ack.verify_listed(&rows).unwrap();
        assert!(ack.verify(&"cd".repeat(32), home.path()).is_err());
        assert!(ack.verify_listed(&[]).is_err());

        let wrong_path: BgRunAck = serde_json::from_value(serde_json::json!({
            "action": "jobs_run",
            "started": true,
            "id": ack.id,
            "pid": 42,
            "log_path": home.path().join("wrong.log"),
            "request_binding_sha256": approval.request_binding_sha256.clone(),
        }))
        .unwrap();
        assert!(
            wrong_path
                .verify(&approval.request_binding_sha256, home.path())
                .is_err()
        );
        assert!(
            serde_json::from_value::<BgRunAck>(serde_json::json!({
                "action": "jobs_run",
                "started": true,
                "id": format!("gui-42-{}", "ab".repeat(16)),
                "pid": 42,
                "log_path": log_path,
                "request_binding_sha256": approval.request_binding_sha256.clone(),
                "unexpected": true,
            }))
            .is_err()
        );
    }

    #[test]
    fn background_job_list_rows_are_strict_and_state_consistent() {
        let rows: Vec<BgJobListRowAck> = serde_json::from_str(
            r#"[
                {"id":"build-42-abcd","status":"running","exit_code":null},
                {"id":"scan-43-abcd","status":"completed","exit_code":0}
            ]"#,
        )
        .unwrap();
        verify_bg_job_list(&rows).unwrap();

        let inconsistent: BgJobListRowAck =
            serde_json::from_str(r#"{"id":"build-42-abcd","status":"running","exit_code":0}"#)
                .unwrap();
        assert!(inconsistent.verify().is_err());
        let duplicate: Vec<BgJobListRowAck> = serde_json::from_str(
            r#"[
                {"id":"build-42-abcd","status":"running","exit_code":null},
                {"id":"build-42-abcd","status":"completed","exit_code":0}
            ]"#,
        )
        .unwrap();
        assert!(verify_bg_job_list(&duplicate).is_err());
        assert!(
            serde_json::from_str::<BgJobListRowAck>(
                r#"{"id":"build-42-abcd","status":"running","exit_code":null,"unexpected":true}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn targeted_action_receipts_are_typed_and_verified() {
        let cron: CronMutationAck =
            serde_json::from_str(r#"{"ok":true,"action":"add","id":"morning"}"#).unwrap();
        cron.verify("add", "morning").unwrap();

        let calendar: CalendarAddAck = serde_json::from_str(
            r#"{"ok":true,"action":"add","outcome":"created","uid":"neoth-a1"}"#,
        )
        .unwrap();
        calendar.verify().unwrap();

        let smart_approve: SmartApproveAck = serde_json::from_str(
            r#"{"ok":true,"action":"set_smart_approve","smart_approve":true,"changed":true}"#,
        )
        .unwrap();
        smart_approve.verify(true).unwrap();
        assert!(smart_approve.verify(false).is_err());

        let sovereign: SovereignDisableAck = serde_json::from_str(
            r#"{"mode":"full-auto","sovereign_buddy":false,"previous_autonomy":"full"}"#,
        )
        .unwrap();
        sovereign.verify().unwrap();

        let scan: SelfDevScanAck = serde_json::from_str(
            r#"{"ok":true,"action":"scan","signals":2,"proposals_staged":1,"proposals_skipped_deployed":0,"proposals_skipped_not_auto_safe":1}"#,
        )
        .unwrap();
        scan.verify().unwrap();

        let edit: SelfEditAck = serde_json::from_str(
            r#"{"status":"applied","paths":["src/lib.rs"],"diff_hash":"abc","dry_run":false}"#,
        )
        .unwrap();
        edit.verify_applied("abc").unwrap();

        let dream: DreamNowAck = serde_json::from_str(
            r#"{"day":"2026-07-15","events_considered":3,"dreams_written":1,"path":"dreams/2026-07-15.jsonl","path_taken":"Local"}"#,
        )
        .unwrap();
        dream.verify().unwrap();

        let reflection: ReflectionAck = serde_json::from_str(
            r#"{"kind":"daily","tag":"2026-07-15","written":false,"reason":"already_done"}"#,
        )
        .unwrap();
        reflection.verify_daily().unwrap();
    }

    #[test]
    fn targeted_gui_mutations_cannot_regress_to_the_unchecked_probe() {
        let source = include_str!("main.rs");
        let start = source.find("GAP-01 Automation / Cron CRUD panel").unwrap();
        let end = source
            .find("Wave 4b — Mesh & Cluster panel callbacks")
            .unwrap();
        let callbacks = &source[start..end];

        // Raw probes in this region are read-only views: Dream day,
        // Permissions matrix, and two WAL inspectors. (The Memory graph
        // moved off the probe boundary to a verified structured readback.)
        assert_eq!(callbacks.matches("run_neothd_probe(").count(), 4);
        assert!(callbacks.contains("run_neothd_probe(&[\"dream\", \"show\""));
        // Baseline: Cron 4, Babel 2, Calendar 1, Self-Improve 5,
        // Self-Dev 4, Obsidian 2, Dream 1, Reflect 1, Buddy policy 4,
        // Companion 1.
        // New actions may increase this count; removing any existing checked
        // action requires an explicit contract-test update.
        assert!(callbacks.matches("run_neothd_json_action").count() >= 25);
        for action in [
            "Cron add",
            "Cron run",
            "Cron toggle",
            "Cron remove",
            "Babel enable",
            "Babel disable",
            "Calendar add",
            "Self-Improve enable",
            "Self-Improve disable",
            "Self-Improve dry-run",
            "Self-Improve accept",
            "Self-Improve rollback",
            "Self-Dev scan",
            "Self-Dev accept",
            "Self-Dev decline",
            "Self-Dev source apply",
            "Obsidian sync",
            "Obsidian wiki build",
            "Dream now",
            "Daily reflection",
            "Buddy self-activation update",
            "Buddy proactive update",
            "Sovereign disable",
            "Smart-Approve update",
            "Companion invite",
        ] {
            assert!(
                callbacks.contains(&format!("\"{action}\"")),
                "missing typed GUI action: {action}"
            );
        }
        assert!(callbacks.contains("&[\"reflect\", \"digest\", \"daily\"]"));

        let wave8_start = source
            .find("Wave 8 — C2 permissions matrix + A4 kanban context menu")
            .unwrap();
        let wave8_end = source[wave8_start..]
            .find("H2 — Memory graph callbacks")
            .map(|offset| wave8_start + offset)
            .unwrap();
        let wave8 = &source[wave8_start..wave8_end];
        assert_eq!(
            wave8.matches("run_neothd_probe(").count(),
            1,
            "only the read-only permissions matrix may use the probe boundary"
        );
        assert!(wave8.contains("run_neothd_probe(&[\"permissions\", \"show\""));
        for action in [
            "Permission set",
            "Permission clear",
            "Kanban move",
            "Kanban bulk move",
            "Kanban assign",
        ] {
            assert!(
                wave8.contains(&format!("\"{action}\"")),
                "missing typed Wave 8 action: {action}"
            );
        }
        assert_eq!(wave8.matches("run_neothd_json_action::<").count(), 5);
    }

    #[test]
    fn every_kanban_mutation_callback_uses_a_typed_receipt() {
        let source = include_str!("main.rs");
        assert_eq!(
            source.matches("window.on_kanban_").count(),
            14,
            "new Kanban callbacks must be classified as read-only or typed mutations"
        );
        for read_only in [
            "window.on_kanban_refresh_clicked",
            "window.on_kanban_copy_task_id",
            "window.on_kanban_task_selected",
            "window.on_kanban_session_selected",
            "window.on_kanban_select_toggled",
            "window.on_kanban_selection_cleared",
        ] {
            assert!(
                source.contains(read_only),
                "missing read-only callback {read_only}"
            );
        }

        let spec_start = source.find("GOLD-ADAPT-AOS-06 — New-Spec pane").unwrap();
        let spec_end = source[spec_start..]
            .find("GOLD-ADAPT-ODY-03 — attach/remove handlers")
            .map(|offset| spec_start + offset)
            .unwrap();
        let spec = &source[spec_start..spec_end];
        assert!(spec.contains("run_neothd_json_action::<gui_action::KanbanAddAck>"));
        assert!(spec.contains("ack.verify(&title, \"feature\")"));
        assert!(spec.contains("request_kanban_refresh(&weak)"));
        for unchecked in ["spawn_neothd_plain", ".output()", "run_neothd_probe("] {
            assert!(
                !spec.contains(unchecked),
                "spec-create regressed to unchecked boundary: {unchecked}"
            );
        }

        let wave8_start = source
            .find("Wave 8 — C2 permissions matrix + A4 kanban context menu")
            .unwrap();
        let wave8_end = source[wave8_start..]
            .find("H2 — Memory graph callbacks")
            .map(|offset| wave8_start + offset)
            .unwrap();
        let wave8 = &source[wave8_start..wave8_end];
        for receipt in ["KanbanMoveAck", "KanbanAssignAck"] {
            assert!(wave8.contains(receipt), "missing Wave 8 receipt {receipt}");
        }

        let legacy_start = source
            .find("Step 6 (2026-05-20): operator action handlers")
            .unwrap();
        let legacy_end = source[legacy_start..]
            .find("Step 5 (2026-05-20): task-card click handler")
            .map(|offset| legacy_start + offset)
            .unwrap();
        let legacy = &source[legacy_start..legacy_end];
        assert_eq!(legacy.matches("run_neothd_json_action::<").count(), 5);
        assert_eq!(legacy.matches("request_kanban_refresh(&weak)").count(), 5);
        for receipt in [
            "KanbanMoveAck",
            "KanbanPromoteAck",
            "KanbanCommentAck",
            "KanbanAssignAck",
            "KanbanFinishAck",
        ] {
            assert!(legacy.contains(receipt), "missing legacy receipt {receipt}");
        }
        for unchecked in ["spawn_neothd_plain", ".output()", "run_neothd_probe("] {
            assert!(
                !legacy.contains(unchecked),
                "legacy Kanban mutation regressed to unchecked boundary: {unchecked}"
            );
        }
    }

    #[test]
    fn omi_configure_receipt_binds_settings_credentials_generation_and_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let expected = OmiConfigureSettingsAck {
            enabled: true,
            mode: "both".into(),
            endpoint: "https://api.omi.me".into(),
            listen_addr: "127.0.0.1:8003".into(),
            retention_days: 14,
            retain_transcripts: true,
            audio_enabled: true,
            visual_enabled: true,
            video_enabled: false,
            allow_cloud_api: true,
            allow_cloud_summary: false,
            create_actions: true,
            seed_groundtruth: false,
            summary_enabled: true,
        };
        let config = b"operator_id: test\n";
        std::fs::write(&path, config).unwrap();
        let raw = serde_json::json!({
            "operation": "omi.configure",
            "operation_id": "0123456789abcdef0123456789abcdef",
            "path": path.display().to_string(),
            "settings_sha256": sha256_hex(&serde_json::to_vec(&expected).unwrap()),
            "config_sha256": sha256_hex(config),
            "reload_requested": true,
            "reload_ts_unix": 42,
            "settings": serde_json::to_value(&expected).unwrap(),
            "credentials": {
                "backend": "keychain",
                "updated_fields": ["omi_developer_api_key", "omi_ingest_token"],
                "developer_api_key_present": true,
                "native_ingest_token_present": true
            }
        });
        let ack: OmiConfigureAck = serde_json::from_value(raw.clone()).unwrap();
        ack.verify(&expected, &path, true, true).unwrap();

        let mut wrong = expected.clone();
        wrong.retention_days = 15;
        assert!(ack.verify(&wrong, &path, true, true).is_err());
        assert!(ack.verify(&expected, &path, false, true).is_err());

        let mut bad_hash = raw.clone();
        bad_hash["config_sha256"] = serde_json::Value::String("ABC".to_string());
        assert!(
            serde_json::from_value::<OmiConfigureAck>(bad_hash)
                .unwrap()
                .verify(&expected, &path, true, true)
                .is_err()
        );
        let mut wrong_settings_digest = raw.clone();
        wrong_settings_digest["settings_sha256"] = serde_json::Value::String("a".repeat(64));
        assert!(
            serde_json::from_value::<OmiConfigureAck>(wrong_settings_digest)
                .unwrap()
                .verify(&expected, &path, true, true)
                .is_err()
        );
        let mut stale_generation = raw.clone();
        stale_generation["config_sha256"] = serde_json::Value::String("b".repeat(64));
        assert!(
            serde_json::from_value::<OmiConfigureAck>(stale_generation)
                .unwrap()
                .verify(&expected, &path, true, true)
                .is_err()
        );
        let mut unknown = raw;
        unknown["unexpected"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<OmiConfigureAck>(unknown).is_err());
    }

    #[test]
    fn cluster_configure_receipt_binds_every_submitted_field_and_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let peers = vec!["peer,one".to_string(), " peer two ".to_string()];
        let ssids = vec!["home,lab".to_string(), "  exact wifi  ".to_string()];
        let raw = format!(
            r#"{{"operation":"cluster.configure","path":{},"reload_requested":true,"reload_error":null,"restart_required":true,"cluster_passphrase_set":true,"cluster":{{"name":"studio","enabled":true,"transport":"peeroxide","peers":["peer,one"," peer two "],"mdns":{{"enabled":false}},"policy":{{"announce_on_untrusted_wifi":false,"trusted_ssids":["home,lab","  exact wifi  "]}},"gossip":{{"replicate_raw_ingress":true,"replay_budget_days":14}},"listen_port":49738}}}}"#,
            serde_json::to_string(&path.display().to_string()).unwrap()
        );
        let ack: ClusterConfigureAck = serde_json::from_str(&raw).unwrap();
        let expected = ExpectedClusterConfig {
            name: Some("studio"),
            enabled: true,
            transport: "peeroxide",
            peers: &peers,
            mdns_enabled: false,
            announce_on_untrusted_wifi: false,
            trusted_ssids: &ssids,
            replicate_raw_ingress: true,
            replay_budget_days: 14,
            listen_port: 49738,
            cluster_passphrase_set: Some(true),
        };
        ack.verify(&expected, &path).unwrap();

        let mut wrong = expected;
        wrong.listen_port = 49739;
        assert!(ack.verify(&wrong, &path).is_err());
        assert!(
            serde_json::from_str::<ClusterConfigureAck>(&raw.replacen(
                "\"cluster\":{",
                "\"unexpected\":1,\"cluster\":{",
                1,
            ))
            .is_err(),
            "cluster receipts must reject uncontracted fields"
        );
    }

    #[test]
    fn cluster_conflict_resolution_receipt_is_exact_and_fail_closed() {
        let raw = r#"{"operation":"cluster.conflicts.resolve","content_id":"memory:abc","preferred_origin":"peer-a","resolved_count":2,"unresolved_remaining":0}"#;
        let ack: ClusterConflictResolveAck = serde_json::from_str(raw).unwrap();
        ack.verify("memory:abc", "peer-a").unwrap();
        assert!(ack.verify("memory:other", "peer-a").is_err());
        assert!(ack.verify("memory:abc", "peer-b").is_err());
        assert!(
            serde_json::from_str::<ClusterConflictResolveAck>(&raw.replacen(
                "\"resolved_count\":2",
                "\"resolved_count\":0",
                1
            ))
            .unwrap()
            .verify("memory:abc", "peer-a")
            .is_err()
        );
        assert!(
            serde_json::from_str::<ClusterConflictResolveAck>(&raw.replacen(
                "}",
                ",\"unexpected\":true}",
                1
            ))
            .is_err()
        );
    }

    #[test]
    fn cluster_request_sync_receipt_binds_operation_peer_state_and_queue_progress() {
        let peer = "ab".repeat(32);
        let raw = format!(
            r#"{{"operation":"cluster.request-sync","peer_pk":"{peer}","state":"queued","requested_at":1700000000,"expires_at":1700000030,"updated_at":1700000000,"last_attempt_at":null,"send_attempts":0,"last_error":null}}"#
        );
        let ack: ClusterRequestSyncAck = serde_json::from_str(&raw).unwrap();
        ack.verify(&peer).unwrap();

        for invalid in [
            raw.replacen("cluster.request-sync", "cluster.sync-state", 1),
            raw.replacen(&peer, &"cd".repeat(32), 1),
            raw.replacen("\"queued\"", "\"active\"", 1),
            raw.replacen("\"send_attempts\":0", "\"send_attempts\":1", 1),
        ] {
            let invalid_ack: ClusterRequestSyncAck = serde_json::from_str(&invalid).unwrap();
            assert!(invalid_ack.verify(&peer).is_err());
        }
        assert!(
            serde_json::from_str::<ClusterRequestSyncAck>(&raw.replacen(
                "}",
                ",\"unexpected\":true}",
                1
            ))
            .is_err(),
            "mesh sync receipts must reject uncontracted fields"
        );
    }

    #[test]
    fn mesh_force_sync_gui_is_singleflight_and_refreshes_only_after_verified_receipt() {
        let source = include_str!("main.rs");
        let start = source
            .find("Force Sync — enqueue one exact paired peer")
            .expect("mesh request callback marker");
        let end = source[start..]
            .find("L73 — mesh peer context menu: copy peer ID")
            .map(|offset| start + offset)
            .expect("mesh request callback end marker");
        let callback = &source[start..end];

        assert!(callback.contains("AtomicBool::new(false)"));
        assert!(callback.contains("swap(true, std::sync::atomic::Ordering::AcqRel)"));
        assert!(callback.contains("run_neothd_json_action::<gui_action::ClusterRequestSyncAck>"));
        assert!(callback.contains("\"request-sync\""));
        assert!(callback.contains("ack.verify(&peer)?"));
        assert!(callback.contains("done.store(false"));
        let verified = callback.find("ack.verify(&peer)?").unwrap();
        let refresh = callback.find("refresh_mesh(weak.clone())").unwrap();
        assert!(
            verified < refresh,
            "refresh must follow receipt verification"
        );
        for stale_path in ["\"sync-state\"", "run_neothd_probe("] {
            assert!(
                !callback.contains(stale_path),
                "force sync regressed to the old read-only path: {stale_path}"
            );
        }
    }

    #[test]
    fn cluster_read_receipts_reject_inconsistent_peer_and_conflict_rows() {
        let status_raw = r#"{
            "mode":"cluster","policy":"trusted","peer_count":1,"conflict_count":1,
            "operator_id":"operator","node_id":"node","cluster_name":"studio",
            "cluster_passphrase_set":true,"cluster_identity_configured":true,
            "cluster_enabled":true,"restart_required":false,"transport_active":true,
            "transport":"peeroxide","listen_port":49738,"mdns_enabled":true,
            "trusted_ssids":[],
            "peers":[{"id":"peer-a","label":"A","last_seen":"1s ago","last_seen_unix":1,"reachable":true}],
            "gossip":{"replicate_raw_ingress":false,"replay_budget_days":14}
        }"#;
        let status: ClusterStatusAck = serde_json::from_str(status_raw).unwrap();
        status.verify().unwrap();
        let wrong_count: ClusterStatusAck =
            serde_json::from_str(&status_raw.replacen("\"peer_count\":1", "\"peer_count\":2", 1))
                .unwrap();
        assert!(wrong_count.verify().is_err());
        let impossible_reachable: ClusterStatusAck = serde_json::from_str(&status_raw.replacen(
            "\"last_seen_unix\":1",
            "\"last_seen_unix\":0",
            1,
        ))
        .unwrap();
        assert!(impossible_reachable.verify().is_err());

        let conflicts_raw = r#"{
            "unresolved_count":1,"include_resolved":false,
            "conflicts":[{"id":7,"content_id":"memory:abc","incumbent_origin":"peer-a",
            "incoming_origin":"peer-b","incumbent_sha256":"aa","incoming_sha256":"bb",
            "policy":"manual","observed_at":1,"resolved_at":null,"preferred_origin":null}]
        }"#;
        let conflicts: ClusterConflictListAck = serde_json::from_str(conflicts_raw).unwrap();
        conflicts.verify_unresolved().unwrap();
        let resolved: ClusterConflictListAck = serde_json::from_str(&conflicts_raw.replacen(
            "\"resolved_at\":null",
            "\"resolved_at\":2",
            1,
        ))
        .unwrap();
        assert!(resolved.verify_unresolved().is_err());
    }

    #[test]
    fn cluster_gui_apply_has_no_direct_yaml_mutation_escape_hatch() {
        let source = include_str!("main.rs");
        let start = source
            .find("C6 — complete cluster desired state")
            .expect("cluster callback marker");
        let end = source[start..]
            .find("C3 — operator identity")
            .map(|offset| start + offset)
            .expect("cluster callback end marker");
        let callback = &source[start..end];
        assert!(callback.contains("ClusterConfigureAck"));
        assert!(callback.contains("acknowledgement.verify(&expected, &expected_path)"));
        assert!(callback.contains("run_json_with_private_stdin"));
        assert!(callback.contains("gui_action::run_json(&mut command"));
        assert!(callback.contains("FREEDOM_WRITE_LOCK"));
        assert!(callback.contains("CLUSTER_UI_REVISION.fetch_add"));
        for unchecked in [
            "set_nested_in_freedom",
            "set_cluster_mdns_enabled_in_freedom",
            "std::fs::write",
            "run_neothd_probe(",
        ] {
            assert!(
                !callback.contains(unchecked),
                "cluster mutation regressed to unchecked boundary: {unchecked}"
            );
        }
    }

    #[test]
    fn scrub_diagnostic_strips_noise_and_paths() {
        // Panic header + anyhow chain continuation + empty → dropped.
        assert_eq!(
            super::scrub_diagnostic("thread 'main' panicked at 'boom'"),
            None
        );
        assert_eq!(super::scrub_diagnostic("caused by: io error"), None);
        assert_eq!(super::scrub_diagnostic("   "), None);
        // "Error:" prefix dropped; a real message survives.
        assert_eq!(
            super::scrub_diagnostic("Error: provider timeout"),
            Some("provider timeout".to_string())
        );
        // Absolute Windows path redacted so internal layout never reaches a toast.
        assert_eq!(
            super::scrub_diagnostic("failed to read C:\\Users\\x\\.neoth\\freedom.yaml now"),
            Some("failed to read <path> now".to_string())
        );
    }
}
