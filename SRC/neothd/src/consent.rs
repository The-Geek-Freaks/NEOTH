//! V03-08 — First-run outbound-LLM consent.
//!
//! Operators explicitly consent to every remote provider route, recorded under
//! `~/.neoth/consent/<provider_kind>.granted`. Fixed-vendor providers use one
//! provider-wide marker. Configurable OpenAI/OpenAI-compatible/Azure routes use
//! canonical-origin grant sets so endpoint A never authorizes endpoint B.
//! Providers guaranteed to stay in-process (`LocalQwen`, `LocalOuro`, `Skip`)
//! never gate. Ollama is endpoint-aware: loopback is local; LAN/DNS/public
//! endpoints require the same origin-bound consent.
//!
//! Why a file marker instead of `freedom.yaml`: marker files survive
//! `neoth init` reconfigure passes that rewrite `freedom.yaml`, and they
//! let the operator audit consent state with `ls ~/.neoth/consent/`.
//!
//! Daemon path (`neoth serve`) cannot prompt (no TTY) — startup must bail
//! with the exact CLI to grant consent before reconnecting. CLI path
//! (`neoth chat`) prompts interactively on a TTY, bails with the same
//! instruction off a TTY.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::init::ProviderKind;

const ENDPOINT_GRANT_VERSION: u8 = 1;
const MAX_CONSENT_MARKER_BYTES: u64 = 64 * 1024;
static CONSENT_STORE_LOCK: Mutex<()> = Mutex::new(());

/// Cloud providers that ship operator text to a third-party. The operator
/// must explicitly grant consent before NEOTH routes any traffic to them.
///
/// THE canonical cloud-egress classifier (GOLD-SEC-09 / A-25). Every gate
/// that asks "is this provider cloud?" — the consent gate, the wizard
/// pre-grant hint, the cost/quota job preview — MUST route through here,
/// not maintain its own match set (those drifted and silently missed
/// `AnthropicApi`/`Cohere`). The match is EXHAUSTIVE on purpose: adding a
/// `ProviderKind` variant fails to compile until it is classified here.
pub fn is_cloud(kind: ProviderKind) -> bool {
    match kind {
        ProviderKind::ClaudeCli
        | ProviderKind::OpenaiApi
        | ProviderKind::AnthropicApi
        | ProviderKind::GeminiApi
        | ProviderKind::Cohere
        | ProviderKind::OpenaiCompat
        | ProviderKind::AwsBedrock
        | ProviderKind::AzureOpenAi
        | ProviderKind::GitHubCopilot
        | ProviderKind::RecursiveMas => true,
        ProviderKind::LocalQwen
        | ProviderKind::LocalOuro
        | ProviderKind::LocalOllama
        | ProviderKind::Skip => false,
    }
}

/// Stable slug used in WAL events + marker filenames. Matches
/// `Provider::name()` so log lines + marker filenames stay aligned.
pub fn slug(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::ClaudeCli => "claude_cli",
        ProviderKind::OpenaiApi => "openai_api",
        ProviderKind::AnthropicApi => "anthropic_api",
        ProviderKind::GeminiApi => "gemini_api",
        ProviderKind::Cohere => "cohere_api",
        ProviderKind::OpenaiCompat => "openai_compat",
        ProviderKind::LocalQwen => "local_qwen",
        ProviderKind::LocalOuro => "local_ouro",
        ProviderKind::LocalOllama => "local_ollama",
        ProviderKind::AwsBedrock => "aws_bedrock",
        ProviderKind::AzureOpenAi => "azure_openai",
        ProviderKind::GitHubCopilot => "copilot_api",
        ProviderKind::RecursiveMas => "recursive_mas",
        ProviderKind::Skip => "skip",
    }
}

pub fn kind_from_slug(s: &str) -> Option<ProviderKind> {
    match s {
        "claude_cli" => Some(ProviderKind::ClaudeCli),
        "openai_api" => Some(ProviderKind::OpenaiApi),
        "anthropic_api" => Some(ProviderKind::AnthropicApi),
        "gemini_api" => Some(ProviderKind::GeminiApi),
        "cohere_api" => Some(ProviderKind::Cohere),
        "openai_compat" => Some(ProviderKind::OpenaiCompat),
        "local_qwen" => Some(ProviderKind::LocalQwen),
        "local_ouro" => Some(ProviderKind::LocalOuro),
        "local_ollama" => Some(ProviderKind::LocalOllama),
        "aws_bedrock" => Some(ProviderKind::AwsBedrock),
        "azure_openai" => Some(ProviderKind::AzureOpenAi),
        "copilot_api" => Some(ProviderKind::GitHubCopilot),
        "recursive_mas" => Some(ProviderKind::RecursiveMas),
        "skip" => Some(ProviderKind::Skip),
        _ => None,
    }
}

fn cloud_label(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::ClaudeCli => "Anthropic Claude",
        ProviderKind::OpenaiApi => "OpenAI",
        ProviderKind::AnthropicApi => "Anthropic Claude (API key)",
        ProviderKind::GeminiApi => "Google Gemini",
        ProviderKind::Cohere => "Cohere",
        ProviderKind::OpenaiCompat => "the configured OpenAI-compatible endpoint",
        ProviderKind::AwsBedrock => "AWS Bedrock (region + IAM credential chain)",
        ProviderKind::AzureOpenAi => "Azure OpenAI (api-version + deployment name)",
        ProviderKind::GitHubCopilot => "GitHub Copilot (api.githubcopilot.com)",
        ProviderKind::LocalQwen => "local Qwen (no remote network)",
        ProviderKind::LocalOuro => "local Ouro thinking-models (no remote network)",
        ProviderKind::LocalOllama => "Ollama",
        ProviderKind::RecursiveMas => {
            "operator-installed RecursiveMAS sidecar (inherits host network access)"
        }
        ProviderKind::Skip => "no provider",
    }
}

/// One concrete provider route at the consent boundary. `ProviderKind` alone
/// is insufficient for configurable OpenAI/Azure adapters, Bedrock regions,
/// or Ollama: the same kind may target a different origin through
/// `provider_endpoint`, `provider_region`, or a hemisphere slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRoute {
    pub kind: ProviderKind,
    pub endpoint: Option<String>,
}

impl ConsentRoute {
    pub fn new(kind: ProviderKind, endpoint: Option<&str>) -> Self {
        Self {
            kind,
            endpoint: endpoint.map(str::to_owned),
        }
    }
}

/// Process-local consent authority for one interactive command invocation.
///
/// Nothing is persisted and no global bypass exists: callers must thread this
/// value into the concrete provider-call authorizer, where only the exact
/// canonical route recorded after an audited `AllowOnce` decision is accepted.
#[derive(Clone, Debug, Default)]
pub(crate) struct EphemeralConsent {
    authorities: std::sync::Arc<std::sync::Mutex<BTreeSet<String>>>,
}

impl EphemeralConsent {
    pub(crate) fn allow_route(&mut self, route: &ConsentRoute) -> Result<()> {
        let Some(authority) = ephemeral_authority(route)? else {
            return Ok(());
        };
        self.authorities
            .lock()
            .map_err(|_| anyhow::anyhow!("ephemeral consent capability lock is poisoned"))?
            .insert(authority);
        Ok(())
    }

    pub(crate) fn extend(&mut self, other: Self) -> Result<()> {
        let additions = other
            .authorities
            .lock()
            .map_err(|_| anyhow::anyhow!("source ephemeral consent capability lock is poisoned"))?
            .clone();
        self.authorities
            .lock()
            .map_err(|_| anyhow::anyhow!("target ephemeral consent capability lock is poisoned"))?
            .extend(additions);
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.authorities
            .lock()
            .map(|authorities| authorities.is_empty())
            // A poisoned capability cannot be treated as an empty/safe permit.
            .unwrap_or(false)
    }

    /// Non-consuming exact-route view used only while constructing an
    /// interactive fallback chain. The concrete leaf authorizer remains the
    /// sole consumer, so merely building a candidate cannot spend or duplicate
    /// one-shot authority.
    pub(crate) fn permits_route(&self, route: &ConsentRoute) -> Result<bool> {
        let Some(authority) = ephemeral_authority(route)? else {
            return Ok(false);
        };
        Ok(self
            .authorities
            .lock()
            .map_err(|_| anyhow::anyhow!("ephemeral consent capability lock is poisoned"))?
            .contains(&authority))
    }

    /// Atomically spend this command's one-shot authority for an exact route.
    ///
    /// Clones share the same set, so retries, fallbacks, helper calls and
    /// post-reply work cannot reuse a permit consumed by an earlier wire
    /// attempt.
    pub(crate) fn consume_route(&self, route: &ConsentRoute) -> Result<bool> {
        let Some(authority) = ephemeral_authority(route)? else {
            return Ok(false);
        };
        Ok(self
            .authorities
            .lock()
            .map_err(|_| anyhow::anyhow!("ephemeral consent capability lock is poisoned"))?
            .remove(&authority))
    }
}

fn ephemeral_authority(route: &ConsentRoute) -> Result<Option<String>> {
    if !route_requires_consent(route.kind, route.endpoint.as_deref()) {
        return Ok(None);
    }
    if uses_endpoint_bound_consent(route.kind) {
        return Ok(Some(format!(
            "{}\0{}",
            slug(route.kind),
            canonical_endpoint_origin(route.kind, route.endpoint.as_deref())?
        )));
    }
    if is_cloud(route.kind) {
        return Ok(Some(format!("{}\0provider", slug(route.kind))));
    }
    anyhow::bail!(
        "provider `{}` cannot receive ephemeral egress consent",
        slug(route.kind)
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentGrant {
    pub kind: ProviderKind,
    pub endpoint_origin: Option<String>,
    pub granted_unix_ts: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EndpointGrantFile {
    version: u8,
    endpoints: BTreeMap<String, String>,
}

/// One provider-scoped marker transition prepared from an exact byte snapshot.
///
/// The raw bytes remain private so audit callers cannot accidentally persist
/// secrets from a malformed marker. They receive stable SHA-256 bindings,
/// provider-scoped grant inventories, and exact origin deltas instead.
#[derive(Clone, Debug)]
pub(crate) struct ConsentMarkerUpdate {
    home: PathBuf,
    kind: ProviderKind,
    source_raw: Option<Vec<u8>>,
    target_raw: Option<Vec<u8>>,
    source_sha256: Option<String>,
    target_sha256: Option<String>,
    prior_grants: Vec<ConsentGrant>,
    target_grants: Vec<ConsentGrant>,
    added_endpoint_origins: Vec<String>,
    removed_endpoint_origins: Vec<String>,
    endpoint_delta_known: bool,
    malformed_source: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConsentMarkerBinding {
    exists: bool,
    sha256: Option<String>,
}

impl ConsentMarkerBinding {
    pub(crate) fn exists(&self) -> bool {
        self.exists
    }

    pub(crate) fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }
}

impl ConsentMarkerUpdate {
    pub(crate) fn kind(&self) -> ProviderKind {
        self.kind
    }

    pub(crate) fn changed(&self) -> bool {
        self.source_raw != self.target_raw
    }

    pub(crate) fn source_exists(&self) -> bool {
        self.source_raw.is_some()
    }

    pub(crate) fn target_exists(&self) -> bool {
        self.target_raw.is_some()
    }

    pub(crate) fn source_sha256(&self) -> Option<&str> {
        self.source_sha256.as_deref()
    }

    pub(crate) fn target_sha256(&self) -> Option<&str> {
        self.target_sha256.as_deref()
    }

    pub(crate) fn prior_grants(&self) -> &[ConsentGrant] {
        &self.prior_grants
    }

    pub(crate) fn target_grants(&self) -> &[ConsentGrant] {
        &self.target_grants
    }

    pub(crate) fn added_endpoint_origins(&self) -> &[String] {
        &self.added_endpoint_origins
    }

    pub(crate) fn removed_endpoint_origins(&self) -> &[String] {
        &self.removed_endpoint_origins
    }

    pub(crate) fn endpoint_delta_known(&self) -> bool {
        self.endpoint_delta_known
    }

    pub(crate) fn malformed_source(&self) -> bool {
        self.malformed_source
    }

    /// Commit only if the provider marker still has the exact bytes captured
    /// during preparation. A competing process therefore cannot be silently
    /// overwritten between audit-intent creation and state mutation.
    pub(crate) fn commit(&self) -> Result<bool> {
        apply_marker_cas(
            &self.home,
            self.kind,
            self.source_raw.as_deref(),
            self.target_raw.as_deref(),
            "commit",
        )
    }

    /// Restore the exact source bytes (including formatting) only if the
    /// committed target is still current. This cannot undo a later mutation.
    pub(crate) fn rollback(&self) -> Result<bool> {
        apply_marker_cas(
            &self.home,
            self.kind,
            self.target_raw.as_deref(),
            self.source_raw.as_deref(),
            "rollback",
        )
    }
}

/// Whether consent authority is bound to the provider's canonical endpoint
/// origin instead of a provider-wide marker.
///
/// Public GUI/CLI consumers use this canonical policy query after resolving a
/// stable provider slug with [`kind_from_slug`]; duplicating the match list in
/// presentation crates can make a valid route impossible to approve.
pub fn uses_endpoint_bound_consent(kind: ProviderKind) -> bool {
    matches!(
        kind,
        ProviderKind::LocalOllama
            | ProviderKind::OpenaiApi
            | ProviderKind::OpenaiCompat
            | ProviderKind::AwsBedrock
            | ProviderKind::AzureOpenAi
    )
}

fn default_endpoint(kind: ProviderKind) -> Result<&'static str> {
    match kind {
        ProviderKind::LocalOllama => Ok(crate::providers::ollama_api::DEFAULT_BASE_URL),
        ProviderKind::OpenaiApi => Ok("https://api.openai.com/v1"),
        ProviderKind::AwsBedrock => Ok(crate::providers::aws_bedrock::DEFAULT_ENDPOINT_ORIGIN),
        ProviderKind::OpenaiCompat | ProviderKind::AzureOpenAi => {
            anyhow::bail!(
                "provider `{}` requires an explicit endpoint before consent can be recorded",
                slug(kind)
            )
        }
        _ => anyhow::bail!(
            "provider `{}` does not use endpoint-bound consent",
            slug(kind)
        ),
    }
}

fn canonical_endpoint_origin(kind: ProviderKind, endpoint: Option<&str>) -> Result<String> {
    let raw = match endpoint {
        Some(endpoint) => endpoint,
        None => default_endpoint(kind)?,
    };
    if kind == ProviderKind::AwsBedrock {
        return crate::providers::aws_bedrock::canonical_endpoint_origin(raw);
    }
    // Never echo the raw endpoint: malformed URLs and userinfo may contain
    // credentials. Operator-facing labels use only the validated origin.
    let url = url::Url::parse(raw)
        .with_context(|| format!("parse configured `{}` endpoint", slug(kind)))?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        anyhow::bail!(
            "configured `{}` endpoint must be an absolute http(s) URL before consent can be recorded",
            slug(kind)
        );
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!(
            "configured `{}` endpoint must not embed userinfo; use the credential store instead",
            slug(kind)
        );
    }
    Ok(url.origin().ascii_serialization())
}

const INVALID_BEDROCK_CONSENT_ROUTE: &str = "invalid://aws-bedrock-region";

/// Build the exact consent route for one effective runtime config.
///
/// Bedrock has no operator-configurable endpoint field: its egress identity is
/// derived from the resolved region. Invalid region text is never copied into
/// the route or an error label; a fixed invalid sentinel makes every grant and
/// preflight path fail closed without leaking the raw value.
pub(crate) fn route_for_provider_config(
    kind: ProviderKind,
    endpoint: Option<&str>,
    region: Option<&str>,
) -> ConsentRoute {
    if kind != ProviderKind::AwsBedrock {
        return ConsentRoute::new(kind, endpoint);
    }
    match crate::providers::aws_bedrock::effective_endpoint_origin(region) {
        Ok(origin) => ConsentRoute::new(kind, Some(&origin)),
        Err(_) => ConsentRoute::new(kind, Some(INVALID_BEDROCK_CONSENT_ROUTE)),
    }
}

pub fn route_endpoint_origin(route: &ConsentRoute) -> Result<Option<String>> {
    if uses_endpoint_bound_consent(route.kind)
        && route_requires_consent(route.kind, route.endpoint.as_deref())
    {
        return canonical_endpoint_origin(route.kind, route.endpoint.as_deref()).map(Some);
    }
    Ok(None)
}

fn consent_lock_path(home: &Path) -> PathBuf {
    consent_dir(home).join(".store.lock")
}

fn empty_endpoint_grants() -> EndpointGrantFile {
    EndpointGrantFile {
        version: ENDPOINT_GRANT_VERSION,
        ..EndpointGrantFile::default()
    }
}

fn read_marker_raw(home: &Path, kind: ProviderKind) -> Result<Option<Vec<u8>>> {
    let path = marker_path(home, kind);
    match crate::updater::self_update::read_control_file_bounded_nofollow(
        home,
        &path,
        MAX_CONSENT_MARKER_BYTES as usize,
        "consent marker",
    ) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn parse_endpoint_grants(
    kind: ProviderKind,
    path: &Path,
    raw: Option<&[u8]>,
) -> Result<EndpointGrantFile> {
    if !uses_endpoint_bound_consent(kind) {
        anyhow::bail!(
            "provider `{}` does not use an endpoint-bound consent marker",
            slug(kind)
        );
    }
    let Some(raw) = raw else {
        return Ok(empty_endpoint_grants());
    };
    let text = std::str::from_utf8(raw)
        .with_context(|| format!("decode endpoint-bound consent marker {}", path.display()))?;
    match serde_json::from_str::<EndpointGrantFile>(text) {
        Ok(grants) => {
            if grants.version != ENDPOINT_GRANT_VERSION {
                anyhow::bail!(
                    "unsupported endpoint-bound consent marker version {} in {}",
                    grants.version,
                    path.display()
                );
            }
            for (origin, granted_unix_ts) in &grants.endpoints {
                let canonical =
                    canonical_endpoint_origin(kind, Some(origin)).with_context(|| {
                        format!(
                            "validate endpoint-bound consent origin in {}",
                            path.display()
                        )
                    })?;
                if canonical != *origin {
                    anyhow::bail!(
                        "non-canonical endpoint-bound consent origin in {}",
                        path.display()
                    );
                }
                if granted_unix_ts
                    .parse::<u64>()
                    .ok()
                    .is_none_or(|timestamp| timestamp == 0)
                {
                    anyhow::bail!(
                        "endpoint-bound consent marker {} contains an invalid Unix timestamp",
                        path.display()
                    );
                }
            }
            Ok(grants)
        }
        Err(_)
            if text
                .trim()
                .parse::<u64>()
                .is_ok_and(|timestamp| timestamp > 0) =>
        {
            let mut grants = empty_endpoint_grants();
            // Legacy OpenAI markers represented the fixed official endpoint.
            // Preserve only that safe historical meaning. Legacy arbitrary
            // OpenAI-compatible, Azure, and Ollama markers carry no origin and
            // therefore authorize none until the operator grants the current
            // exact route. Bedrock's legacy provider-wide marker safely maps
            // only to the historical default region; it can never authorize a
            // different regional data plane.
            if matches!(kind, ProviderKind::OpenaiApi | ProviderKind::AwsBedrock) {
                grants.endpoints.insert(
                    canonical_endpoint_origin(kind, None)?,
                    text.trim().to_string(),
                );
            }
            Ok(grants)
        }
        Err(error) => Err(error)
            .with_context(|| format!("parse endpoint-bound consent marker {}", path.display())),
    }
}

fn read_endpoint_grants(home: &Path, kind: ProviderKind) -> Result<EndpointGrantFile> {
    let path = marker_path(home, kind);
    let raw = read_marker_raw(home, kind)?;
    parse_endpoint_grants(kind, &path, raw.as_deref())
}

fn encode_endpoint_grants(kind: ProviderKind, grants: &EndpointGrantFile) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(grants)
        .with_context(|| format!("encode `{}` endpoint-bound consent marker", slug(kind)))
}

fn with_consent_store_lock<T>(home: &Path, mutate: impl FnOnce() -> Result<T>) -> Result<T> {
    let _process_guard = CONSENT_STORE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("consent store mutex poisoned"))?;
    let _file_guard =
        crate::util::locked_file::lock_file_blocking(&consent_lock_path(home), "consent store")?;
    mutate()
}

fn raw_sha256(raw: Option<&[u8]>) -> Option<String> {
    raw.map(|bytes| hex::encode(Sha256::digest(bytes)))
}

/// Return an exact provider-marker binding without parsing or exposing its raw
/// bytes. Recovery code can compare this with an intent/outcome record even
/// when the marker is malformed or from a newer schema version.
pub(crate) fn marker_snapshot_binding(
    home: &Path,
    kind: ProviderKind,
) -> Result<ConsentMarkerBinding> {
    with_consent_store_lock(home, || {
        let raw = read_marker_raw(home, kind)?;
        Ok(ConsentMarkerBinding {
            exists: raw.is_some(),
            sha256: raw_sha256(raw.as_deref()),
        })
    })
}

fn write_marker_raw(home: &Path, kind: ProviderKind, raw: Option<&[u8]>) -> Result<()> {
    let path = marker_path(home, kind);
    match raw {
        Some(bytes) => crate::util::atomic_write::atomic_write_private(&path, bytes)
            .with_context(|| format!("atomically write {}", path.display())),
        None => crate::util::atomic_write::durable_remove_file(&path)
            .with_context(|| format!("durably remove {}", path.display())),
    }
}

fn apply_marker_cas(
    home: &Path,
    kind: ProviderKind,
    expected: Option<&[u8]>,
    replacement: Option<&[u8]>,
    operation: &str,
) -> Result<bool> {
    with_consent_store_lock(home, || {
        let current = read_marker_raw(home, kind)?;
        if current.as_deref() != expected {
            anyhow::bail!(
                "cannot {operation} consent marker `{}`: marker changed after preparation",
                slug(kind)
            );
        }
        if expected == replacement {
            return Ok(false);
        }
        write_marker_raw(home, kind, replacement)?;
        Ok(true)
    })
}

/// LocalOllama is conditionally consent-managed. Its default endpoint is
/// loopback, while any malformed, LAN, DNS, or public endpoint is treated as
/// remote (fail closed). This deliberately shares the provider adapter's
/// typed-host loopback classifier so IPv4/IPv6/domain handling cannot drift.
pub fn route_requires_consent(kind: ProviderKind, endpoint: Option<&str>) -> bool {
    if is_cloud(kind) {
        return true;
    }
    if kind != ProviderKind::LocalOllama {
        return false;
    }
    let endpoint = endpoint.unwrap_or(crate::providers::ollama_api::DEFAULT_BASE_URL);
    let Ok(url) = url::Url::parse(endpoint) else {
        return true;
    };
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return true;
    }
    !crate::providers::http_client::url_has_loopback_host(&url)
}

/// Whether a provider can own a durable consent marker. LocalOllama is
/// included even though its loopback route does not require one: operators
/// targeting a remote Ollama server need `neoth consent grant local_ollama`.
pub fn is_consent_managed_kind(kind: ProviderKind) -> bool {
    is_cloud(kind) || kind == ProviderKind::LocalOllama
}

pub fn is_route_granted(home: &Path, route: &ConsentRoute) -> bool {
    if !route_requires_consent(route.kind, route.endpoint.as_deref()) {
        return true;
    }
    match crate::cli::consent_outbox::blocks_provider_use(home, route.kind) {
        Ok(false) => {}
        Ok(true) | Err(_) => return false,
    }
    if !uses_endpoint_bound_consent(route.kind) {
        return read_marker_raw(home, route.kind)
            .and_then(|raw| inventory_from_raw(home, route.kind, raw.as_deref()))
            .map(|grants| !grants.is_empty())
            .unwrap_or(false);
    }
    let Ok(origin) = canonical_endpoint_origin(route.kind, route.endpoint.as_deref()) else {
        return false;
    };
    read_endpoint_grants(home, route.kind)
        .map(|grants| grants.endpoints.contains_key(&origin))
        .unwrap_or(false)
}

pub(crate) fn route_label(route: &ConsentRoute) -> String {
    if uses_endpoint_bound_consent(route.kind)
        && route_requires_consent(route.kind, route.endpoint.as_deref())
    {
        return match canonical_endpoint_origin(route.kind, route.endpoint.as_deref()) {
            Ok(origin) => format!("{} ({origin})", cloud_label(route.kind)),
            Err(_) => format!(
                "{} (invalid or credential-bearing endpoint)",
                cloud_label(route.kind)
            ),
        };
    }
    cloud_label(route.kind).to_string()
}

pub fn consent_dir(home: &Path) -> PathBuf {
    home.join("consent")
}

pub fn marker_path(home: &Path, kind: ProviderKind) -> PathBuf {
    consent_dir(home).join(format!("{}.granted", slug(kind)))
}

/// True when (a) the kind is not cloud or (b) the operator has granted
/// consent. The "non-cloud is always granted" branch lets callers gate on
/// `is_granted` unconditionally without re-checking `is_cloud`.
pub fn is_granted(home: &Path, kind: ProviderKind) -> bool {
    if !is_cloud(kind) {
        return true;
    }
    is_route_granted(home, &ConsentRoute::new(kind, None))
}

fn inventory_from_raw(
    home: &Path,
    kind: ProviderKind,
    raw: Option<&[u8]>,
) -> Result<Vec<ConsentGrant>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if uses_endpoint_bound_consent(kind) {
        return Ok(
            parse_endpoint_grants(kind, &marker_path(home, kind), Some(raw))?
                .endpoints
                .into_iter()
                .map(|(origin, granted_unix_ts)| ConsentGrant {
                    kind,
                    endpoint_origin: Some(origin),
                    granted_unix_ts,
                })
                .collect(),
        );
    }
    let text = std::str::from_utf8(raw)
        .with_context(|| format!("decode {}", marker_path(home, kind).display()))?;
    let granted_unix_ts = text.trim();
    let timestamp = granted_unix_ts.parse::<u64>().with_context(|| {
        format!(
            "parse positive Unix timestamp in {}",
            marker_path(home, kind).display()
        )
    })?;
    if timestamp == 0 {
        anyhow::bail!(
            "consent marker {} contains a zero Unix timestamp",
            marker_path(home, kind).display()
        );
    }
    Ok(vec![ConsentGrant {
        kind,
        endpoint_origin: None,
        granted_unix_ts: granted_unix_ts.to_string(),
    }])
}

fn marker_update(
    home: &Path,
    kind: ProviderKind,
    source_raw: Option<Vec<u8>>,
    target_raw: Option<Vec<u8>>,
    prior_grants: Vec<ConsentGrant>,
    target_grants: Vec<ConsentGrant>,
    endpoint_delta_known: bool,
    malformed_source: bool,
) -> ConsentMarkerUpdate {
    let prior_origins: BTreeSet<_> = prior_grants
        .iter()
        .filter_map(|grant| grant.endpoint_origin.clone())
        .collect();
    let target_origins: BTreeSet<_> = target_grants
        .iter()
        .filter_map(|grant| grant.endpoint_origin.clone())
        .collect();
    let added_endpoint_origins = target_origins.difference(&prior_origins).cloned().collect();
    let removed_endpoint_origins = prior_origins.difference(&target_origins).cloned().collect();
    ConsentMarkerUpdate {
        home: home.to_path_buf(),
        kind,
        source_sha256: raw_sha256(source_raw.as_deref()),
        target_sha256: raw_sha256(target_raw.as_deref()),
        source_raw,
        target_raw,
        prior_grants,
        target_grants,
        added_endpoint_origins,
        removed_endpoint_origins,
        endpoint_delta_known,
        malformed_source,
    }
}

/// Prepare one provider's grant transition from an exact, locked snapshot.
///
/// Fixed-vendor cloud routes are provider-wide. Operator-configurable
/// OpenAI/OpenAI-compatible/Azure endpoints and remote Ollama are canonicalized
/// to origins and merged into an endpoint set. Existing grants keep their
/// original timestamp and exact marker bytes when the request is idempotent.
pub(crate) fn prepare_grant_routes(
    home: &Path,
    routes: &[ConsentRoute],
) -> Result<ConsentMarkerUpdate> {
    if routes.is_empty() {
        anyhow::bail!("cannot record consent for an empty route set");
    }
    let kind = routes[0].kind;
    if routes.iter().any(|route| route.kind != kind) {
        anyhow::bail!("one consent mutation cannot mix provider kinds");
    }
    let mut endpoint_origins = BTreeSet::new();
    for route in routes {
        if !route_requires_consent(route.kind, route.endpoint.as_deref()) {
            anyhow::bail!(
                "route `{}` does not cross a consent-managed egress boundary",
                slug(route.kind)
            );
        }
        if uses_endpoint_bound_consent(route.kind) {
            endpoint_origins.insert(canonical_endpoint_origin(
                route.kind,
                route.endpoint.as_deref(),
            )?);
        } else if !is_cloud(route.kind) {
            anyhow::bail!(
                "provider `{}` cannot own a durable consent grant",
                slug(route.kind)
            );
        }
    }

    with_consent_store_lock(home, || {
        let source_raw = read_marker_raw(home, kind)?;
        let prior_inventory = inventory_from_raw(home, kind, source_raw.as_deref());
        let prior_grants = prior_inventory.with_context(|| {
            format!(
                "refusing to replace malformed `{}` consent state; revoke it first",
                slug(kind)
            )
        })?;
        let malformed_source = false;

        let target_raw = if uses_endpoint_bound_consent(kind) {
            let mut grants =
                parse_endpoint_grants(kind, &marker_path(home, kind), source_raw.as_deref())?;
            let now = unix_ts_string();
            let mut changed = false;
            for origin in endpoint_origins {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    grants.endpoints.entry(origin)
                {
                    entry.insert(now.clone());
                    changed = true;
                }
            }
            if changed {
                Some(encode_endpoint_grants(kind, &grants)?)
            } else {
                source_raw.clone()
            }
        } else if source_raw.is_some() {
            source_raw.clone()
        } else {
            Some(unix_ts_string().into_bytes())
        };
        let target_grants = inventory_from_raw(home, kind, target_raw.as_deref())?;
        Ok(marker_update(
            home,
            kind,
            source_raw,
            target_raw,
            prior_grants,
            target_grants,
            true,
            malformed_source,
        ))
    })
}

/// Prepare a provider-wide revoke without parsing markers belonging to any
/// other provider. A malformed or newer endpoint-bound marker is deliberately
/// snapshotted as raw bytes and remains revocable.
pub(crate) fn prepare_revoke_kind(home: &Path, kind: ProviderKind) -> Result<ConsentMarkerUpdate> {
    if !is_consent_managed_kind(kind) {
        anyhow::bail!(
            "provider `{}` cannot own a durable consent grant",
            slug(kind)
        );
    }
    with_consent_store_lock(home, || {
        let source_raw = read_marker_raw(home, kind)?;
        let (prior_grants, malformed_source) =
            match inventory_from_raw(home, kind, source_raw.as_deref()) {
                Ok(grants) => (grants, false),
                Err(_) => (Vec::new(), source_raw.is_some()),
            };
        Ok(marker_update(
            home,
            kind,
            source_raw,
            None,
            prior_grants,
            Vec::new(),
            !uses_endpoint_bound_consent(kind) || !malformed_source,
            malformed_source,
        ))
    })
}

/// Record consent for a provider whose default route is unambiguous. Providers
/// requiring an operator endpoint must use [`grant_route`] or [`grant_routes`]
/// so authority is origin-bound.
#[cfg(test)]
pub(crate) fn grant(home: &Path, kind: ProviderKind) -> Result<()> {
    if !is_cloud(kind) {
        anyhow::bail!(
            "consent::grant called with non-cloud kind `{}` — remote Ollama \
             consent requires one concrete endpoint-bound ConsentRoute",
            slug(kind)
        );
    }
    prepare_grant_routes(home, &[ConsentRoute::new(kind, None)])?
        .commit()
        .map(|_| ())
}

/// Atomically add every route to its provider's durable consent state.
/// Fixed-vendor providers retain one provider-wide marker; configurable
/// OpenAI/OpenAI-compatible/Azure and remote Ollama origins share a versioned
/// per-provider marker whose membership is checked on every hot-path dispatch.
#[cfg(test)]
pub(crate) fn grant_routes(home: &Path, routes: &[ConsentRoute]) -> Result<()> {
    prepare_grant_routes(home, routes)?.commit().map(|_| ())
}

#[cfg(test)]
pub(crate) fn grant_route(home: &Path, route: &ConsentRoute) -> Result<()> {
    grant_routes(home, std::slice::from_ref(route))
}

#[cfg(test)]
pub(crate) fn revoke(home: &Path, kind: ProviderKind) -> Result<()> {
    prepare_revoke_kind(home, kind)?.commit().map(|_| ())
}

/// List every endpoint-aware grant. Unknown files in the directory are ignored;
/// a malformed known marker fails closed instead of being reported as granted.
pub fn list_route_grants(home: &Path) -> Result<Vec<ConsentGrant>> {
    let dir = consent_dir(home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(slug_part) = name.strip_suffix(".granted") else {
            continue;
        };
        let Some(kind) = kind_from_slug(slug_part) else {
            continue;
        };
        out.extend(list_route_grants_for_kind(home, kind)?);
    }
    out.sort_by(|a, b| {
        slug(a.kind)
            .cmp(slug(b.kind))
            .then_with(|| a.endpoint_origin.cmp(&b.endpoint_origin))
    });
    Ok(out)
}

/// Provider-scoped grant inventory. This function never opens or parses a
/// marker owned by another provider, so one corrupt marker cannot block an
/// unrelated provider's show/grant/revoke flow.
pub(crate) fn list_route_grants_for_kind(
    home: &Path,
    kind: ProviderKind,
) -> Result<Vec<ConsentGrant>> {
    if !is_consent_managed_kind(kind) {
        return Ok(Vec::new());
    }
    let raw = read_marker_raw(home, kind)?;
    inventory_from_raw(home, kind, raw.as_deref())
}

/// Compatibility inventory used by older callers. Endpoint-bound grants remain
/// separate rows so no origin is silently discarded.
pub fn list_grants(home: &Path) -> Result<Vec<(ProviderKind, String)>> {
    Ok(list_route_grants(home)?
        .into_iter()
        .map(|grant| (grant.kind, grant.granted_unix_ts))
        .collect())
}

pub fn has_grant_for_kind(home: &Path, kind: ProviderKind) -> Result<bool> {
    Ok(!list_route_grants_for_kind(home, kind)?.is_empty())
}

/// P-02 (Session 24) — tri-state consent decision. Replaces the
/// implicit two-state (granted-marker-exists vs not) with an
/// explicit operator choice that the audit chain can record.
///
/// - `AllowOnce`: continue this turn only; no marker written; the
///   next call re-prompts. Useful for one-off cloud bursts the
///   operator doesn't want to make persistent.
/// - `AllowAlways`: continue + write the `.granted` marker so
///   future calls auto-pass. Mirrors the pre-P-02 behaviour.
/// - `Deny`: abort this turn; no marker written. Operator explicitly
///   said no; record the audit anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDecision {
    AllowOnce,
    AllowAlways,
    Deny,
}

impl ConsentDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            ConsentDecision::AllowOnce => "allow_once",
            ConsentDecision::AllowAlways => "allow_always",
            ConsentDecision::Deny => "deny",
        }
    }

    /// True when the decision lets the current turn continue.
    /// `Deny` is the only false branch.
    pub fn allows(self) -> bool {
        !matches!(self, ConsentDecision::Deny)
    }

    /// True when the decision persists to the marker file. Only
    /// `AllowAlways` flips the bit; the other two leave state alone.
    pub fn persists(self) -> bool {
        matches!(self, ConsentDecision::AllowAlways)
    }
}

/// Parse an operator-typed answer into a [`ConsentDecision`].
/// Accepts the canonical strings + a few aliases. Case-insensitive.
/// Returns `None` for unrecognised input — callers prompt again.
pub fn parse_decision(s: &str) -> Option<ConsentDecision> {
    match s.trim().to_lowercase().as_str() {
        "1" | "once" | "allow once" | "allow_once" | "y" | "yes" => {
            Some(ConsentDecision::AllowOnce)
        }
        "2" | "always" | "allow always" | "allow_always" | "a" => {
            Some(ConsentDecision::AllowAlways)
        }
        "3" | "deny" | "no" | "n" | "d" => Some(ConsentDecision::Deny),
        _ => None,
    }
}

/// Build the canonical route-aware `CONSENT_DECISION` payload used by every
/// interactive surface. `endpoint_origin` is null for fixed-vendor grants and
/// a canonical origin for configurable OpenAI/Azure or remote Ollama routes.
pub fn consent_decision_payload(
    route: &ConsentRoute,
    decision: ConsentDecision,
    source: &str,
    ts_unix: i64,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "kind": slug(route.kind),
        "decision": decision.as_str(),
        "source": source,
        "endpoint_origin": route_endpoint_origin(route)?,
        "ts_unix": ts_unix,
    }))
    .context("serialize route-aware consent decision payload")
}

#[cfg(test)]
fn apply_decision(home: &Path, kind: ProviderKind, decision: ConsentDecision) -> Result<bool> {
    if !is_consent_managed_kind(kind) {
        // Non-cloud providers don't gate; apply is a no-op. Keep
        // the API symmetric so callers can pipe every kind through.
        return Ok(false);
    }
    match decision {
        ConsentDecision::AllowAlways => {
            let was_granted = is_granted(home, kind);
            grant(home, kind)?;
            Ok(!was_granted)
        }
        ConsentDecision::AllowOnce | ConsentDecision::Deny => Ok(false),
    }
}

#[cfg(test)]
fn apply_route_decision(
    home: &Path,
    route: &ConsentRoute,
    decision: ConsentDecision,
) -> Result<bool> {
    if !route_requires_consent(route.kind, route.endpoint.as_deref()) {
        return Ok(false);
    }
    match decision {
        ConsentDecision::AllowAlways => {
            let was_granted = is_route_granted(home, route);
            grant_route(home, route)?;
            Ok(!was_granted)
        }
        ConsentDecision::AllowOnce | ConsentDecision::Deny => Ok(false),
    }
}

/// Prompt for a one-turn or persistent route decision without mutating the
/// marker. Callers must audit the returned decision and route persistent grants
/// through the transactional consent service before sending any provider text.
/// `None` means this exact route was already granted.
pub fn prompt_route_decision(home: &Path, route: &ConsentRoute) -> Result<Option<ConsentDecision>> {
    if is_route_granted(home, route) {
        return Ok(None);
    }
    #[cfg(test)]
    if std::env::var("NEOTH_CONSENT_BYPASS").as_deref() == Ok("1") {
        return Ok(Some(ConsentDecision::AllowOnce));
    }
    let slug_s = slug(route.kind);
    let label = route_label(route);
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "first-run consent required for provider `{slug_s}` ({label}). \
             Your chat text will be sent to {label}'s servers. Run \
             `neoth consent grant {slug_s}` once to record consent."
        );
    }
    eprintln!();
    eprintln!("=== First-run outbound-LLM consent ===");
    eprintln!();
    eprintln!("Your chat text is about to be sent to {label}'s servers.");
    eprintln!("This is a third-party cloud service. Their TOS + retention");
    eprintln!("policies apply. NEOTH only routes — it cannot enforce");
    eprintln!("retention/deletion guarantees on the remote side.");
    eprintln!();
    eprintln!("Persistent consent is bound to this exact egress route at:");
    eprintln!("  {}", marker_path(home, route.kind).display());
    eprintln!();
    eprintln!("  1) Allow once");
    eprintln!("  2) Always allow this exact route");
    eprintln!("  3) Deny");
    loop {
        eprint!("Choose 1, 2, or 3: ");
        std::io::stderr().flush().ok();
        let mut input = String::new();
        std::io::stdin().lock().read_line(&mut input)?;
        if let Some(decision) = parse_decision(&input) {
            return Ok(Some(decision));
        }
        eprintln!("Invalid choice. Enter 1, 2, or 3.");
    }
}

#[cfg(test)]
fn ensure_granted_or_prompt(home: &Path, kind: ProviderKind) -> Result<()> {
    ensure_route_granted_or_prompt(home, &ConsentRoute::new(kind, None))
}

#[cfg(test)]
fn ensure_route_granted_or_prompt(home: &Path, route: &ConsentRoute) -> Result<()> {
    match prompt_route_decision(home, route)? {
        None | Some(ConsentDecision::AllowOnce) => Ok(()),
        Some(ConsentDecision::AllowAlways) => {
            apply_route_decision(home, route, ConsentDecision::AllowAlways)?;
            Ok(())
        }
        Some(ConsentDecision::Deny) => {
            anyhow::bail!("consent declined — exiting without sending any text")
        }
    }
}

fn unix_ts_string() -> String {
    crate::time::now_unix_secs().to_string()
}

/// A-2 (Session 13) — enumerate every distinct cloud `ProviderKind` the
/// operator's council topology will fan out to. Session 13 V03-08 originally
/// gated only `config.provider_kind` (legacy single-mode field), which
/// silently bypassed consent when an operator configured per-hemisphere
/// cloud providers via `inference.{left,right,cerebellum}`. This helper +
/// `ensure_all_granted_or_prompt` close that bypass.
///
/// Returns deduped, ordered list of cloud kinds:
/// - `TopologyMode::Single` → at most one kind (default_slot).
/// - `TopologyMode::Triplet|Custom` → one kind per distinct slot.provider
///   that resolves to a cloud kind; local kinds (LocalQwen) are dropped.
///
/// Legacy single-mode operators (only `provider_kind` set, no inference
/// topology) still get covered via the existing `provider_kind` fallback
/// at the call site.
pub fn cloud_kinds_for_council(
    config: &crate::config::FreedomConfig,
) -> Vec<crate::cli::init::ProviderKind> {
    use crate::config::inference::HemisphereRole;
    let mut seen: Vec<crate::cli::init::ProviderKind> = Vec::with_capacity(3);
    for role in [
        HemisphereRole::Left,
        HemisphereRole::Right,
        HemisphereRole::Cerebellum,
    ] {
        let slot = config.inference.slot_for(role);
        let Some(provider) = slot.provider else {
            continue;
        };
        let kind = provider.to_provider_kind();
        if !is_cloud(kind) {
            continue;
        }
        if !seen.contains(&kind) {
            seen.push(kind);
        }
    }
    seen
}

/// Effective route for a hemisphere provider construction. Mirrors
/// `providers::from_config_for_role`: an explicit slot owns its endpoint;
/// an empty slot falls back to the top-level provider and endpoint.
pub fn route_for_role(
    config: &crate::config::FreedomConfig,
    role: crate::config::inference::HemisphereRole,
) -> Option<ConsentRoute> {
    let slot = config.inference.slot_for(role);
    match slot.provider {
        Some(provider) => Some(route_for_provider_config(
            provider.to_provider_kind(),
            slot.endpoint.as_deref(),
            slot.region.as_deref().or(config.provider_region.as_deref()),
        )),
        None => config.provider_kind.map(|kind| {
            route_for_provider_config(
                kind,
                config.provider_endpoint.as_deref(),
                config.provider_region.as_deref(),
            )
        }),
    }
}

fn route_for_explicit_auxiliary(
    config: &crate::config::FreedomConfig,
    kind: ProviderKind,
) -> ConsentRoute {
    // Auxiliary factories preserve the main endpoint only for the same
    // provider kind. A different vendor gets an isolated synthetic config and
    // therefore its adapter default endpoint.
    let endpoint = (config.provider_kind == Some(kind))
        .then_some(config.provider_endpoint.as_deref())
        .flatten();
    route_for_provider_config(kind, endpoint, config.provider_region.as_deref())
}

/// Effective route used by `providers::from_config_for_utility`.
pub fn route_for_utility(config: &crate::config::FreedomConfig) -> Option<ConsentRoute> {
    match config.inference.utility_provider {
        Some(provider) => Some(route_for_explicit_auxiliary(
            config,
            provider.to_provider_kind(),
        )),
        None => config.provider_kind.map(|kind| {
            route_for_provider_config(
                kind,
                config.provider_endpoint.as_deref(),
                config.provider_region.as_deref(),
            )
        }),
    }
}

fn route_for_learn(config: &crate::config::FreedomConfig) -> Option<ConsentRoute> {
    match config.profile.learn_provider.as_deref() {
        Some(raw) => serde_yaml::from_str::<ProviderKind>(raw)
            .ok()
            .map(|kind| route_for_explicit_auxiliary(config, kind)),
        None => config.provider_kind.map(|kind| {
            route_for_provider_config(
                kind,
                config.provider_endpoint.as_deref(),
                config.provider_region.as_deref(),
            )
        }),
    }
}

fn route_for_teacher(config: &crate::config::FreedomConfig) -> Option<ConsentRoute> {
    match config.inference.teacher_provider {
        Some(provider) => Some(route_for_explicit_auxiliary(
            config,
            provider.to_provider_kind(),
        )),
        None => config.provider_kind.map(|kind| {
            route_for_provider_config(
                kind,
                config.provider_endpoint.as_deref(),
                config.provider_region.as_deref(),
            )
        }),
    }
}

/// Canonical consent inventory for every configured provider route that can
/// receive operator-derived text without an additional opt-in at dispatch,
/// including fallback candidates that may become active after a 429. Cloud
/// fixed-vendor routes deduplicate by provider kind. Configurable OpenAI,
/// OpenAI-compatible, Azure, Bedrock-region, and remote Ollama routes
/// deduplicate by canonical origin so one configured host can never hide
/// another.
pub fn required_consent_routes(config: &crate::config::FreedomConfig) -> Vec<ConsentRoute> {
    use crate::config::inference::HemisphereRole;

    let roles = [
        HemisphereRole::Left,
        HemisphereRole::Right,
        HemisphereRole::Cerebellum,
    ];
    let mut candidates = Vec::with_capacity(16 + config.fallback.chain.len());
    if let Some(kind) = config.provider_kind {
        candidates.push(route_for_provider_config(
            kind,
            config.provider_endpoint.as_deref(),
            config.provider_region.as_deref(),
        ));
    }
    for role in roles {
        if let Some(route) = route_for_role(config, role) {
            candidates.push(route);
        }
    }
    // Recursive councils can override every inner role independently for each
    // outer hemisphere. These factories use the explicit sub-slot's endpoint
    // exactly as written, so the consent inventory must mirror those nine
    // potential leaves instead of stopping at the outer triplet. Empty
    // sub-slots fall back through `slot_for_sub` to the already-inventoried
    // outer role and therefore need no duplicate candidate here.
    for sub_slots in config.inference.hemisphere_sub_slots.values() {
        for role in roles {
            let slot = sub_slots.slot_for(role);
            if let Some(provider) = slot.provider {
                candidates.push(route_for_provider_config(
                    provider.to_provider_kind(),
                    slot.endpoint.as_deref(),
                    slot.region.as_deref().or(config.provider_region.as_deref()),
                ));
            }
        }
    }
    candidates.extend(
        [
            route_for_learn(config),
            route_for_utility(config),
            route_for_teacher(config),
        ]
        .into_iter()
        .flatten(),
    );
    if config.fallback.max_hops > 0 {
        candidates.extend(config.fallback.chain.iter().filter_map(|slot| {
            slot.provider.map(|provider| {
                route_for_provider_config(
                    provider.to_provider_kind(),
                    slot.endpoint.as_deref(),
                    slot.region.as_deref().or(config.provider_region.as_deref()),
                )
            })
        }));
    }

    let mut required = Vec::with_capacity(candidates.len());
    for route in candidates {
        if !route_requires_consent(route.kind, route.endpoint.as_deref()) {
            continue;
        }
        let duplicate = required.iter().any(|existing: &ConsentRoute| {
            if existing.kind != route.kind {
                return false;
            }
            if !uses_endpoint_bound_consent(route.kind) {
                return true;
            }
            match (
                canonical_endpoint_origin(existing.kind, existing.endpoint.as_deref()),
                canonical_endpoint_origin(route.kind, route.endpoint.as_deref()),
            ) {
                (Ok(existing), Ok(candidate)) => existing == candidate,
                _ => existing.endpoint == route.endpoint,
            }
        });
        if !duplicate {
            required.push(route);
        }
    }
    required
}

/// A-2 pre-flight wrapper. Calls `ensure_granted_or_prompt` for each
/// distinct cloud kind the council will fan out to. Single-mode operators
/// with only `provider_kind` set (no inference topology) are still gated
/// via the caller's existing `ensure_granted_or_prompt(home, config.provider_kind)`
/// call — this helper covers the per-hemisphere case the legacy gate missed.
#[cfg(test)]
fn ensure_all_granted_or_prompt(home: &Path, config: &crate::config::FreedomConfig) -> Result<()> {
    for route in required_consent_routes(config) {
        ensure_route_granted_or_prompt(home, &route)?;
    }
    Ok(())
}

/// Finding 5 (Session 13) — runtime consent re-check, never prompts.
/// Called per-debate / per-channel-message AFTER the startup
/// `ensure_all_granted_or_prompt` succeeded so a mid-run
/// `neoth consent revoke <provider>` (file-marker deletion) is honoured
/// without daemon restart. Returns `Err` with an operator-facing
/// "consent revoked while daemon running" message that the channel /
/// chat layer surfaces verbatim.
///
/// Unlike `ensure_all_granted_or_prompt` this:
/// 1. Never prompts (no TTY assumption — runs on every hot-path call).
/// 2. Never honours `NEOTH_CONSENT_BYPASS` — bypass is a startup-only
///    escape hatch (CI / scripted bring-up), not a "ignore revokes
///    forever" lever. A revoke MUST stop traffic regardless of the env
///    var, otherwise the consent UX is misleading.
/// 3. Reports the FIRST revoked kind so the operator gets actionable
///    output without us iterating every provider after the first miss.
pub fn ensure_all_still_granted(home: &Path, config: &crate::config::FreedomConfig) -> Result<()> {
    ensure_routes_still_granted(home, &required_consent_routes(config))
}

/// Non-interactive live gate for an immutable provider-route inventory.
/// Long-lived runtimes use this when the provider graph was constructed from
/// an earlier config generation: the authority check must describe the graph
/// that can actually dispatch, not an unrelated on-disk edit.
pub fn ensure_routes_still_granted(home: &Path, routes: &[ConsentRoute]) -> Result<()> {
    routes
        .iter()
        .try_for_each(|route| ensure_route_still_granted(home, route))
}

/// Non-interactive live gate for a concrete route. It never honours
/// `NEOTH_CONSENT_BYPASS`: deleting the marker must stop the next dispatch in
/// a running daemon, including cluster-delegated inference.
pub fn ensure_route_still_granted(home: &Path, route: &ConsentRoute) -> Result<()> {
    if !is_route_granted(home, route) {
        anyhow::bail!(
            "consent for provider `{}` was revoked while the daemon was \
             running. Run `neoth consent grant {}` and resend, or restart \
             `neoth serve` after granting.",
            slug(route.kind),
            slug(route.kind),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn is_cloud_classifies_every_provider_kind() {
        // Cloud-egress providers (all require consent).
        assert!(is_cloud(ProviderKind::ClaudeCli));
        assert!(is_cloud(ProviderKind::OpenaiApi));
        assert!(is_cloud(ProviderKind::AnthropicApi)); // A-25: was missing downstream
        assert!(is_cloud(ProviderKind::GeminiApi));
        assert!(is_cloud(ProviderKind::Cohere)); // A-25: was missing downstream
        assert!(is_cloud(ProviderKind::OpenaiCompat));
        assert!(is_cloud(ProviderKind::AwsBedrock));
        assert!(is_cloud(ProviderKind::AzureOpenAi));
        assert!(is_cloud(ProviderKind::GitHubCopilot)); // GOLD-ADAPT-ODY-15
        assert!(is_cloud(ProviderKind::RecursiveMas));
        // Local + skip never gate.
        assert!(!is_cloud(ProviderKind::LocalQwen));
        assert!(!is_cloud(ProviderKind::LocalOuro));
        assert!(!is_cloud(ProviderKind::Skip));
    }

    #[test]
    fn slug_round_trips_via_kind_from_slug() {
        for &kind in &[
            ProviderKind::ClaudeCli,
            ProviderKind::OpenaiApi,
            ProviderKind::GeminiApi,
            ProviderKind::OpenaiCompat,
            ProviderKind::LocalQwen,
            ProviderKind::AwsBedrock,
            ProviderKind::AzureOpenAi,
            ProviderKind::GitHubCopilot, // GOLD-ADAPT-ODY-15
            ProviderKind::RecursiveMas,
            ProviderKind::Skip,
        ] {
            assert_eq!(kind_from_slug(slug(kind)), Some(kind), "{kind:?}");
        }
    }

    #[test]
    fn recursive_mas_sidecar_is_provider_wide_consent_managed() {
        let tmp = TempDir::new().unwrap();
        let config = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::RecursiveMas),
            ..Default::default()
        };
        let routes = required_consent_routes(&config);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].kind, ProviderKind::RecursiveMas);
        assert!(routes[0].endpoint.is_none());
        assert!(route_requires_consent(ProviderKind::RecursiveMas, None));
        assert!(!is_route_granted(tmp.path(), &routes[0]));

        grant(tmp.path(), ProviderKind::RecursiveMas).unwrap();
        assert!(is_route_granted(tmp.path(), &routes[0]));
        revoke(tmp.path(), ProviderKind::RecursiveMas).unwrap();
        assert!(!is_route_granted(tmp.path(), &routes[0]));
    }

    #[test]
    fn kind_from_slug_returns_none_for_unknown() {
        assert!(kind_from_slug("nope").is_none());
        assert!(kind_from_slug("").is_none());
        assert!(kind_from_slug("OPENAI_API").is_none()); // case-sensitive
    }

    #[test]
    fn is_granted_returns_true_for_non_cloud_kinds_without_marker() {
        let tmp = TempDir::new().unwrap();
        assert!(is_granted(tmp.path(), ProviderKind::LocalQwen));
        assert!(is_granted(tmp.path(), ProviderKind::Skip));
    }

    #[test]
    fn is_granted_returns_false_for_cloud_kind_without_marker() {
        let tmp = TempDir::new().unwrap();
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
        assert!(!is_granted(tmp.path(), ProviderKind::ClaudeCli));
    }

    #[test]
    fn grant_creates_marker_and_is_granted_flips_true() {
        let tmp = TempDir::new().unwrap();
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(is_granted(tmp.path(), ProviderKind::OpenaiApi));
        assert!(marker_path(tmp.path(), ProviderKind::OpenaiApi).exists());
        // grant for one kind does not leak to another
        assert!(!is_granted(tmp.path(), ProviderKind::GeminiApi));
    }

    #[test]
    fn grant_rejects_non_cloud_kinds() {
        let tmp = TempDir::new().unwrap();
        let err = grant(tmp.path(), ProviderKind::LocalQwen).unwrap_err();
        assert!(err.to_string().contains("non-cloud"));
        let err = grant(tmp.path(), ProviderKind::LocalOllama).unwrap_err();
        assert!(err.to_string().contains("endpoint-bound"));
    }

    #[test]
    fn revoke_removes_marker_and_is_granted_flips_false() {
        let tmp = TempDir::new().unwrap();
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(is_granted(tmp.path(), ProviderKind::OpenaiApi));
        revoke(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
    }

    #[test]
    fn revoke_is_idempotent_when_marker_absent() {
        let tmp = TempDir::new().unwrap();
        let update = prepare_revoke_kind(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(!update.changed());
        assert!(!update.source_exists());
        assert!(!update.target_exists());
        assert!(!update.commit().unwrap());
        assert!(!update.rollback().unwrap());
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
    }

    #[test]
    fn list_grants_returns_empty_when_consent_dir_missing() {
        let tmp = TempDir::new().unwrap();
        let listed = list_grants(tmp.path()).unwrap();
        assert!(listed.is_empty());
    }

    #[test]
    fn list_grants_returns_every_granted_kind_sorted_by_slug() {
        let tmp = TempDir::new().unwrap();
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        grant(tmp.path(), ProviderKind::ClaudeCli).unwrap();
        grant(tmp.path(), ProviderKind::GeminiApi).unwrap();
        let listed: Vec<ProviderKind> = list_grants(tmp.path())
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            listed,
            vec![
                ProviderKind::ClaudeCli,
                ProviderKind::GeminiApi,
                ProviderKind::OpenaiApi,
            ]
        );
    }

    #[test]
    fn list_grants_ignores_unknown_files_in_consent_dir() {
        let tmp = TempDir::new().unwrap();
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        // Drop a stray file in the consent dir.
        std::fs::write(consent_dir(tmp.path()).join("README.txt"), "ignore me").unwrap();
        std::fs::write(consent_dir(tmp.path()).join("bogus.granted"), "0").unwrap();
        let listed = list_grants(tmp.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, ProviderKind::OpenaiApi);
    }

    #[test]
    fn ensure_granted_or_prompt_short_circuits_when_already_granted() {
        let tmp = TempDir::new().unwrap();
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        // Must return Ok without touching stdin/stdout.
        ensure_granted_or_prompt(tmp.path(), ProviderKind::OpenaiApi).unwrap();
    }

    #[test]
    fn ensure_granted_or_prompt_short_circuits_for_non_cloud_kinds() {
        let tmp = TempDir::new().unwrap();
        ensure_granted_or_prompt(tmp.path(), ProviderKind::LocalQwen).unwrap();
        ensure_granted_or_prompt(tmp.path(), ProviderKind::Skip).unwrap();
        // No marker should have been created (these aren't cloud).
        assert!(!consent_dir(tmp.path()).exists());
    }

    #[test]
    fn ensure_granted_or_prompt_honours_bypass_env() {
        let _env = crate::test_env::lock();
        let tmp = TempDir::new().unwrap();
        // SAFETY: tests run single-threaded for env mutation via cargo's
        // default --test-threads, but mark it explicitly with serial_test
        // if this ever flakes. For now: the bypass var is unique enough
        // that no other test reads it concurrently.
        // SAFETY: tests are isolated to their own process and we restore
        // the var on the next line.
        // SAFETY: set + remove the env var inside one test; concurrent
        // tests don't reference NEOTH_CONSENT_BYPASS.
        unsafe {
            std::env::set_var("NEOTH_CONSENT_BYPASS", "1");
        }
        let result = ensure_granted_or_prompt(tmp.path(), ProviderKind::OpenaiApi);
        unsafe {
            std::env::remove_var("NEOTH_CONSENT_BYPASS");
        }
        assert!(result.is_ok());
        // Bypass does NOT record a marker — caller is responsible for
        // running `neoth consent grant` later if they want a marker.
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
    }

    // ── A-2 (Session 13) multi-provider council preflight ────────────

    fn mk_config_with_inference(
        primary: Option<crate::cli::init::ProviderKind>,
        left: Option<crate::config::inference::InferenceProvider>,
        right: Option<crate::config::inference::InferenceProvider>,
        cere: Option<crate::config::inference::InferenceProvider>,
        mode: crate::config::inference::TopologyMode,
    ) -> crate::config::FreedomConfig {
        use crate::config::FreedomConfig;
        use crate::config::inference::{HemisphereSlot, InferenceTopology};
        let mut cfg = FreedomConfig::default();
        cfg.provider_kind = primary;
        let mut topo = InferenceTopology::default();
        topo.mode = mode;
        topo.left = HemisphereSlot {
            provider: left,
            ..HemisphereSlot::default()
        };
        topo.right = HemisphereSlot {
            provider: right,
            ..HemisphereSlot::default()
        };
        topo.cerebellum = HemisphereSlot {
            provider: cere,
            ..HemisphereSlot::default()
        };
        cfg.inference = topo;
        cfg
    }

    #[test]
    fn cloud_kinds_for_council_returns_empty_in_single_mode_without_default_slot() {
        let cfg = mk_config_with_inference(
            None,
            None,
            None,
            None,
            crate::config::inference::TopologyMode::Single,
        );
        // Single-mode without a default_slot.provider returns empty —
        // legacy `provider_kind` covers that case at the caller.
        let kinds = cloud_kinds_for_council(&cfg);
        assert!(kinds.is_empty());
    }

    #[test]
    fn cloud_kinds_for_council_dedups_in_single_mode_with_default_slot() {
        use crate::config::FreedomConfig;
        use crate::config::inference::{
            HemisphereSlot, InferenceProvider, InferenceTopology, TopologyMode,
        };
        let mut cfg = FreedomConfig::default();
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Single;
        topo.default_slot = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            ..HemisphereSlot::default()
        };
        cfg.inference = topo;
        // All three slots collapse to default_slot → one kind dedup'd.
        let kinds = cloud_kinds_for_council(&cfg);
        assert_eq!(kinds, vec![crate::cli::init::ProviderKind::OpenaiApi]);
    }

    #[test]
    fn cloud_kinds_for_council_returns_three_distinct_in_custom_mode() {
        let cfg = mk_config_with_inference(
            None,
            Some(crate::config::inference::InferenceProvider::ClaudeCli),
            Some(crate::config::inference::InferenceProvider::OpenAi),
            Some(crate::config::inference::InferenceProvider::Gemini),
            crate::config::inference::TopologyMode::Custom,
        );
        let kinds = cloud_kinds_for_council(&cfg);
        assert_eq!(kinds.len(), 3);
        assert!(kinds.contains(&crate::cli::init::ProviderKind::ClaudeCli));
        assert!(kinds.contains(&crate::cli::init::ProviderKind::OpenaiApi));
        assert!(kinds.contains(&crate::cli::init::ProviderKind::GeminiApi));
    }

    #[test]
    fn cloud_kinds_for_council_skips_local_qwen() {
        let cfg = mk_config_with_inference(
            None,
            Some(crate::config::inference::InferenceProvider::ClaudeCli),
            Some(crate::config::inference::InferenceProvider::LocalQwen),
            Some(crate::config::inference::InferenceProvider::Gemini),
            crate::config::inference::TopologyMode::Custom,
        );
        let kinds = cloud_kinds_for_council(&cfg);
        // Local_qwen drops; only the two clouds remain.
        assert_eq!(kinds.len(), 2);
        assert!(kinds.contains(&crate::cli::init::ProviderKind::ClaudeCli));
        assert!(kinds.contains(&crate::cli::init::ProviderKind::GeminiApi));
        assert!(!kinds.contains(&crate::cli::init::ProviderKind::LocalQwen));
    }

    #[test]
    fn ollama_consent_is_endpoint_aware_and_fail_closed() {
        for endpoint in [
            None,
            Some("http://localhost:11434"),
            Some("http://LOCALHOST.:11434"),
            Some("http://127.0.0.42:11434"),
            Some("http://[::1]:11434"),
        ] {
            assert!(
                !route_requires_consent(ProviderKind::LocalOllama, endpoint),
                "loopback endpoint must remain zero-friction: {endpoint:?}"
            );
        }
        for endpoint in [
            Some("http://192.168.1.20:11434"),
            Some("https://ollama.example.com"),
            Some("http://localhost.evil.example:11434"),
            Some("ftp://localhost:11434"),
            Some("http://operator@localhost:11434"),
            Some("https://operator:secret@127.0.0.1:11434"),
            Some("not a URL"),
        ] {
            assert!(
                route_requires_consent(ProviderKind::LocalOllama, endpoint),
                "non-loopback or malformed endpoint must fail closed: {endpoint:?}"
            );
        }
    }

    #[test]
    fn remote_ollama_route_requires_revocable_marker() {
        let tmp = TempDir::new().unwrap();
        let route = ConsentRoute::new(ProviderKind::LocalOllama, Some("http://192.168.1.20:11434"));
        assert!(!is_route_granted(tmp.path(), &route));
        assert!(ensure_route_still_granted(tmp.path(), &route).is_err());
        grant_route(tmp.path(), &route).unwrap();
        assert!(is_route_granted(tmp.path(), &route));
        ensure_route_still_granted(tmp.path(), &route).unwrap();
        revoke(tmp.path(), ProviderKind::LocalOllama).unwrap();
        assert!(!is_route_granted(tmp.path(), &route));
    }

    #[test]
    fn remote_ollama_grant_is_bound_to_canonical_origin() {
        let tmp = TempDir::new().unwrap();
        let host_a = ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("http://OLLAMA-A.example:11434/api/generate"),
        );
        let host_a_other_path = ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("http://ollama-a.example:11434/v1/chat"),
        );
        let host_b = ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("http://ollama-b.example:11434"),
        );

        grant_route(tmp.path(), &host_a).unwrap();

        assert!(is_route_granted(tmp.path(), &host_a));
        assert!(
            is_route_granted(tmp.path(), &host_a_other_path),
            "same canonical origin must share one explicit grant"
        );
        assert!(
            !is_route_granted(tmp.path(), &host_b),
            "granting host A must never authorize host B"
        );
        assert!(ensure_route_still_granted(tmp.path(), &host_b).is_err());
    }

    #[test]
    fn configurable_cloud_grants_are_bound_to_canonical_origin() {
        let tmp = TempDir::new().unwrap();
        for kind in [
            ProviderKind::OpenaiApi,
            ProviderKind::OpenaiCompat,
            ProviderKind::AzureOpenAi,
        ] {
            let route_a = ConsentRoute::new(kind, Some("https://API-A.example/v1/chat"));
            let route_a_other_path = ConsentRoute::new(kind, Some("https://api-a.example/other"));
            let route_b = ConsentRoute::new(kind, Some("https://api-b.example/v1"));

            grant_route(tmp.path(), &route_a).unwrap();

            assert!(is_route_granted(tmp.path(), &route_a));
            assert!(is_route_granted(tmp.path(), &route_a_other_path));
            assert!(
                !is_route_granted(tmp.path(), &route_b),
                "granting endpoint A must not authorize endpoint B for {}",
                slug(kind)
            );
            revoke(tmp.path(), kind).unwrap();
        }
    }

    #[test]
    fn bedrock_grants_are_isolated_by_effective_region() {
        let tmp = TempDir::new().unwrap();
        let us_east = route_for_provider_config(ProviderKind::AwsBedrock, None, Some("us-east-1"));
        let eu_central =
            route_for_provider_config(ProviderKind::AwsBedrock, None, Some("eu-central-1"));

        grant_route(tmp.path(), &us_east).unwrap();

        assert!(is_route_granted(tmp.path(), &us_east));
        assert!(!is_route_granted(tmp.path(), &eu_central));
        assert_eq!(
            route_endpoint_origin(&us_east).unwrap().as_deref(),
            Some("https://bedrock-runtime.us-east-1.amazonaws.com")
        );
        assert_eq!(
            route_endpoint_origin(&eu_central).unwrap().as_deref(),
            Some("https://bedrock-runtime.eu-central-1.amazonaws.com")
        );
    }

    #[test]
    fn legacy_bedrock_marker_authorizes_only_default_region() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        std::fs::write(
            marker_path(tmp.path(), ProviderKind::AwsBedrock),
            b"1717171717",
        )
        .unwrap();
        let default = route_for_provider_config(ProviderKind::AwsBedrock, None, Some("us-east-1"));
        let other = route_for_provider_config(ProviderKind::AwsBedrock, None, Some("eu-central-1"));

        assert!(is_route_granted(tmp.path(), &default));
        assert!(!is_route_granted(tmp.path(), &other));
        assert_eq!(
            list_route_grants_for_kind(tmp.path(), ProviderKind::AwsBedrock)
                .unwrap()
                .into_iter()
                .map(|grant| grant.endpoint_origin)
                .collect::<Vec<_>>(),
            vec![Some(
                "https://bedrock-runtime.us-east-1.amazonaws.com".to_string()
            )]
        );
    }

    #[test]
    fn invalid_bedrock_region_fails_closed_without_echoing_raw_value() {
        let route = route_for_provider_config(
            ProviderKind::AwsBedrock,
            None,
            Some("bad/region?token=super-secret"),
        );
        let error = route_endpoint_origin(&route).unwrap_err();
        assert!(!format!("{error:#}").contains("super-secret"));
        assert!(!route_label(&route).contains("super-secret"));
    }

    #[test]
    fn legacy_unbound_custom_cloud_markers_authorize_no_arbitrary_origin() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        for kind in [ProviderKind::OpenaiCompat, ProviderKind::AzureOpenAi] {
            std::fs::write(marker_path(tmp.path(), kind), b"1717171717").unwrap();
            let route = ConsentRoute::new(kind, Some("https://operator-gateway.example/v1"));

            assert!(!is_route_granted(tmp.path(), &route));
            assert!(
                list_route_grants_for_kind(tmp.path(), kind)
                    .unwrap()
                    .is_empty()
            );

            grant_route(tmp.path(), &route).unwrap();
            assert!(is_route_granted(tmp.path(), &route));
            revoke(tmp.path(), kind).unwrap();
        }
    }

    #[test]
    fn endpoint_errors_and_labels_never_echo_embedded_credentials() {
        let route = ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("https://operator:super-secret@ollama.example:11434/api"),
        );
        let error = route_endpoint_origin(&route).unwrap_err();
        assert!(!format!("{error:#}").contains("super-secret"));
        let label = route_label(&route);
        assert!(!label.contains("operator"));
        assert!(!label.contains("super-secret"));
    }

    #[test]
    fn endpoint_bound_markers_require_positive_numeric_timestamps() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        for timestamp in ["garbage", "0"] {
            let marker = marker_path(tmp.path(), ProviderKind::OpenaiCompat);
            std::fs::write(
                &marker,
                format!(
                    "{{\"version\":1,\"endpoints\":{{\"https://api.example\":\"{timestamp}\"}}}}"
                ),
            )
            .unwrap();
            let route =
                ConsentRoute::new(ProviderKind::OpenaiCompat, Some("https://api.example/v1"));
            assert!(!is_route_granted(tmp.path(), &route));
            assert!(list_route_grants_for_kind(tmp.path(), ProviderKind::OpenaiCompat).is_err());
        }
    }

    #[test]
    fn prepared_cloud_grant_is_idempotent_and_preserves_exact_marker_bytes() {
        let tmp = TempDir::new().unwrap();
        let marker = marker_path(tmp.path(), ProviderKind::OpenaiApi);
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        let original = b" 1717171717 \n";
        std::fs::write(&marker, original).unwrap();

        let update = prepare_grant_routes(
            tmp.path(),
            &[ConsentRoute::new(ProviderKind::OpenaiApi, None)],
        )
        .unwrap();

        assert!(!update.changed());
        assert!(update.source_exists());
        assert!(update.target_exists());
        assert_eq!(update.source_sha256(), update.target_sha256());
        assert!(!update.commit().unwrap());
        assert!(!update.rollback().unwrap());
        assert_eq!(std::fs::read(marker).unwrap(), original);
    }

    #[test]
    fn malformed_cloud_marker_never_authorizes_and_requires_raw_bound_revoke() {
        let tmp = TempDir::new().unwrap();
        let marker = marker_path(tmp.path(), ProviderKind::OpenaiApi);
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        let malformed = b"\xffnot-a-timestamp";
        std::fs::write(&marker, malformed).unwrap();
        let route = ConsentRoute::new(ProviderKind::OpenaiApi, None);

        assert!(!is_route_granted(tmp.path(), &route));
        assert!(!is_granted(tmp.path(), ProviderKind::OpenaiApi));
        assert!(list_route_grants_for_kind(tmp.path(), ProviderKind::OpenaiApi).is_err());
        let grant_error = prepare_grant_routes(tmp.path(), &[route]).unwrap_err();
        assert!(format!("{grant_error:#}").contains("revoke it first"));

        let revoke = prepare_revoke_kind(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(revoke.changed());
        assert!(revoke.malformed_source());
        assert!(revoke.source_exists());
        assert!(!revoke.target_exists());
        assert!(revoke.commit().unwrap());
        assert!(!marker.exists());
        assert!(revoke.rollback().unwrap());
        assert_eq!(std::fs::read(marker).unwrap(), malformed);
    }

    #[test]
    fn prepared_local_grant_commits_and_rolls_back_exact_source_bytes() {
        let tmp = TempDir::new().unwrap();
        let marker = marker_path(tmp.path(), ProviderKind::LocalOllama);
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        let original = br#"{
  "version": 1,
  "endpoints": {
    "http://ollama-a.example:11434": "1717171717"
  }
}"#;
        std::fs::write(&marker, original).unwrap();
        let route = ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("http://ollama-b.example:11434/api/generate"),
        );

        let update = prepare_grant_routes(tmp.path(), &[route]).unwrap();

        assert!(update.changed());
        assert!(!update.malformed_source());
        assert!(update.endpoint_delta_known());
        assert_eq!(
            update.added_endpoint_origins(),
            &["http://ollama-b.example:11434".to_string()]
        );
        assert!(update.removed_endpoint_origins().is_empty());
        assert_eq!(update.prior_grants().len(), 1);
        assert_eq!(update.target_grants().len(), 2);
        assert!(update.commit().unwrap());
        assert_ne!(std::fs::read(&marker).unwrap(), original);
        assert!(update.rollback().unwrap());
        assert_eq!(std::fs::read(marker).unwrap(), original);
    }

    #[test]
    fn prepared_update_cas_does_not_overwrite_competing_marker_change() {
        let tmp = TempDir::new().unwrap();
        let update = prepare_grant_routes(
            tmp.path(),
            &[ConsentRoute::new(ProviderKind::OpenaiApi, None)],
        )
        .unwrap();
        let marker = marker_path(tmp.path(), ProviderKind::OpenaiApi);
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        std::fs::write(&marker, b"competing-process").unwrap();

        let error = update.commit().unwrap_err();

        assert!(error.to_string().contains("changed after preparation"));
        assert_eq!(std::fs::read(marker).unwrap(), b"competing-process");
    }

    #[test]
    fn malformed_local_marker_does_not_poison_other_provider_inventory_or_revoke() {
        let tmp = TempDir::new().unwrap();
        grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        std::fs::write(
            marker_path(tmp.path(), ProviderKind::LocalOllama),
            br#"{"version":999,"endpoints":{}}"#,
        )
        .unwrap();

        let openai = list_route_grants_for_kind(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert_eq!(openai.len(), 1);
        assert!(list_route_grants_for_kind(tmp.path(), ProviderKind::LocalOllama).is_err());

        revoke(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(!marker_path(tmp.path(), ProviderKind::OpenaiApi).exists());
        assert!(marker_path(tmp.path(), ProviderKind::LocalOllama).exists());
    }

    #[test]
    fn malformed_local_marker_revoke_is_raw_bound_and_exactly_rollbackable() {
        let tmp = TempDir::new().unwrap();
        let marker = marker_path(tmp.path(), ProviderKind::LocalOllama);
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        let malformed = br#"{"version":999,"endpoints":{"not":"trusted"},"future":true}"#;
        std::fs::write(&marker, malformed).unwrap();
        let source_binding =
            marker_snapshot_binding(tmp.path(), ProviderKind::LocalOllama).unwrap();
        assert!(source_binding.exists());
        assert_eq!(
            source_binding.sha256(),
            raw_sha256(Some(malformed)).as_deref()
        );

        let update = prepare_revoke_kind(tmp.path(), ProviderKind::LocalOllama).unwrap();

        assert!(update.changed());
        assert_eq!(update.kind(), ProviderKind::LocalOllama);
        assert!(update.source_exists());
        assert!(!update.target_exists());
        assert!(update.source_sha256().is_some());
        assert!(update.target_sha256().is_none());
        assert!(update.malformed_source());
        assert!(!update.endpoint_delta_known());
        assert!(update.prior_grants().is_empty());
        assert!(update.removed_endpoint_origins().is_empty());
        assert!(update.commit().unwrap());
        assert!(!marker.exists());
        let removed_binding =
            marker_snapshot_binding(tmp.path(), ProviderKind::LocalOllama).unwrap();
        assert!(!removed_binding.exists());
        assert!(removed_binding.sha256().is_none());
        assert!(update.rollback().unwrap());
        assert_eq!(std::fs::read(marker).unwrap(), malformed);
    }

    #[test]
    fn legacy_unbound_ollama_marker_authorizes_no_remote_origin() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        std::fs::write(
            marker_path(tmp.path(), ProviderKind::LocalOllama),
            "1717171717",
        )
        .unwrap();
        let route = ConsentRoute::new(ProviderKind::LocalOllama, Some("http://192.168.1.20:11434"));

        assert!(!is_route_granted(tmp.path(), &route));
        assert!(list_route_grants(tmp.path()).unwrap().is_empty());

        grant_route(tmp.path(), &route).unwrap();
        assert!(is_route_granted(tmp.path(), &route));
        assert_eq!(list_route_grants(tmp.path()).unwrap().len(), 1);
    }

    #[test]
    fn embedded_ollama_userinfo_cannot_be_persistently_granted() {
        let tmp = TempDir::new().unwrap();
        let route = ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("https://operator:secret@ollama.example"),
        );

        assert!(route_requires_consent(
            route.kind,
            route.endpoint.as_deref()
        ));
        assert!(grant_route(tmp.path(), &route).is_err());
        assert!(!is_route_granted(tmp.path(), &route));
    }

    #[test]
    fn required_routes_keep_distinct_remote_ollama_origins() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider, TopologyMode};

        let mut cfg = crate::config::FreedomConfig::default();
        cfg.inference.mode = TopologyMode::Triplet;
        cfg.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::LocalOllama),
            endpoint: Some("http://ollama-a.example:11434".into()),
            ..HemisphereSlot::default()
        };
        cfg.inference.right = HemisphereSlot {
            provider: Some(InferenceProvider::LocalOllama),
            endpoint: Some("http://ollama-b.example:11434".into()),
            ..HemisphereSlot::default()
        };
        cfg.inference.cerebellum = HemisphereSlot {
            provider: Some(InferenceProvider::LocalOllama),
            endpoint: Some("http://OLLAMA-A.example:11434/other".into()),
            ..HemisphereSlot::default()
        };

        let routes: Vec<_> = required_consent_routes(&cfg)
            .into_iter()
            .filter(|route| route.kind == ProviderKind::LocalOllama)
            .collect();
        assert_eq!(routes.len(), 2);
        assert_eq!(
            route_endpoint_origin(&routes[0]).unwrap().as_deref(),
            Some("http://ollama-a.example:11434")
        );
        assert_eq!(
            route_endpoint_origin(&routes[1]).unwrap().as_deref(),
            Some("http://ollama-b.example:11434")
        );
    }

    #[test]
    fn required_routes_include_learn_utility_and_teacher_providers() {
        use crate::config::inference::InferenceProvider;
        let mut cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalQwen),
            ..Default::default()
        };
        cfg.profile.learn_provider = Some("openai_api".into());
        cfg.inference.utility_provider = Some(InferenceProvider::Gemini);
        cfg.inference.teacher_provider = Some(InferenceProvider::AnthropicApi);

        let routes = required_consent_routes(&cfg);
        let kinds: Vec<_> = routes.iter().map(|route| route.kind).collect();
        assert_eq!(
            kinds,
            vec![
                ProviderKind::OpenaiApi,
                ProviderKind::GeminiApi,
                ProviderKind::AnthropicApi,
            ]
        );
    }

    #[test]
    fn required_routes_include_every_explicit_recursive_sub_slot() {
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, SubHemisphereSlots,
        };

        let mut cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalQwen),
            ..Default::default()
        };
        cfg.inference.hemisphere_sub_slots.insert(
            HemisphereRole::Left,
            SubHemisphereSlots {
                left: HemisphereSlot {
                    provider: Some(InferenceProvider::OpenAi),
                    ..Default::default()
                },
                right: HemisphereSlot {
                    provider: Some(InferenceProvider::LocalOllama),
                    endpoint: Some("http://10.0.0.44:11434".into()),
                    ..Default::default()
                },
                cerebellum: HemisphereSlot {
                    provider: Some(InferenceProvider::Gemini),
                    ..Default::default()
                },
            },
        );
        cfg.inference.hemisphere_sub_slots.insert(
            HemisphereRole::Right,
            SubHemisphereSlots {
                left: HemisphereSlot {
                    provider: Some(InferenceProvider::AnthropicApi),
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        let routes = required_consent_routes(&cfg);
        assert_eq!(routes.len(), 4);
        assert!(
            routes
                .iter()
                .any(|route| route.kind == ProviderKind::OpenaiApi)
        );
        assert!(
            routes
                .iter()
                .any(|route| route.kind == ProviderKind::GeminiApi)
        );
        assert!(
            routes
                .iter()
                .any(|route| route.kind == ProviderKind::AnthropicApi)
        );
        assert!(routes.iter().any(|route| {
            route.kind == ProviderKind::LocalOllama
                && route.endpoint.as_deref() == Some("http://10.0.0.44:11434")
        }));
    }

    #[test]
    fn required_routes_bind_bedrock_for_every_runtime_factory() {
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, SubHemisphereSlots, TopologyMode,
        };

        let mut cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::AwsBedrock),
            provider_region: Some("eu-central-1".into()),
            ..Default::default()
        };
        cfg.inference.mode = TopologyMode::Custom;
        cfg.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            region: Some("ap-south-1".into()),
            ..Default::default()
        };
        cfg.inference.hemisphere_sub_slots.insert(
            HemisphereRole::Left,
            SubHemisphereSlots {
                right: HemisphereSlot {
                    provider: Some(InferenceProvider::AwsBedrock),
                    region: Some("us-west-2".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        cfg.profile.learn_provider = Some("aws_bedrock".into());
        cfg.inference.utility_provider = Some(InferenceProvider::AwsBedrock);
        cfg.inference.teacher_provider = Some(InferenceProvider::AwsBedrock);
        cfg.fallback.chain.push(HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            region: Some("sa-east-1".into()),
            ..Default::default()
        });

        let origins = required_consent_routes(&cfg)
            .into_iter()
            .filter(|route| route.kind == ProviderKind::AwsBedrock)
            .map(|route| route_endpoint_origin(&route).unwrap().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            origins,
            [
                "https://bedrock-runtime.ap-south-1.amazonaws.com".to_string(),
                "https://bedrock-runtime.eu-central-1.amazonaws.com".to_string(),
                "https://bedrock-runtime.sa-east-1.amazonaws.com".to_string(),
                "https://bedrock-runtime.us-west-2.amazonaws.com".to_string(),
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn zero_hop_fallback_is_not_in_required_consent_inventory() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};

        let mut cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalQwen),
            ..Default::default()
        };
        cfg.fallback.max_hops = 0;
        cfg.fallback.chain.push(HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            region: Some("eu-central-1".into()),
            ..Default::default()
        });

        assert!(
            required_consent_routes(&cfg)
                .into_iter()
                .all(|route| route.kind != ProviderKind::AwsBedrock)
        );
    }

    #[test]
    fn ephemeral_consent_view_is_exact_and_non_consuming() {
        let route_a = route_for_provider_config(ProviderKind::AwsBedrock, None, Some("us-east-1"));
        let route_b =
            route_for_provider_config(ProviderKind::AwsBedrock, None, Some("eu-central-1"));
        let mut ephemeral = EphemeralConsent::default();
        ephemeral.allow_route(&route_a).unwrap();

        assert!(ephemeral.permits_route(&route_a).unwrap());
        assert!(ephemeral.permits_route(&route_a).unwrap());
        assert!(!ephemeral.permits_route(&route_b).unwrap());
        assert!(ephemeral.consume_route(&route_a).unwrap());
        assert!(!ephemeral.permits_route(&route_a).unwrap());
        assert!(!ephemeral.consume_route(&route_a).unwrap());
    }

    #[test]
    fn recursive_sub_slot_revocation_blocks_the_live_inventory() {
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, SubHemisphereSlots,
        };

        let home = TempDir::new().unwrap();
        let mut cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalQwen),
            ..Default::default()
        };
        cfg.inference.hemisphere_sub_slots.insert(
            HemisphereRole::Cerebellum,
            SubHemisphereSlots {
                right: HemisphereSlot {
                    provider: Some(InferenceProvider::OpenAi),
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        let error = ensure_all_still_granted(home.path(), &cfg)
            .expect_err("an ungranted recursive leaf must block before council dispatch");
        assert!(error.to_string().contains("openai_api"));
    }

    #[test]
    fn local_ollama_occurrence_cannot_hide_remote_hemisphere_route() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider, TopologyMode};
        let mut cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://localhost:11434".into()),
            ..Default::default()
        };
        cfg.profile.learn_provider = None;
        cfg.inference.mode = TopologyMode::Custom;
        cfg.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::LocalOllama),
            endpoint: Some("http://localhost:11434".into()),
            ..Default::default()
        };
        cfg.inference.right = HemisphereSlot {
            provider: Some(InferenceProvider::LocalOllama),
            endpoint: Some("http://10.0.0.8:11434".into()),
            ..Default::default()
        };

        let routes = required_consent_routes(&cfg);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].kind, ProviderKind::LocalOllama);
        assert_eq!(routes[0].endpoint.as_deref(), Some("http://10.0.0.8:11434"));
    }

    #[test]
    fn single_mode_role_route_falls_back_to_top_level_endpoint() {
        let cfg = crate::config::FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some("http://10.0.0.9:11434".into()),
            ..Default::default()
        };
        let route = route_for_role(&cfg, crate::config::inference::HemisphereRole::Left).unwrap();
        assert_eq!(route.kind, ProviderKind::LocalOllama);
        assert_eq!(route.endpoint.as_deref(), Some("http://10.0.0.9:11434"));
        assert!(route_requires_consent(
            route.kind,
            route.endpoint.as_deref()
        ));
    }

    // Note: bypass-env semantics for `ensure_all_granted_or_prompt` are
    // identical to the inner `ensure_granted_or_prompt`, which is already
    // covered by `ensure_granted_or_prompt_honours_bypass_env`. Adding a
    // second env-mutating test races against it under cargo's default
    // parallel test runner.

    // ── Finding 5 (Session 13) runtime consent re-check ───────────────

    #[test]
    fn ensure_all_still_granted_passes_when_every_kind_granted() {
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            Some(crate::cli::init::ProviderKind::OpenaiApi),
            Some(crate::config::inference::InferenceProvider::Gemini),
            Some(crate::config::inference::InferenceProvider::ClaudeCli),
            None,
            crate::config::inference::TopologyMode::Custom,
        );
        grant(tmp.path(), crate::cli::init::ProviderKind::OpenaiApi).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::GeminiApi).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::ClaudeCli).unwrap();
        let result = ensure_all_still_granted(tmp.path(), &cfg);
        assert!(result.is_ok(), "all granted should pass, got {result:?}");
    }

    #[test]
    fn ensure_all_still_granted_blocks_when_primary_provider_revoked() {
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            Some(crate::cli::init::ProviderKind::OpenaiApi),
            None,
            None,
            None,
            crate::config::inference::TopologyMode::Single,
        );
        // Operator initially granted, then later revoked.
        grant(tmp.path(), crate::cli::init::ProviderKind::OpenaiApi).unwrap();
        revoke(tmp.path(), crate::cli::init::ProviderKind::OpenaiApi).unwrap();
        let err = ensure_all_still_granted(tmp.path(), &cfg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("openai_api"),
            "msg should name provider: {msg}"
        );
        assert!(msg.contains("revoked"), "msg should say revoked: {msg}",);
        assert!(msg.contains("daemon"), "msg should mention daemon: {msg}",);
    }

    #[test]
    fn ensure_all_still_granted_blocks_when_hemisphere_provider_revoked() {
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            Some(crate::cli::init::ProviderKind::ClaudeCli),
            Some(crate::config::inference::InferenceProvider::ClaudeCli),
            Some(crate::config::inference::InferenceProvider::Gemini),
            Some(crate::config::inference::InferenceProvider::OpenAi),
            crate::config::inference::TopologyMode::Custom,
        );
        // Grant every kind, then revoke only the Right (Gemini) slot.
        grant(tmp.path(), crate::cli::init::ProviderKind::ClaudeCli).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::GeminiApi).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::OpenaiApi).unwrap();
        revoke(tmp.path(), crate::cli::init::ProviderKind::GeminiApi).unwrap();
        let err = ensure_all_still_granted(tmp.path(), &cfg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("gemini_api"),
            "msg should name revoked hemisphere provider: {msg}",
        );
    }

    #[test]
    fn ensure_all_still_granted_passes_when_only_local_qwen() {
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            None,
            Some(crate::config::inference::InferenceProvider::LocalQwen),
            Some(crate::config::inference::InferenceProvider::LocalQwen),
            Some(crate::config::inference::InferenceProvider::LocalQwen),
            crate::config::inference::TopologyMode::Custom,
        );
        // No grants needed — local-only never gates.
        let result = ensure_all_still_granted(tmp.path(), &cfg);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_all_still_granted_ignores_bypass_env() {
        // Critical contract: the runtime re-check MUST NOT honour
        // NEOTH_CONSENT_BYPASS. Bypass is a startup-only escape hatch
        // for CI / scripted bring-up; once the daemon is live a revoke
        // must stop traffic regardless of the env var.
        //
        // We pin this by constructing a state where bypass would
        // short-circuit `ensure_all_granted_or_prompt` (no marker file
        // + bypass=1) but `ensure_all_still_granted` must still bail.
        // To avoid env-var races with other tests we use a temp home
        // dir and never set the bypass var — instead we directly
        // verify the implementation by reading the source: the only
        // env check `ensure_all_still_granted` makes is none.
        //
        // Test pins the OUTCOME: a revoked provider always bails,
        // regardless of any env mutation the caller might make.
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            Some(crate::cli::init::ProviderKind::OpenaiApi),
            None,
            None,
            None,
            crate::config::inference::TopologyMode::Single,
        );
        // No grant recorded. ensure_all_still_granted must bail even
        // though no marker file ever existed (revoke of never-granted
        // is the same observable end-state as revoke of previously-granted).
        let err = ensure_all_still_granted(tmp.path(), &cfg).unwrap_err();
        assert!(err.to_string().contains("openai_api"));
    }

    #[test]
    fn ensure_all_granted_or_prompt_passes_when_every_kind_granted() {
        let tmp = TempDir::new().unwrap();
        let cfg = mk_config_with_inference(
            Some(crate::cli::init::ProviderKind::OpenaiApi),
            Some(crate::config::inference::InferenceProvider::Gemini),
            Some(crate::config::inference::InferenceProvider::ClaudeCli),
            Some(crate::config::inference::InferenceProvider::LocalQwen),
            crate::config::inference::TopologyMode::Custom,
        );
        grant(tmp.path(), crate::cli::init::ProviderKind::OpenaiApi).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::GeminiApi).unwrap();
        grant(tmp.path(), crate::cli::init::ProviderKind::ClaudeCli).unwrap();
        // LocalQwen needs no grant.
        let result = ensure_all_granted_or_prompt(tmp.path(), &cfg);
        assert!(result.is_ok());
    }

    #[test]
    fn marker_path_uses_slug_for_filename() {
        let tmp = TempDir::new().unwrap();
        let p = marker_path(tmp.path(), ProviderKind::ClaudeCli);
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("claude_cli.granted")
        );
        assert!(p.parent().unwrap().ends_with("consent"));
    }

    #[test]
    fn marker_reader_rejects_oversized_content_from_the_opened_handle() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        let path = marker_path(tmp.path(), ProviderKind::ClaudeCli);
        std::fs::write(&path, vec![b'x'; MAX_CONSENT_MARKER_BYTES as usize + 1]).unwrap();

        let error = read_marker_raw(tmp.path(), ProviderKind::ClaudeCli).unwrap_err();
        assert!(format!("{error:#}").contains("size cap"));
        assert!(!is_granted(tmp.path(), ProviderKind::ClaudeCli));
    }

    #[cfg(unix)]
    #[test]
    fn marker_reader_rejects_a_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(consent_dir(tmp.path())).unwrap();
        let target = tmp.path().join("outside-marker");
        std::fs::write(&target, b"1717171717").unwrap();
        let path = marker_path(tmp.path(), ProviderKind::ClaudeCli);
        symlink(&target, &path).unwrap();

        assert!(read_marker_raw(tmp.path(), ProviderKind::ClaudeCli).is_err());
        assert!(!is_granted(tmp.path(), ProviderKind::ClaudeCli));
    }

    // ── P-02 (Session 24) tri-state ConsentDecision ──────────────────

    #[test]
    fn p_02_decision_helpers_pin_allows_and_persists() {
        // Drift guard for the two boolean projections of the enum.
        assert!(ConsentDecision::AllowOnce.allows());
        assert!(ConsentDecision::AllowAlways.allows());
        assert!(!ConsentDecision::Deny.allows());

        assert!(!ConsentDecision::AllowOnce.persists());
        assert!(ConsentDecision::AllowAlways.persists());
        assert!(!ConsentDecision::Deny.persists());
    }

    #[test]
    fn p_02_decision_as_str_pinned_for_audit() {
        assert_eq!(ConsentDecision::AllowOnce.as_str(), "allow_once");
        assert_eq!(ConsentDecision::AllowAlways.as_str(), "allow_always");
        assert_eq!(ConsentDecision::Deny.as_str(), "deny");
    }

    #[test]
    fn p_02_parse_decision_accepts_canonical_and_aliases_case_insensitive() {
        // Canonical
        assert_eq!(
            parse_decision("allow_once"),
            Some(ConsentDecision::AllowOnce)
        );
        assert_eq!(
            parse_decision("allow_always"),
            Some(ConsentDecision::AllowAlways)
        );
        assert_eq!(parse_decision("deny"), Some(ConsentDecision::Deny));
        // Numeric (1/2/3 menu picker)
        assert_eq!(parse_decision("1"), Some(ConsentDecision::AllowOnce));
        assert_eq!(parse_decision("2"), Some(ConsentDecision::AllowAlways));
        assert_eq!(parse_decision("3"), Some(ConsentDecision::Deny));
        // Aliases
        assert_eq!(parse_decision("YES"), Some(ConsentDecision::AllowOnce));
        assert_eq!(parse_decision("Always"), Some(ConsentDecision::AllowAlways));
        assert_eq!(parse_decision("  no  "), Some(ConsentDecision::Deny));
        assert_eq!(
            parse_decision("Allow Once"),
            Some(ConsentDecision::AllowOnce)
        );
    }

    #[test]
    fn p_02_parse_decision_returns_none_for_garbage() {
        assert!(parse_decision("").is_none());
        assert!(parse_decision("maybe").is_none());
        assert!(parse_decision("42").is_none());
    }

    #[test]
    fn p_02_apply_decision_allow_always_writes_marker() {
        let tmp = TempDir::new().unwrap();
        let kind = ProviderKind::OpenaiApi;
        assert!(!is_granted(tmp.path(), kind));
        let changed = apply_decision(tmp.path(), kind, ConsentDecision::AllowAlways).unwrap();
        assert!(changed, "first AllowAlways must flip the bit");
        assert!(is_granted(tmp.path(), kind));
        // Second AllowAlways on already-granted state — same outcome,
        // `changed = false` per the contract.
        let changed2 = apply_decision(tmp.path(), kind, ConsentDecision::AllowAlways).unwrap();
        assert!(!changed2, "idempotent AllowAlways must report no change");
        assert!(is_granted(tmp.path(), kind));
    }

    #[test]
    fn p_02_apply_decision_allow_once_does_not_write_marker() {
        let tmp = TempDir::new().unwrap();
        let kind = ProviderKind::OpenaiApi;
        let changed = apply_decision(tmp.path(), kind, ConsentDecision::AllowOnce).unwrap();
        assert!(!changed);
        assert!(
            !is_granted(tmp.path(), kind),
            "AllowOnce must NOT persist — next call re-prompts",
        );
    }

    #[test]
    fn p_02_apply_decision_deny_does_not_write_marker_or_revoke_existing() {
        let tmp = TempDir::new().unwrap();
        let kind = ProviderKind::OpenaiApi;
        // Deny against fresh state → no marker.
        apply_decision(tmp.path(), kind, ConsentDecision::Deny).unwrap();
        assert!(!is_granted(tmp.path(), kind));
        // Deny against ALREADY-granted state must NOT auto-revoke the
        // existing grant. Operator who said deny-this-time keeps
        // their prior allow-always; an explicit `neoth consent revoke`
        // is the only path to drop the marker. Pin this.
        grant(tmp.path(), kind).unwrap();
        apply_decision(tmp.path(), kind, ConsentDecision::Deny).unwrap();
        assert!(
            is_granted(tmp.path(), kind),
            "Deny must not auto-revoke prior AllowAlways — operator uses `consent revoke`",
        );
    }

    #[test]
    fn p_02_apply_decision_non_cloud_kind_is_noop() {
        let tmp = TempDir::new().unwrap();
        // Local provider — every decision is a no-op + reports no-change.
        for d in [
            ConsentDecision::AllowOnce,
            ConsentDecision::AllowAlways,
            ConsentDecision::Deny,
        ] {
            let changed = apply_decision(tmp.path(), ProviderKind::LocalQwen, d).unwrap();
            assert!(!changed, "non-cloud apply must be no-op for {d:?}");
        }
        assert!(!consent_dir(tmp.path()).exists());
    }

    #[test]
    fn p_02_consent_decision_payload_carries_required_fields() {
        let bytes = consent_decision_payload(
            &ConsentRoute::new(ProviderKind::OpenaiApi, None),
            ConsentDecision::AllowAlways,
            "tty",
            1_700_000_000,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["kind"], "openai_api");
        assert_eq!(v["decision"], "allow_always");
        assert_eq!(v["source"], "tty");
        assert_eq!(v["endpoint_origin"], "https://api.openai.com");
        assert_eq!(v["ts_unix"], 1_700_000_000);
    }

    #[test]
    fn p_02_consent_decision_payload_round_trips_via_serde() {
        // Drift guard for the enum's serde rename. A future refactor
        // that drops `rename_all = "snake_case"` would break WAL
        // replay; this test catches it.
        let json = serde_json::to_string(&ConsentDecision::AllowAlways).unwrap();
        assert_eq!(json, "\"allow_always\"");
        let back: ConsentDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ConsentDecision::AllowAlways);
    }
}
