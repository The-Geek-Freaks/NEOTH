//! Discovery orchestrator — fan-out across all configured model
//! sources and merge results into the catalog.
//!
//! Entry points:
//!
//!   - [`discover_all`] — plans every configured model-discovery source,
//!     runs the sources that have usable setup, and updates the catalog on
//!     disk. Used by the daemon refresh task + `neoth catalog refresh`.
//!   - [`build_sources_from_config_at`] — translates `FreedomConfig` into an
//!     explicit [`SourcePlan`]. The plan retains every configured provider,
//!     including providers that cannot run because credentials or required
//!     endpoint configuration are missing, so callers cannot silently mistake
//!     an omitted provider for a successful refresh.
//!
//! Concurrency: sources are independent — one provider's failure
//! does NOT halt the others. `futures::join_all` collects results
//! in parallel; each source records a sanitized failure status under
//! `ProviderCatalog::last_error` so the operator sees which provider needs
//! attention without persisting provider-controlled response text.

use std::path::Path;

use anyhow::{Context, Result};
use futures_util::future::join_all;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::catalog::{CatalogMutation, CatalogRefreshAttempt, ModelsCatalog};
use super::sources::ModelSource;
use super::sources::anthropic::AnthropicSource;
use super::sources::bedrock::BedrockSource;
use super::sources::gemini::GeminiSource;
use super::sources::openai::OpenAiSource;
use crate::cli::init::ProviderKind;
use crate::config::FreedomConfig;
use crate::config::inference::{HemisphereRole, HemisphereSlot, InferenceProvider};
use crate::consent::{ConsentRoute, is_route_granted};
use crate::providers::aws_credentials;
use crate::secret::SecretString;

/// Summary of one discovery run — returned to the CLI subcommand
/// so the operator sees `refreshed: 3, failed: 1` rather than just
/// "done".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryReport {
    /// Whether this run durably published a new catalog generation. Failed
    /// fetches count because they persist `last_error`; a v1-to-v2 migration
    /// also counts even when no provider was runnable.
    pub catalog_changed: bool,
    /// Exact committed catalog generation observed or written by this run.
    /// `None` only when no catalog file exists.
    pub catalog_generation: Option<u64>,
    /// SHA-256 of the canonical v2 catalog bytes for the generation above.
    /// Never contains provider credentials or raw endpoint values.
    pub catalog_hash: Option<String>,
    /// Canonical provider keys covered by the source plan. Every key must
    /// appear in exactly one outcome set below.
    pub configured: Vec<String>,
    /// Provider keys that were already fresh and therefore not fetched during
    /// a stale-only execution.
    pub fresh: Vec<String>,
    /// Provider keys that successfully refreshed.
    pub refreshed: Vec<String>,
    /// Provider keys where the fetch raised an error.
    pub failed: Vec<String>,
    /// Provider keys whose completion lost the durable refresh CAS to a newer
    /// attempt or to a catalog clear. These are incomplete outcomes, but they
    /// did not mutate the current catalog generation.
    pub superseded: Vec<String>,
    /// Provider keys that were skipped because no credentials were
    /// configured (typical for an operator who only uses one cloud).
    pub skipped_no_creds: Vec<String>,
    /// Provider keys whose external credential-chain resolution failed before
    /// a request could be constructed. Only provider IDs cross this boundary;
    /// resolver error text is deliberately not included in receipts.
    pub credential_failures: Vec<String>,
    /// Provider keys missing non-secret mandatory setup, such as an
    /// OpenAI-compatible endpoint URL.
    pub configuration_failures: Vec<String>,
    /// Effective runtime providers for which NEOTH has an adapter but no
    /// provider model-list discovery source. They remain explicit in the
    /// outcome partition instead of being misreported as "no sources".
    pub unsupported: Vec<String>,
    /// Effective routes which were not eligible for discovery because the
    /// selected NEOTH instance has no egress consent for that exact route.
    pub blocked_no_consent: Vec<String>,
}

impl DiscoveryReport {
    pub fn summary_line(&self) -> String {
        format!(
            "{} fresh, {} refreshed, {} failed, {} superseded, {} skipped (no creds), {} credential failures, {} configuration failures, {} unsupported, {} blocked (no consent)",
            self.fresh.len(),
            self.refreshed.len(),
            self.failed.len(),
            self.superseded.len(),
            self.skipped_no_creds.len(),
            self.credential_failures.len(),
            self.configuration_failures.len(),
            self.unsupported.len(),
            self.blocked_no_consent.len(),
        )
    }
}

pub const ANTHROPIC_CATALOG_PROVIDER: &str = "anthropic_api";
pub const OPENAI_CATALOG_PROVIDER: &str = "openai_api";
pub const GEMINI_CATALOG_PROVIDER: &str = "gemini_api";
pub const OPENAI_COMPAT_CATALOG_PROVIDER: &str = "openai_compat";
pub const BEDROCK_CATALOG_PROVIDER: &str = "aws_bedrock";
pub const INVALID_CATALOG_PROVIDER: &str = "invalid_provider";

type CatalogBindingMac = Hmac<Sha256>;

#[cfg(test)]
const TEST_CATALOG_BINDING_KEY: &[u8] = b"neoth-test-catalog-binding-key-v1";

enum PlannedSourceState {
    Runnable {
        source: Box<dyn ModelSource>,
        binding_hash: String,
    },
    Fresh,
    SkippedNoCredentials,
    CredentialFailure,
    ConfigurationFailure,
    Unsupported,
    BlockedNoConsent,
}

type RunnableSources = Vec<(&'static str, String, Box<dyn ModelSource>)>;

enum CatalogUpdate {
    Refreshed {
        provider: &'static str,
        attempt_token: String,
        binding_hash: String,
        result: super::sources::FetchResult,
    },
    Failed {
        provider: &'static str,
        attempt_token: String,
        binding_hash: String,
        error: String,
    },
}

enum CatalogApplyOutcome {
    Refreshed(&'static str),
    Failed(&'static str),
    Superseded(&'static str),
}

/// One canonical provider in a discovery plan. Kept private so callers cannot
/// manufacture contradictory provider states.
struct PlannedSource {
    provider: String,
    state: PlannedSourceState,
}

/// Complete configured discovery scope. Unlike a plain source vector, this
/// retains providers that cannot currently run and carries them into the
/// receipt as an explicit, fail-closed outcome.
#[derive(Default)]
pub struct SourcePlan {
    entries: Vec<PlannedSource>,
}

impl SourcePlan {
    fn push(&mut self, provider: impl Into<String>, state: PlannedSourceState) {
        let provider = provider.into();
        debug_assert!(
            !self.entries.iter().any(|entry| entry.provider == provider),
            "duplicate canonical model-catalog provider `{provider}`"
        );
        self.entries.push(PlannedSource { provider, state });
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn binding_hash_for_test(&self, provider: &str) -> Option<&str> {
        self.entries.iter().find_map(|entry| {
            if entry.provider != provider {
                return None;
            }
            match &entry.state {
                PlannedSourceState::Runnable { binding_hash, .. } => Some(binding_hash.as_str()),
                _ => None,
            }
        })
    }

    /// Convert every configured provider with a fresh cached entry into an
    /// explicit `fresh` outcome. An absent catalog entry is never fresh, so its
    /// runnable or setup-failure disposition remains intact.
    pub fn stale_only(mut self, catalog: &ModelsCatalog, now_unix: u64) -> Self {
        let ttl_secs = catalog.effective_ttl_secs();
        for entry in &mut self.entries {
            if let PlannedSourceState::Runnable { binding_hash, .. } = &entry.state
                && catalog.provider(&entry.provider).is_some_and(|provider| {
                    provider.is_fresh_for_binding(now_unix, ttl_secs, binding_hash)
                })
            {
                entry.state = PlannedSourceState::Fresh;
            }
        }
        self
    }

    #[cfg(test)]
    fn from_sources(sources: Vec<Box<dyn ModelSource>>) -> Self {
        let mut plan = Self::default();
        for source in sources {
            let provider = source.provider();
            // Deterministic injected sources carry no credential material. This
            // seam exists for orchestrator tests; production config planning
            // always uses the selected instance's WAL HMAC key below.
            let binding_hash = catalog_binding_hmac(
                b"neoth-injected-catalog-source-v1",
                provider,
                &[("source", "injected")],
            );
            plan.push(
                provider,
                PlannedSourceState::Runnable {
                    source,
                    // Injection seam for deterministic sources. Production
                    // hashes the exact effective runtime identity instead.
                    binding_hash,
                },
            );
        }
        plan
    }

    fn into_execution(self) -> (DiscoveryReport, RunnableSources) {
        let mut report = DiscoveryReport::default();
        let mut runnable = Vec::new();
        for entry in self.entries {
            report.configured.push(entry.provider.clone());
            match entry.state {
                PlannedSourceState::Runnable {
                    source,
                    binding_hash,
                } => runnable.push((source.provider(), binding_hash, source)),
                PlannedSourceState::Fresh => report.fresh.push(entry.provider),
                PlannedSourceState::SkippedNoCredentials => {
                    report.skipped_no_creds.push(entry.provider)
                }
                PlannedSourceState::CredentialFailure => {
                    report.credential_failures.push(entry.provider)
                }
                PlannedSourceState::ConfigurationFailure => {
                    report.configuration_failures.push(entry.provider)
                }
                PlannedSourceState::Unsupported => report.unsupported.push(entry.provider),
                PlannedSourceState::BlockedNoConsent => {
                    report.blocked_no_consent.push(entry.provider)
                }
            }
        }
        (report, runnable)
    }
}

/// One exact runtime binding. Secrets never cross the receipt boundary and are
/// compared only in memory to reject a canonical catalog which would collapse
/// multiple credential or endpoint identities.
#[derive(Clone)]
struct RouteBinding {
    kind: ProviderKind,
    key: Option<SecretString>,
    endpoint: Option<String>,
    region: Option<String>,
    binary: Option<String>,
    consented: bool,
    runtime_rejected: bool,
}

impl RouteBinding {
    fn provider_id(&self) -> &'static str {
        self.kind
            .catalog_key()
            .unwrap_or_else(|| self.kind.as_provider_id())
    }

    fn same_catalog_identity(&self, other: &Self) -> bool {
        if self.provider_id() != other.provider_id() {
            return false;
        }
        match self.kind {
            ProviderKind::OpenaiApi | ProviderKind::OpenaiCompat => {
                self.kind == other.kind
                    && effective_models_endpoint(self.kind, self.endpoint.as_deref()).ok()
                        == effective_models_endpoint(other.kind, other.endpoint.as_deref()).ok()
                    && self.key.as_ref().map(SecretString::expose_secret)
                        == other.key.as_ref().map(SecretString::expose_secret)
            }
            ProviderKind::AwsBedrock => {
                self.kind == other.kind
                    && effective_bedrock_region(self.region.as_deref())
                        == effective_bedrock_region(other.region.as_deref())
            }
            ProviderKind::GeminiApi => {
                self.kind == other.kind
                    && self.key.as_ref().map(SecretString::expose_secret)
                        == other.key.as_ref().map(SecretString::expose_secret)
            }
            // Anthropic REST and Claude CLI intentionally share one catalog.
            // Their exact source selection is resolved across the whole group.
            ProviderKind::ClaudeCli | ProviderKind::AnthropicApi => true,
            // These adapters have no discovery source, so endpoint/key fields
            // cannot make their terminal Unsupported outcome contradictory.
            _ => self.kind == other.kind,
        }
    }

    fn same_exact_route(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.endpoint.as_deref().map(str::trim) == other.endpoint.as_deref().map(str::trim)
            && self.region.as_deref().map(str::trim) == other.region.as_deref().map(str::trim)
            && self.binary.as_deref().map(str::trim) == other.binary.as_deref().map(str::trim)
            && self.key.as_ref().map(SecretString::expose_secret)
                == other.key.as_ref().map(SecretString::expose_secret)
            && self.consented == other.consented
            && self.runtime_rejected == other.runtime_rejected
    }
}

/// Production planning is always bound to the selected NEOTH instance. This
/// is required because consent is instance-local; a process-global or
/// home-less fallback inventory could otherwise perform unapproved egress.
pub fn build_sources_from_config_at(config: &FreedomConfig, home: &Path) -> Result<SourcePlan> {
    let binding_key = zeroize::Zeroizing::new(
        crate::wal::compaction::load_or_init_key(&home.join("wal").join("hmac.key"))
            .context("load instance key for model-catalog route bindings")?,
    );
    Ok(build_sources_with_bedrock_resolver_at(
        config,
        Some(home),
        binding_key.as_slice(),
        resolve_bedrock_credentials_for_discovery,
    ))
}

/// Test-only home-less seam. Production callers must use
/// [`build_sources_from_config_at`].
#[cfg(test)]
fn build_sources_from_config(config: &FreedomConfig) -> SourcePlan {
    build_sources_with_bedrock_resolver_at(
        config,
        None,
        TEST_CATALOG_BINDING_KEY,
        resolve_bedrock_credentials_for_discovery,
    )
}

#[cfg(test)]
fn build_sources_with_bedrock_resolver(
    config: &FreedomConfig,
    bedrock_resolver: impl FnOnce(&FreedomConfig, &[u8]) -> Result<(Box<dyn ModelSource>, String)>,
) -> SourcePlan {
    build_sources_with_bedrock_resolver_at(config, None, TEST_CATALOG_BINDING_KEY, bedrock_resolver)
}

fn build_sources_with_bedrock_resolver_at(
    config: &FreedomConfig,
    home: Option<&Path>,
    binding_key: &[u8],
    bedrock_resolver: impl FnOnce(&FreedomConfig, &[u8]) -> Result<(Box<dyn ModelSource>, String)>,
) -> SourcePlan {
    let (bindings, invalid_auxiliary) = effective_route_bindings(config, home);
    let mut plan = SourcePlan::default();
    let mut resolver = Some(bedrock_resolver);

    let mut provider_ids = Vec::new();
    for provider in [
        ANTHROPIC_CATALOG_PROVIDER,
        OPENAI_CATALOG_PROVIDER,
        GEMINI_CATALOG_PROVIDER,
        OPENAI_COMPAT_CATALOG_PROVIDER,
        BEDROCK_CATALOG_PROVIDER,
    ] {
        if bindings
            .iter()
            .any(|binding| binding.provider_id() == provider)
        {
            provider_ids.push(provider);
        }
    }
    for binding in &bindings {
        let provider = binding.provider_id();
        if !provider_ids.contains(&provider) {
            provider_ids.push(provider);
        }
    }

    for provider in provider_ids {
        let grouped: Vec<&RouteBinding> = bindings
            .iter()
            .filter(|binding| binding.provider_id() == provider)
            .collect();
        let first = grouped[0];
        let state = if grouped.iter().any(|binding| !binding.consented) {
            PlannedSourceState::BlockedNoConsent
        } else if grouped.iter().any(|binding| binding.runtime_rejected) {
            PlannedSourceState::ConfigurationFailure
        } else if provider == ANTHROPIC_CATALOG_PROVIDER {
            state_for_anthropic_group(&grouped, binding_key)
        } else if grouped
            .iter()
            .skip(1)
            .any(|binding| !first.same_catalog_identity(binding))
        {
            // One catalog key cannot honestly represent multiple endpoints,
            // credentials or regions. Do not pick the first.
            PlannedSourceState::ConfigurationFailure
        } else {
            state_for_binding(config, first, binding_key, &mut resolver)
        };
        plan.push(provider, state);
    }

    if invalid_auxiliary {
        plan.push(
            INVALID_CATALOG_PROVIDER,
            PlannedSourceState::ConfigurationFailure,
        );
    }
    plan
}

fn state_for_anthropic_group(grouped: &[&RouteBinding], binding_key: &[u8]) -> PlannedSourceState {
    let mut api_key: Option<SecretString> = None;
    let mut api_bindings = 0usize;
    let mut missing_api_keys = 0usize;
    for binding in grouped
        .iter()
        .filter(|binding| binding.kind == ProviderKind::AnthropicApi)
    {
        api_bindings += 1;
        let Some(candidate) = binding.key.clone() else {
            missing_api_keys += 1;
            continue;
        };
        if api_key
            .as_ref()
            .is_some_and(|known| known.expose_secret() != candidate.expose_secret())
        {
            return PlannedSourceState::ConfigurationFailure;
        }
        api_key = Some(candidate);
    }
    // One canonical provider key cannot honestly stand for a mixture of
    // authenticated and unauthenticated Anthropic REST routes. Falling back to
    // the available key would silently claim coverage for the missing route.
    if api_bindings > 0 && missing_api_keys > 0 {
        return PlannedSourceState::ConfigurationFailure;
    }
    if let Some(key) = api_key {
        let binding_hash = catalog_binding_hmac(
            binding_key,
            ANTHROPIC_CATALOG_PROVIDER,
            &[("source", "rest"), ("api_key", key.expose_secret())],
        );
        return PlannedSourceState::Runnable {
            source: Box::new(AnthropicSource::new(Some(key)).without_cli_probe()),
            binding_hash,
        };
    }

    let cli_bindings: Vec<_> = grouped
        .iter()
        .filter(|binding| binding.kind == ProviderKind::ClaudeCli)
        .collect();
    let Some(first) = cli_bindings.first() else {
        return PlannedSourceState::SkippedNoCredentials;
    };
    if cli_bindings.iter().skip(1).any(|binding| {
        binding.binary.as_deref().map(str::trim) != first.binary.as_deref().map(str::trim)
    }) {
        return PlannedSourceState::ConfigurationFailure;
    }
    let mut source = AnthropicSource::new(None);
    if let Some(binary) = first.binary.as_deref() {
        source = source.with_cli_binary(binary);
    }
    let binary = first.binary.as_deref().unwrap_or("claude");
    PlannedSourceState::Runnable {
        source: Box::new(source),
        binding_hash: catalog_binding_hmac(
            binding_key,
            ANTHROPIC_CATALOG_PROVIDER,
            &[("source", "cli"), ("binary", binary)],
        ),
    }
}

fn state_for_binding<F>(
    config: &FreedomConfig,
    binding: &RouteBinding,
    binding_key: &[u8],
    bedrock_resolver: &mut Option<F>,
) -> PlannedSourceState
where
    F: FnOnce(&FreedomConfig, &[u8]) -> Result<(Box<dyn ModelSource>, String)>,
{
    match binding.kind {
        ProviderKind::ClaudeCli => {
            unreachable!("anthropic bindings are resolved as one canonical group")
        }
        ProviderKind::AnthropicApi => {
            binding
                .key
                .clone()
                .map_or(PlannedSourceState::SkippedNoCredentials, |key| {
                    PlannedSourceState::Runnable {
                        binding_hash: catalog_binding_hmac(
                            binding_key,
                            ANTHROPIC_CATALOG_PROVIDER,
                            &[("source", "rest"), ("api_key", key.expose_secret())],
                        ),
                        source: Box::new(AnthropicSource::new(Some(key)).without_cli_probe()),
                    }
                })
        }
        ProviderKind::OpenaiApi => {
            binding
                .key
                .clone()
                .map_or(PlannedSourceState::SkippedNoCredentials, |key| {
                    let Ok(Some(endpoint)) = effective_models_endpoint(
                        ProviderKind::OpenaiApi,
                        binding.endpoint.as_deref(),
                    ) else {
                        return PlannedSourceState::ConfigurationFailure;
                    };
                    let binding_hash = catalog_binding_hmac(
                        binding_key,
                        OPENAI_CATALOG_PROVIDER,
                        &[("endpoint", &endpoint), ("api_key", key.expose_secret())],
                    );
                    let mut source = OpenAiSource::new_openai(Some(key));
                    if binding.endpoint.is_some() {
                        source = source.with_endpoint(endpoint);
                    }
                    PlannedSourceState::Runnable {
                        binding_hash,
                        source: Box::new(source),
                    }
                })
        }
        ProviderKind::GeminiApi => {
            binding
                .key
                .clone()
                .map_or(PlannedSourceState::SkippedNoCredentials, |key| {
                    PlannedSourceState::Runnable {
                        binding_hash: catalog_binding_hmac(
                            binding_key,
                            GEMINI_CATALOG_PROVIDER,
                            &[("api_key", key.expose_secret())],
                        ),
                        source: Box::new(GeminiSource::new(Some(key))),
                    }
                })
        }
        ProviderKind::OpenaiCompat => {
            match binding
                .endpoint
                .as_deref()
                .map(|endpoint| OpenAiSource::new_compat(binding.key.clone(), endpoint))
            {
                Some(Ok(source)) => {
                    let endpoint = effective_models_endpoint(
                        ProviderKind::OpenaiCompat,
                        binding.endpoint.as_deref(),
                    )
                    .expect("validated OpenAI-compatible endpoint")
                    .expect("OpenAI-compatible endpoint is present");
                    let key = binding
                        .key
                        .as_ref()
                        .map(SecretString::expose_secret)
                        .unwrap_or("");
                    PlannedSourceState::Runnable {
                        binding_hash: catalog_binding_hmac(
                            binding_key,
                            OPENAI_COMPAT_CATALOG_PROVIDER,
                            &[("endpoint", &endpoint), ("api_key", key)],
                        ),
                        source: Box::new(source),
                    }
                }
                Some(Err(_)) | None => PlannedSourceState::ConfigurationFailure,
            }
        }
        ProviderKind::AwsBedrock => {
            let mut bedrock_config = config.clone();
            bedrock_config.provider_region = binding.region.clone();
            match bedrock_resolver
                .take()
                .expect("one canonical Bedrock target per plan")(
                &bedrock_config, binding_key
            ) {
                Ok((source, binding_hash)) => PlannedSourceState::Runnable {
                    source,
                    binding_hash,
                },
                Err(_) => PlannedSourceState::CredentialFailure,
            }
        }
        ProviderKind::Skip => PlannedSourceState::ConfigurationFailure,
        ProviderKind::LocalQwen
        | ProviderKind::LocalOuro
        | ProviderKind::LocalOllama
        | ProviderKind::RecursiveMas
        | ProviderKind::AzureOpenAi
        | ProviderKind::Cohere
        | ProviderKind::GitHubCopilot => PlannedSourceState::Unsupported,
    }
}

fn effective_route_bindings(
    config: &FreedomConfig,
    home: Option<&Path>,
) -> (Vec<RouteBinding>, bool) {
    const ROLES: [HemisphereRole; 3] = [
        HemisphereRole::Left,
        HemisphereRole::Right,
        HemisphereRole::Cerebellum,
    ];
    let mut bindings = Vec::new();
    let mut invalid_auxiliary = false;

    // Left is always the primary runtime route. Right/Cerebellum and recursive
    // leaves exist only when the council can actually dispatch them.
    push_slot_binding(
        &mut bindings,
        config,
        config.inference.slot_for(HemisphereRole::Left),
        home,
    );
    let council_enabled =
        !config.council.disabled.unwrap_or(false) && !config.council.mode.is_single();
    if council_enabled {
        for role in [HemisphereRole::Right, HemisphereRole::Cerebellum] {
            push_slot_binding(&mut bindings, config, config.inference.slot_for(role), home);
        }
        if config.inference.hemisphere_council_depth.get() > 1 {
            for outer in ROLES {
                for inner in ROLES {
                    push_slot_binding(
                        &mut bindings,
                        config,
                        config.inference.slot_for_sub(outer, inner),
                        home,
                    );
                }
            }
        }
    }

    // These factories can route independently of the primary/council. Their
    // cross-vendor synthetic configs explicitly strip main key + endpoint.
    match config.inference.utility_provider {
        Some(provider) => push_auxiliary_binding(
            &mut bindings,
            config,
            provider.to_provider_kind(),
            false,
            home,
        ),
        None => push_top_level_binding(&mut bindings, config, home),
    }
    match config.inference.teacher_provider {
        Some(provider) => {
            let rejected = provider.is_local() || provider == InferenceProvider::RecursiveMas;
            push_auxiliary_binding(
                &mut bindings,
                config,
                provider.to_provider_kind(),
                rejected,
                home,
            );
        }
        None => push_top_level_binding(&mut bindings, config, home),
    }
    match config.profile.learn_provider.as_deref() {
        Some(raw) => match serde_yaml::from_str::<ProviderKind>(raw) {
            Ok(kind) => {
                push_auxiliary_binding(&mut bindings, config, kind, false, home);
                if config.profile.allow_cloud_fallback {
                    push_top_level_binding(&mut bindings, config, home);
                }
            }
            Err(_) => invalid_auxiliary = true,
        },
        None => push_top_level_binding(&mut bindings, config, home),
    }

    // A max_hops=0 chain is unreachable. Production inventory uses the exact
    // runtime consent filter; intentionally excluded candidates must not poison
    // an otherwise runnable provider group as a discovery failure.
    if config.fallback.max_hops > 0 {
        let fallbacks: Vec<_> = match home {
            Some(home) => crate::providers::consented_fallback_slots(home, &config.fallback.chain),
            None => config
                .fallback
                .chain
                .iter()
                .filter_map(|slot| slot.provider.map(|provider| (slot, provider)))
                .collect(),
        };
        for (slot, provider) in fallbacks {
            push_explicit_binding(
                &mut bindings,
                config,
                provider.to_provider_kind(),
                slot,
                false,
                home,
            );
        }
    }

    (bindings, invalid_auxiliary)
}

fn push_slot_binding(
    bindings: &mut Vec<RouteBinding>,
    config: &FreedomConfig,
    slot: &HemisphereSlot,
    home: Option<&Path>,
) {
    match slot.provider {
        Some(provider) => push_explicit_binding(
            bindings,
            config,
            provider.to_provider_kind(),
            slot,
            false,
            home,
        ),
        None => push_top_level_binding(bindings, config, home),
    }
}

fn push_top_level_binding(
    bindings: &mut Vec<RouteBinding>,
    config: &FreedomConfig,
    home: Option<&Path>,
) {
    let Some(kind) = config.provider_kind else {
        return;
    };
    push_binding(
        bindings,
        RouteBinding {
            kind,
            key: nonempty_key(config.provider_key.as_ref()),
            endpoint: nonempty(config.provider_endpoint.as_deref()),
            region: nonempty(config.provider_region.as_deref()),
            binary: nonempty(config.provider_binary.as_deref()),
            consented: route_consented(home, kind, config.provider_endpoint.as_deref()),
            runtime_rejected: kind == ProviderKind::Skip,
        },
    );
}

fn push_auxiliary_binding(
    bindings: &mut Vec<RouteBinding>,
    config: &FreedomConfig,
    kind: ProviderKind,
    runtime_rejected: bool,
    home: Option<&Path>,
) {
    let same_vendor = config.provider_kind == Some(kind);
    let endpoint = same_vendor
        .then(|| nonempty(config.provider_endpoint.as_deref()))
        .flatten();
    push_binding(
        bindings,
        RouteBinding {
            kind,
            key: same_vendor
                .then(|| nonempty_key(config.provider_key.as_ref()))
                .flatten(),
            endpoint: endpoint.clone(),
            region: nonempty(config.provider_region.as_deref()),
            binary: nonempty(config.provider_binary.as_deref()),
            consented: route_consented(home, kind, endpoint.as_deref()),
            runtime_rejected,
        },
    );
}

fn push_explicit_binding(
    bindings: &mut Vec<RouteBinding>,
    config: &FreedomConfig,
    kind: ProviderKind,
    slot: &HemisphereSlot,
    runtime_rejected: bool,
    home: Option<&Path>,
) {
    let endpoint = nonempty(slot.endpoint.as_deref());
    push_binding(
        bindings,
        RouteBinding {
            kind,
            key: nonempty_key(slot.key.as_ref()),
            endpoint: endpoint.clone(),
            region: nonempty(slot.region.as_deref())
                .or_else(|| nonempty(config.provider_region.as_deref())),
            binary: nonempty(config.provider_binary.as_deref()),
            consented: route_consented(home, kind, endpoint.as_deref()),
            runtime_rejected,
        },
    );
}

fn push_binding(bindings: &mut Vec<RouteBinding>, binding: RouteBinding) {
    if !bindings
        .iter()
        .any(|known| known.same_exact_route(&binding))
    {
        bindings.push(binding);
    }
}

fn route_consented(home: Option<&Path>, kind: ProviderKind, endpoint: Option<&str>) -> bool {
    match home {
        Some(home) => is_route_granted(home, &ConsentRoute::new(kind, endpoint)),
        None => true,
    }
}

fn nonempty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn nonempty_key(key: Option<&SecretString>) -> Option<SecretString> {
    key.filter(|key| !key.is_empty()).cloned()
}

fn effective_models_endpoint(kind: ProviderKind, endpoint: Option<&str>) -> Result<Option<String>> {
    match kind {
        ProviderKind::OpenaiApi => super::sources::openai::canonical_models_endpoint(
            endpoint.unwrap_or("https://api.openai.com/v1/models"),
        )
        .map(Some),
        ProviderKind::OpenaiCompat => super::sources::openai::canonical_models_endpoint(
            endpoint.ok_or_else(|| anyhow::anyhow!("openai_compat endpoint missing"))?,
        )
        .map(Some),
        _ => Ok(None),
    }
}

fn effective_bedrock_region(region: Option<&str>) -> String {
    region
        .map(str::trim)
        .filter(|region| !region.is_empty())
        .map(str::to_owned)
        .or_else(|| std::env::var("AWS_REGION").ok())
        .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
        .unwrap_or_else(|| "us-east-1".to_string())
}

fn catalog_binding_hmac(key: &[u8], provider: &str, fields: &[(&str, &str)]) -> String {
    let mut mac = CatalogBindingMac::new_from_slice(key).expect("HMAC-SHA256 accepts any key");
    for value in ["neoth.catalog.binding.v3", provider] {
        mac.update(&(value.len() as u64).to_le_bytes());
        mac.update(value.as_bytes());
    }
    for (name, value) in fields {
        for part in [*name, *value] {
            mac.update(&(part.len() as u64).to_le_bytes());
            mac.update(part.as_bytes());
        }
    }
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
pub(crate) fn catalog_binding_hash(provider: &str, fields: &[(&str, &str)]) -> String {
    catalog_binding_hmac(TEST_CATALOG_BINDING_KEY, provider, fields)
}

fn resolve_bedrock_credentials_for_discovery(
    config: &FreedomConfig,
    binding_key: &[u8],
) -> Result<(Box<dyn ModelSource>, String)> {
    let region = effective_bedrock_region(config.provider_region.as_deref());
    let resolved = aws_credentials::resolve_chain(None, &aws_credentials::env_var_getter, None)?;
    let source = format!("{:?}", resolved.source);
    let session_token = resolved
        .credentials
        .session_token
        .as_ref()
        .map(SecretString::expose_secret)
        .unwrap_or("");
    let binding_hash = catalog_binding_hmac(
        binding_key,
        BEDROCK_CATALOG_PROVIDER,
        &[
            ("region", &region),
            ("credential_source", &source),
            (
                "access_key_id",
                resolved.credentials.access_key_id.expose_secret(),
            ),
            (
                "secret_access_key",
                resolved.credentials.secret_access_key.expose_secret(),
            ),
            ("session_token", session_token),
        ],
    );
    Ok((
        Box::new(BedrockSource::new(region, resolved.credentials)),
        binding_hash,
    ))
}

/// Run every source concurrently, update the catalog at `path` with
/// the results. Failures are recorded per-provider but do not abort
/// the run.
pub async fn discover_all(catalog_path: &Path, config: &FreedomConfig) -> Result<DiscoveryReport> {
    let home = catalog_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "model catalog path `{}` has no NEOTH instance directory",
            catalog_path.display()
        )
    })?;
    let plan = build_sources_from_config_at(config, home)?;
    let report = discover_with_plan(catalog_path, plan).await?;
    if !report.skipped_no_creds.is_empty()
        || !report.credential_failures.is_empty()
        || !report.configuration_failures.is_empty()
        || !report.unsupported.is_empty()
        || !report.blocked_no_consent.is_empty()
    {
        tracing::warn!(
            skipped_no_creds = ?report.skipped_no_creds,
            credential_failures = ?report.credential_failures,
            configuration_failures = ?report.configuration_failures,
            unsupported = ?report.unsupported,
            blocked_no_consent = ?report.blocked_no_consent,
            "model discovery source plan is incomplete"
        );
    }
    Ok(report)
}

/// Lower-level entry point — accepts pre-built sources so tests can
/// inject a deterministic mix. Production callers use [`discover_all`].
#[cfg(test)]
pub(crate) async fn discover_with_sources(
    catalog_path: &Path,
    sources: Vec<Box<dyn ModelSource>>,
) -> Result<DiscoveryReport> {
    discover_with_plan(catalog_path, SourcePlan::from_sources(sources)).await
}

/// Execute an exact source plan. Planning omissions are preserved in the
/// returned report, while only runnable entries are fetched.
pub async fn discover_with_plan(catalog_path: &Path, plan: SourcePlan) -> Result<DiscoveryReport> {
    let (mut report, sources) = plan.into_execution();

    if sources.is_empty() {
        // Nothing runnable. Preserve the configured/skipped/failure partition
        // and observe the exact existing snapshot. A valid v1 cache is
        // migrated once through the locked update path; malformed or unknown
        // state remains fail-closed and is never replaced as an empty cache.
        if let Some((generation, content_hash, changed)) = catalog_snapshot(catalog_path)? {
            report.catalog_generation = Some(generation);
            report.catalog_hash = Some(content_hash);
            report.catalog_changed = changed;
        }
        return Ok(report);
    }

    // Reserve a durable per-provider attempt before releasing the catalog
    // lock for network I/O. A later refresh replaces this token; completion
    // below compares it atomically and refuses to publish stale responses.
    let mut attempts = Vec::with_capacity(sources.len());
    for (provider, binding_hash, _) in &sources {
        attempts.push((*provider, binding_hash.clone(), mint_refresh_token()?));
    }
    ModelsCatalog::update_at_with_clear_epoch(catalog_path, |catalog, clear_epoch| {
        for (provider, binding_hash, token) in &attempts {
            let entry = catalog
                .providers
                .entry((*provider).to_string())
                .or_default();
            entry.refresh_attempt = Some(CatalogRefreshAttempt {
                token: token.clone(),
                binding_hash: binding_hash.clone(),
                clear_epoch: Some(clear_epoch.to_string()),
            });
        }
        Ok(())
    })?;

    // Network discovery deliberately happens outside the catalog lock. Only
    // the already-fetched outcomes enter the short locked CAS merge below.
    let futures = sources.iter().map(|(_, _, source)| source.fetch());
    let results = join_all(futures).await;
    let mut updates = Vec::with_capacity(results.len());

    for ((provider, binding_hash, attempt_token), result) in attempts.into_iter().zip(results) {
        match result {
            Ok(fr) if fr.provider == provider => {
                updates.push(CatalogUpdate::Refreshed {
                    provider,
                    attempt_token,
                    binding_hash,
                    result: fr,
                });
            }
            Ok(_) => {
                let error = "model discovery source returned a mismatched provider id".to_string();
                updates.push(CatalogUpdate::Failed {
                    provider,
                    attempt_token,
                    binding_hash,
                    error,
                });
            }
            Err(_error) => {
                updates.push(CatalogUpdate::Failed {
                    provider,
                    attempt_token,
                    binding_hash,
                    // Source errors may contain provider-controlled response
                    // bodies, endpoints, query tokens, or credential-chain
                    // details. Receipts already identify the provider; keep
                    // durable/public telemetry deliberately generic.
                    error: "model discovery request failed; check provider configuration and connectivity, then retry"
                        .to_string(),
                });
            }
        }
    }

    let commit = ModelsCatalog::update_at_if_changed_with_clear_epoch(
        catalog_path,
        move |catalog, clear_epoch| {
            let mut outcomes = Vec::new();
            let mut changed = false;
            for update in updates {
                let (provider, attempt_token, binding_hash) = match &update {
                    CatalogUpdate::Refreshed {
                        provider,
                        attempt_token,
                        binding_hash,
                        ..
                    }
                    | CatalogUpdate::Failed {
                        provider,
                        attempt_token,
                        binding_hash,
                        ..
                    } => (*provider, attempt_token, binding_hash),
                };
                let is_current = catalog
                    .provider(provider)
                    .and_then(|entry| entry.refresh_attempt.as_ref())
                    .is_some_and(|attempt| {
                        attempt.token.as_str() == attempt_token.as_str()
                            && attempt.binding_hash.as_str() == binding_hash.as_str()
                            && attempt.clear_epoch.as_deref() == Some(clear_epoch)
                    });
                if !is_current {
                    outcomes.push(CatalogApplyOutcome::Superseded(provider));
                    continue;
                }
                match update {
                    CatalogUpdate::Refreshed {
                        binding_hash,
                        result,
                        ..
                    } => {
                        catalog.upsert_bound(
                            result.provider,
                            result.origin,
                            result.models,
                            binding_hash,
                        );
                        changed = true;
                        outcomes.push(CatalogApplyOutcome::Refreshed(provider));
                    }
                    CatalogUpdate::Failed {
                        provider, error, ..
                    } => {
                        catalog.record_error(provider, error);
                        changed = true;
                        outcomes.push(CatalogApplyOutcome::Failed(provider));
                    }
                }
            }
            Ok(if changed {
                CatalogMutation::Commit(outcomes)
            } else {
                CatalogMutation::Unchanged(outcomes)
            })
        },
    )?;
    for outcome in commit.value {
        match outcome {
            CatalogApplyOutcome::Refreshed(provider) => report.refreshed.push(provider.to_string()),
            CatalogApplyOutcome::Failed(provider) => report.failed.push(provider.to_string()),
            CatalogApplyOutcome::Superseded(provider) => {
                report.superseded.push(provider.to_string())
            }
        }
    }
    report.catalog_generation = commit.generation;
    report.catalog_hash = commit.content_hash;
    report.catalog_changed = commit.changed;
    Ok(report)
}

fn catalog_snapshot(catalog_path: &Path) -> Result<Option<(u64, String, bool)>> {
    match ModelsCatalog::load_snapshot_strict_from(catalog_path) {
        Ok(Some(snapshot)) => Ok(Some((
            snapshot.catalog.generation,
            snapshot.content_hash,
            false,
        ))),
        Ok(None) => Ok(None),
        Err(strict_error) => {
            if !catalog_path.exists() {
                return Err(strict_error);
            }
            let commit = ModelsCatalog::update_at(catalog_path, |_| Ok(())).with_context(|| {
                format!("migrate existing model catalog after strict read failed: {strict_error:#}")
            })?;
            Ok(Some((commit.generation, commit.content_hash, true)))
        }
    }
}

fn mint_refresh_token() -> Result<String> {
    let mut token = [0u8; 32];
    getrandom::getrandom(&mut token).context("mint models catalog refresh token")?;
    Ok(hex::encode(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::init::ProviderKind;
    use crate::config::FreedomConfig;
    use crate::config::inference::{HemisphereSlot, InferenceProvider, InferenceTopology};
    use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
    use crate::models::sources::FetchResult;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;

    fn base_config() -> FreedomConfig {
        let mut config = FreedomConfig {
            operator_id: Some("test".into()),
            ..Default::default()
        };
        config.profile.learn_provider = None;
        config
    }

    fn runnable_binding(plan: SourcePlan, provider: &str) -> String {
        let (_, sources) = plan.into_execution();
        sources
            .into_iter()
            .find(|(candidate, _, _)| *candidate == provider)
            .map(|(_, binding_hash, _)| binding_hash)
            .unwrap_or_else(|| panic!("missing runnable catalog source `{provider}`"))
    }

    fn is_sha256(value: &str) -> bool {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    /// Drop-in mock source used by orchestrator tests — never touches
    /// the network.
    struct MockSource {
        name: &'static str,
        result: std::sync::Mutex<Option<Result<FetchResult>>>,
    }

    impl MockSource {
        fn ok(name: &'static str, ids: Vec<&'static str>) -> Self {
            let models = ids.into_iter().map(ModelEntry::new).collect();
            Self {
                name,
                result: std::sync::Mutex::new(Some(Ok(FetchResult {
                    provider: name,
                    origin: SourceOrigin::Api,
                    models,
                }))),
            }
        }

        fn err(name: &'static str, msg: &str) -> Self {
            Self {
                name,
                result: std::sync::Mutex::new(Some(Err(anyhow::anyhow!(msg.to_string())))),
            }
        }
    }

    #[async_trait]
    impl ModelSource for MockSource {
        fn provider(&self) -> &'static str {
            self.name
        }

        async fn fetch(&self) -> Result<FetchResult> {
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow::anyhow!("already consumed")))
        }
    }

    struct CountingSource {
        name: &'static str,
        fetches: Arc<AtomicUsize>,
    }

    struct DelayedSource {
        name: &'static str,
        model: &'static str,
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl ModelSource for DelayedSource {
        fn provider(&self) -> &'static str {
            self.name
        }

        async fn fetch(&self) -> Result<FetchResult> {
            self.started.notify_one();
            self.release.notified().await;
            Ok(FetchResult {
                provider: self.name,
                origin: SourceOrigin::Api,
                models: vec![ModelEntry::new(self.model)],
            })
        }
    }

    #[async_trait]
    impl ModelSource for CountingSource {
        fn provider(&self) -> &'static str {
            self.name
        }

        async fn fetch(&self) -> Result<FetchResult> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            Ok(FetchResult {
                provider: self.name,
                origin: SourceOrigin::Api,
                models: vec![ModelEntry::new(format!("{}-model", self.name))],
            })
        }
    }

    #[tokio::test]
    async fn empty_sources_returns_empty_report_no_file_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let report = discover_with_sources(&path, vec![]).await.unwrap();
        assert!(report.refreshed.is_empty());
        assert!(report.failed.is_empty());
        assert!(!report.catalog_changed);
        // Catalog file should NOT have been created.
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn empty_plan_observes_v2_snapshot_and_migrates_v1_fail_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        std::fs::write(&path, br#"{"version":1,"ttl_secs":3600,"providers":{}}"#).unwrap();

        let report = discover_with_sources(&path, vec![]).await.unwrap();
        assert!(report.catalog_changed);
        assert_eq!(report.catalog_generation, Some(1));
        assert!(report.catalog_hash.as_deref().is_some_and(is_sha256));
        let migrated = ModelsCatalog::load_strict_from(&path).unwrap().unwrap();
        assert_eq!(migrated.version, crate::models::catalog::CATALOG_VERSION);
        assert_eq!(migrated.generation, 1);

        let original = b"{ not valid json";
        std::fs::write(&path, original).unwrap();
        assert!(discover_with_sources(&path, vec![]).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[tokio::test]
    async fn all_sources_succeed_populates_catalog() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let sources: Vec<Box<dyn ModelSource>> = vec![
            Box::new(MockSource::ok("anthropic_api", vec!["claude-opus-4-7"])),
            Box::new(MockSource::ok("openai_api", vec!["gpt-5.5", "gpt-5.4"])),
        ];
        let report = discover_with_sources(&path, sources).await.unwrap();
        assert_eq!(report.refreshed.len(), 2);
        assert!(report.failed.is_empty());
        assert!(report.catalog_changed);
        assert_eq!(report.catalog_generation, Some(2));
        assert!(report.catalog_hash.as_deref().is_some_and(is_sha256));

        let reloaded = ModelsCatalog::load_from(&path);
        assert_eq!(reloaded.provider("anthropic_api").unwrap().models.len(), 1);
        assert_eq!(reloaded.provider("openai_api").unwrap().models.len(), 2);
    }

    #[tokio::test]
    async fn one_failure_does_not_block_other_sources() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let sources: Vec<Box<dyn ModelSource>> = vec![
            Box::new(MockSource::err("anthropic_api", "401 unauthorized")),
            Box::new(MockSource::ok("openai_api", vec!["gpt-5.5"])),
        ];
        let report = discover_with_sources(&path, sources).await.unwrap();
        assert_eq!(report.failed, vec!["anthropic_api".to_string()]);
        assert_eq!(report.refreshed, vec!["openai_api".to_string()]);

        let reloaded = ModelsCatalog::load_from(&path);
        let failed = reloaded.provider("anthropic_api").unwrap();
        assert!(failed.models.is_empty());
        assert_eq!(
            failed.last_error.as_deref(),
            Some(
                "model discovery request failed; check provider configuration and connectivity, then retry"
            )
        );
        assert!(!format!("{failed:?}").contains("401 unauthorized"));
    }

    #[tokio::test]
    async fn prior_models_preserved_when_refresh_fails() {
        // Operator's wizard select must keep working through a
        // transient API outage. Refresh failures stamp last_error
        // but never wipe the previous catalog.
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");

        // Seed: one good refresh.
        let sources_good: Vec<Box<dyn ModelSource>> = vec![Box::new(MockSource::ok(
            "openai_api",
            vec!["gpt-5.5", "gpt-5.4"],
        ))];
        discover_with_sources(&path, sources_good).await.unwrap();

        // Second pass: transient failure on the same provider.
        let sources_fail: Vec<Box<dyn ModelSource>> = vec![Box::new(MockSource::err(
            "openai_api",
            "503 service unavailable",
        ))];
        discover_with_sources(&path, sources_fail).await.unwrap();

        let reloaded = ModelsCatalog::load_from(&path);
        let p = reloaded.provider("openai_api").unwrap();
        assert_eq!(p.models.len(), 2, "prior models preserved through failure");
        assert!(p.last_error.is_some(), "last_error stamped");
    }

    #[tokio::test]
    async fn superseded_slow_fetch_cannot_overwrite_newer_provider_attempt() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let mut old_plan = SourcePlan::default();
        old_plan.push(
            OPENAI_CATALOG_PROVIDER,
            PlannedSourceState::Runnable {
                source: Box::new(DelayedSource {
                    name: OPENAI_CATALOG_PROVIDER,
                    model: "old-model",
                    started: Arc::clone(&started),
                    release: Arc::clone(&release),
                }),
                binding_hash: "a".repeat(64),
            },
        );
        let old_path = path.clone();
        let old_run = tokio::spawn(async move { discover_with_plan(&old_path, old_plan).await });
        started.notified().await;

        let mut new_plan = SourcePlan::default();
        new_plan.push(
            OPENAI_CATALOG_PROVIDER,
            PlannedSourceState::Runnable {
                source: Box::new(MockSource::ok(OPENAI_CATALOG_PROVIDER, vec!["new-model"])),
                binding_hash: "b".repeat(64),
            },
        );
        let new_report = discover_with_plan(&path, new_plan).await.unwrap();
        assert_eq!(new_report.refreshed, vec![OPENAI_CATALOG_PROVIDER]);
        let winning_generation = new_report.catalog_generation;
        let winning_hash = new_report.catalog_hash.clone();

        release.notify_one();
        let old_report = old_run.await.unwrap().unwrap();
        assert!(old_report.failed.is_empty());
        assert_eq!(old_report.superseded, vec![OPENAI_CATALOG_PROVIDER]);
        assert!(!old_report.catalog_changed);
        assert_eq!(old_report.catalog_generation, winning_generation);
        assert_eq!(old_report.catalog_hash, winning_hash);
        let catalog = ModelsCatalog::load_strict_from(&path).unwrap().unwrap();
        assert_eq!(Some(catalog.generation), winning_generation);
        let provider = catalog.provider(OPENAI_CATALOG_PROVIDER).unwrap();
        assert_eq!(provider.binding_hash.as_ref().unwrap(), &"b".repeat(64));
        assert_eq!(provider.models[0].id, "new-model");
        assert!(provider.refresh_attempt.is_none());
    }

    #[tokio::test]
    async fn clear_supersedes_in_flight_fetch_without_resurrecting_catalog() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let mut plan = SourcePlan::default();
        plan.push(
            OPENAI_CATALOG_PROVIDER,
            PlannedSourceState::Runnable {
                source: Box::new(DelayedSource {
                    name: OPENAI_CATALOG_PROVIDER,
                    model: "late-model",
                    started: Arc::clone(&started),
                    release: Arc::clone(&release),
                }),
                binding_hash: "a".repeat(64),
            },
        );

        let refresh_path = path.clone();
        let refresh = tokio::spawn(async move { discover_with_plan(&refresh_path, plan).await });
        started.notified().await;
        assert!(ModelsCatalog::clear_at(&path).unwrap());
        assert!(!path.exists());

        release.notify_one();
        let report = refresh.await.unwrap().unwrap();
        assert_eq!(report.superseded, vec![OPENAI_CATALOG_PROVIDER]);
        assert!(report.refreshed.is_empty());
        assert!(report.failed.is_empty());
        assert!(!report.catalog_changed);
        assert_eq!(report.catalog_generation, None);
        assert_eq!(report.catalog_hash, None);
        assert!(!path.exists(), "late completion must not recreate catalog");
    }

    #[test]
    fn build_sources_empty_config_returns_no_sources() {
        let config = base_config();
        let sources = build_sources_from_config(&config);
        assert!(sources.is_empty());
    }

    #[test]
    fn build_sources_recognises_claude_cli_top_level() {
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::ClaudeCli);
        config.provider_key = Some(crate::secret::SecretString::new("sk-ant".into()));
        let (_, sources) = build_sources_from_config(&config).into_execution();
        let names: Vec<_> = sources.iter().map(|(provider, _, _)| *provider).collect();
        assert!(names.contains(&"anthropic_api"));
    }

    #[test]
    fn build_sources_recognises_openai_per_hemisphere() {
        let mut config = base_config();
        config.inference = InferenceTopology {
            mode: crate::config::inference::TopologyMode::Custom,
            left: HemisphereSlot {
                provider: Some(InferenceProvider::OpenAi),
                key: Some(crate::secret::SecretString::new("sk-test".into())),
                ..Default::default()
            },
            ..Default::default()
        };
        let (_, sources) = build_sources_from_config(&config).into_execution();
        let names: Vec<_> = sources.iter().map(|(provider, _, _)| *provider).collect();
        assert!(names.contains(&"openai_api"));
    }

    #[test]
    fn build_sources_recognises_gemini_per_hemisphere() {
        let mut config = base_config();
        config.inference = InferenceTopology {
            mode: crate::config::inference::TopologyMode::Custom,
            right: HemisphereSlot {
                provider: Some(InferenceProvider::Gemini),
                key: Some(crate::secret::SecretString::new("AIza-test".into())),
                ..Default::default()
            },
            ..Default::default()
        };
        let (_, sources) = build_sources_from_config(&config).into_execution();
        let names: Vec<_> = sources.iter().map(|(provider, _, _)| *provider).collect();
        assert!(names.contains(&"gemini_api"));
    }

    #[test]
    fn missing_anthropic_rest_key_cannot_fall_through_to_configured_cli_route() {
        let mut config = base_config();
        config.inference = InferenceTopology {
            mode: crate::config::inference::TopologyMode::Custom,
            left: HemisphereSlot {
                provider: Some(InferenceProvider::AnthropicApi),
                key: None,
                ..Default::default()
            },
            right: HemisphereSlot {
                provider: Some(InferenceProvider::ClaudeCli),
                ..Default::default()
            },
            ..Default::default()
        };

        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(report.configured, vec![ANTHROPIC_CATALOG_PROVIDER]);
        assert_eq!(
            report.configuration_failures,
            vec![ANTHROPIC_CATALOG_PROVIDER]
        );
        assert!(sources.is_empty());
    }

    #[test]
    fn build_sources_ignores_recursive_slots_until_runtime_depth_exceeds_one() {
        let mut config = base_config();
        config.fallback.chain.push(HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            key: Some(crate::secret::SecretString::new("sk-fallback".into())),
            ..Default::default()
        });
        let mut sub_slots = crate::config::inference::SubHemisphereSlots::default();
        sub_slots.right = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            key: Some(crate::secret::SecretString::new("AIza-recursive".into())),
            ..Default::default()
        };
        config
            .inference
            .hemisphere_sub_slots
            .insert(crate::config::inference::HemisphereRole::Left, sub_slots);

        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(report.configured, vec![OPENAI_CATALOG_PROVIDER]);
        assert_eq!(sources.len(), 1);

        config.inference.hemisphere_council_depth =
            crate::config::inference::HemisphereCouncilDepth::new_clamped(2).0;
        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(
            report.configured,
            vec![OPENAI_CATALOG_PROVIDER, GEMINI_CATALOG_PROVIDER]
        );
        assert_eq!(
            sources
                .iter()
                .map(|(provider, _, _)| *provider)
                .collect::<Vec<_>>(),
            vec![OPENAI_CATALOG_PROVIDER, GEMINI_CATALOG_PROVIDER]
        );
    }

    #[test]
    fn source_plan_never_reuses_another_vendors_top_level_key() {
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::AnthropicApi);
        config.provider_key = Some(crate::secret::SecretString::new("sk-anthropic".into()));
        config.inference.mode = crate::config::inference::TopologyMode::Custom;
        config.inference.left.provider = Some(InferenceProvider::OpenAi);

        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(
            report.configured,
            vec![ANTHROPIC_CATALOG_PROVIDER, OPENAI_CATALOG_PROVIDER]
        );
        assert_eq!(report.skipped_no_creds, vec![OPENAI_CATALOG_PROVIDER]);
        assert_eq!(
            sources
                .iter()
                .map(|(provider, _, _)| *provider)
                .collect::<Vec<_>>(),
            vec![ANTHROPIC_CATALOG_PROVIDER]
        );
    }

    #[test]
    fn source_plan_reports_auxiliary_provider_without_vendor_credentials() {
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::AnthropicApi);
        config.provider_key = Some(crate::secret::SecretString::new("sk-anthropic".into()));
        config.inference.utility_provider = Some(InferenceProvider::Gemini);

        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(
            report.configured,
            vec![ANTHROPIC_CATALOG_PROVIDER, GEMINI_CATALOG_PROVIDER]
        );
        assert_eq!(report.skipped_no_creds, vec![GEMINI_CATALOG_PROVIDER]);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].0, ANTHROPIC_CATALOG_PROVIDER);
    }

    #[test]
    fn auxiliary_routes_reuse_only_same_vendor_credentials() {
        let mut same_vendor = base_config();
        same_vendor.provider_kind = Some(ProviderKind::OpenaiApi);
        same_vendor.provider_key = Some(crate::secret::SecretString::new("sk-openai".into()));
        same_vendor.inference.utility_provider = Some(InferenceProvider::OpenAi);
        let (report, sources) = build_sources_from_config(&same_vendor).into_execution();
        assert!(report.skipped_no_creds.is_empty());
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].0, OPENAI_CATALOG_PROVIDER);

        let mut cross_vendor = same_vendor.clone();
        cross_vendor.inference.utility_provider = None;
        cross_vendor.inference.teacher_provider = Some(InferenceProvider::Gemini);
        cross_vendor.profile.learn_provider = Some("gemini_api".into());
        let (report, _) = build_sources_from_config(&cross_vendor).into_execution();
        assert_eq!(report.skipped_no_creds, vec![GEMINI_CATALOG_PROVIDER]);
    }

    #[test]
    fn invalid_learn_and_rejected_local_teacher_are_explicit_failures() {
        let mut invalid_learn = base_config();
        invalid_learn.profile.learn_provider = Some("not_a_provider".into());
        let (report, sources) = build_sources_from_config(&invalid_learn).into_execution();
        assert_eq!(report.configured, vec![INVALID_CATALOG_PROVIDER]);
        assert_eq!(
            report.configuration_failures,
            vec![INVALID_CATALOG_PROVIDER]
        );
        assert!(sources.is_empty());

        let mut local_teacher = base_config();
        local_teacher.inference.teacher_provider = Some(InferenceProvider::LocalQwen);
        let (report, sources) = build_sources_from_config(&local_teacher).into_execution();
        assert_eq!(report.configured, vec!["local_qwen"]);
        assert_eq!(report.configuration_failures, vec!["local_qwen"]);
        assert!(sources.is_empty());
    }

    #[test]
    fn unwired_profile_provider_does_not_claim_an_effective_catalog_route() {
        let mut config = base_config();
        config.inference.profile_provider = Some(InferenceProvider::Gemini);
        let plan = build_sources_from_config(&config);
        assert!(plan.is_empty());
    }

    #[test]
    fn source_plan_uses_per_slot_openai_compat_endpoint() {
        let mut config = base_config();
        config.inference.mode = crate::config::inference::TopologyMode::Custom;
        config.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            endpoint: Some("http://127.0.0.1:11434/v1".into()),
            ..Default::default()
        };

        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(report.configured, vec![OPENAI_COMPAT_CATALOG_PROVIDER]);
        assert!(report.configuration_failures.is_empty());
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].0, OPENAI_COMPAT_CATALOG_PROVIDER);
    }

    #[test]
    fn catalog_binding_tracks_effective_key_endpoint_region_and_cli_binary() {
        let mut openai = base_config();
        openai.provider_kind = Some(ProviderKind::OpenaiApi);
        openai.provider_key = Some(crate::secret::SecretString::new("sk-one".into()));
        let default_endpoint =
            runnable_binding(build_sources_from_config(&openai), OPENAI_CATALOG_PROVIDER);
        openai.provider_endpoint = Some("https://api.openai.com/v1".into());
        let explicit_default =
            runnable_binding(build_sources_from_config(&openai), OPENAI_CATALOG_PROVIDER);
        assert_eq!(default_endpoint, explicit_default);
        openai.provider_key = Some(crate::secret::SecretString::new("sk-two".into()));
        assert_ne!(
            explicit_default,
            runnable_binding(build_sources_from_config(&openai), OPENAI_CATALOG_PROVIDER)
        );

        let mut claude = base_config();
        claude.provider_kind = Some(ProviderKind::ClaudeCli);
        let default_binary = runnable_binding(
            build_sources_from_config(&claude),
            ANTHROPIC_CATALOG_PROVIDER,
        );
        claude.provider_binary = Some("/opt/neoth/claude-custom".into());
        assert_ne!(
            default_binary,
            runnable_binding(
                build_sources_from_config(&claude),
                ANTHROPIC_CATALOG_PROVIDER
            )
        );

        assert_ne!(
            catalog_binding_hash(BEDROCK_CATALOG_PROVIDER, &[("region", "us-east-1")]),
            catalog_binding_hash(BEDROCK_CATALOG_PROVIDER, &[("region", "eu-west-1")])
        );
    }

    #[test]
    fn single_mode_ignores_inactive_slots_and_never_borrows_their_compat_key() {
        let mut config = base_config();
        config.inference.default_slot = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            endpoint: Some("http://127.0.0.1:11434/v1".into()),
            ..Default::default()
        };
        config.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            endpoint: Some("http://127.0.0.1:11434/v1".into()),
            key: Some(crate::secret::SecretString::new("inactive-key".into())),
            ..Default::default()
        };

        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(report.configured, vec![OPENAI_COMPAT_CATALOG_PROVIDER]);
        assert!(report.configuration_failures.is_empty());
        assert_eq!(sources.len(), 1);
    }

    #[test]
    fn compat_endpoint_and_key_are_atomic_and_conflicting_slots_fail_closed() {
        let mut config = base_config();
        config.inference.mode = crate::config::inference::TopologyMode::Custom;
        config.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            endpoint: Some("http://127.0.0.1:11434/v1".into()),
            ..Default::default()
        };
        config.inference.right = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            endpoint: Some("http://127.0.0.1:11434/v1/models".into()),
            key: Some(crate::secret::SecretString::new("slot-b-key".into())),
            ..Default::default()
        };

        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(report.configured, vec![OPENAI_COMPAT_CATALOG_PROVIDER]);
        assert_eq!(
            report.configuration_failures,
            vec![OPENAI_COMPAT_CATALOG_PROVIDER]
        );
        assert!(sources.is_empty());
    }

    #[test]
    fn equivalent_compat_endpoints_and_credentials_coalesce() {
        let mut config = base_config();
        config.inference.mode = crate::config::inference::TopologyMode::Custom;
        for slot in [&mut config.inference.left, &mut config.inference.right] {
            slot.provider = Some(InferenceProvider::OpenAiCompat);
            slot.key = Some(crate::secret::SecretString::new("same-key".into()));
        }
        config.inference.left.endpoint = Some("http://127.0.0.1:11434/v1/".into());
        config.inference.right.endpoint = Some("http://127.0.0.1:11434/v1/models#ignored".into());

        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert!(report.configuration_failures.is_empty());
        assert_eq!(report.configured, vec![OPENAI_COMPAT_CATALOG_PROVIDER]);
        assert_eq!(sources.len(), 1);
    }

    #[test]
    fn conflicting_gemini_credentials_never_collapse_into_one_catalog() {
        let mut config = base_config();
        config.inference.mode = crate::config::inference::TopologyMode::Custom;
        config.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            key: Some(crate::secret::SecretString::new("gemini-key-a".into())),
            ..Default::default()
        };
        config.inference.right = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            key: Some(crate::secret::SecretString::new("gemini-key-b".into())),
            ..Default::default()
        };

        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(report.configured, vec![GEMINI_CATALOG_PROVIDER]);
        assert_eq!(report.configuration_failures, vec![GEMINI_CATALOG_PROVIDER]);
        assert!(sources.is_empty());
    }

    #[test]
    fn mixed_missing_and_present_anthropic_api_keys_fail_closed() {
        let mut config = base_config();
        config.inference.mode = crate::config::inference::TopologyMode::Custom;
        config.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::AnthropicApi),
            key: Some(crate::secret::SecretString::new("anthropic-key".into())),
            ..Default::default()
        };
        config.inference.right = HemisphereSlot {
            provider: Some(InferenceProvider::AnthropicApi),
            key: None,
            ..Default::default()
        };

        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(report.configured, vec![ANTHROPIC_CATALOG_PROVIDER]);
        assert_eq!(
            report.configuration_failures,
            vec![ANTHROPIC_CATALOG_PROVIDER]
        );
        assert!(sources.is_empty());
    }

    #[test]
    fn stale_only_never_masks_missing_configuration_or_credentials() {
        let mut catalog = ModelsCatalog::default();
        catalog.providers.insert(
            OPENAI_CATALOG_PROVIDER.into(),
            crate::models::catalog::ProviderCatalog {
                fetched_at_unix: 1_000_000,
                ..Default::default()
            },
        );
        catalog.providers.insert(
            OPENAI_COMPAT_CATALOG_PROVIDER.into(),
            crate::models::catalog::ProviderCatalog {
                fetched_at_unix: 1_000_000,
                ..Default::default()
            },
        );

        let mut no_key = base_config();
        no_key.provider_kind = Some(ProviderKind::OpenaiApi);
        let (report, _) = build_sources_from_config(&no_key)
            .stale_only(&catalog, 1_000_001)
            .into_execution();
        assert_eq!(report.skipped_no_creds, vec![OPENAI_CATALOG_PROVIDER]);
        assert!(report.fresh.is_empty());

        let mut no_endpoint = base_config();
        no_endpoint.provider_kind = Some(ProviderKind::OpenaiCompat);
        let (report, _) = build_sources_from_config(&no_endpoint)
            .stale_only(&catalog, 1_000_001)
            .into_execution();
        assert_eq!(
            report.configuration_failures,
            vec![OPENAI_COMPAT_CATALOG_PROVIDER]
        );
        assert!(report.fresh.is_empty());
    }

    #[test]
    fn unsupported_runtime_adapter_is_an_explicit_terminal_outcome() {
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::Cohere);
        let (report, sources) = build_sources_from_config(&config).into_execution();
        assert_eq!(report.configured, vec!["cohere_api"]);
        assert_eq!(report.unsupported, vec!["cohere_api"]);
        assert!(sources.is_empty());
    }

    #[test]
    fn discovery_is_bound_to_instance_consent() {
        let home = tempdir().unwrap();
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::OpenaiApi);
        config.provider_key = Some(crate::secret::SecretString::new("sk-test".into()));

        let (blocked, sources) = build_sources_from_config_at(&config, home.path())
            .unwrap()
            .into_execution();
        assert_eq!(blocked.blocked_no_consent, vec![OPENAI_CATALOG_PROVIDER]);
        assert!(sources.is_empty());

        crate::consent::grant(home.path(), ProviderKind::OpenaiApi).unwrap();
        let (granted, sources) = build_sources_from_config_at(&config, home.path())
            .unwrap()
            .into_execution();
        assert!(granted.blocked_no_consent.is_empty());
        assert_eq!(sources.len(), 1);
    }

    #[test]
    fn production_catalog_bindings_are_stable_per_instance_and_differ_across_instances() {
        let first_home = tempdir().unwrap();
        let second_home = tempdir().unwrap();
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::OpenaiApi);
        config.provider_key = Some(crate::secret::SecretString::new("sk-same-route".into()));
        crate::consent::grant(first_home.path(), ProviderKind::OpenaiApi).unwrap();
        crate::consent::grant(second_home.path(), ProviderKind::OpenaiApi).unwrap();

        let first = runnable_binding(
            build_sources_from_config_at(&config, first_home.path()).unwrap(),
            OPENAI_CATALOG_PROVIDER,
        );
        let first_again = runnable_binding(
            build_sources_from_config_at(&config, first_home.path()).unwrap(),
            OPENAI_CATALOG_PROVIDER,
        );
        let second = runnable_binding(
            build_sources_from_config_at(&config, second_home.path()).unwrap(),
            OPENAI_CATALOG_PROVIDER,
        );

        assert!(is_sha256(&first));
        assert_eq!(first, first_again, "one instance must bind routes stably");
        assert_ne!(
            first, second,
            "identical credentials must not have a cross-instance fingerprint"
        );
    }

    #[test]
    fn fallback_discovery_never_egresses_without_instance_consent() {
        let home = tempdir().unwrap();
        let mut config = base_config();
        config.fallback.chain.push(HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            key: Some(crate::secret::SecretString::new("sk-fallback".into())),
            ..Default::default()
        });

        let (excluded, sources) = build_sources_from_config_at(&config, home.path())
            .unwrap()
            .into_execution();
        assert!(excluded.configured.is_empty());
        assert!(excluded.blocked_no_consent.is_empty());
        assert!(sources.is_empty());

        crate::consent::grant(home.path(), ProviderKind::OpenaiApi).unwrap();
        let (granted, sources) = build_sources_from_config_at(&config, home.path())
            .unwrap()
            .into_execution();
        assert!(granted.blocked_no_consent.is_empty());
        assert_eq!(sources.len(), 1);

        config.fallback.max_hops = 0;
        let (disabled, sources) = build_sources_from_config_at(&config, home.path())
            .unwrap()
            .into_execution();
        assert!(disabled.configured.is_empty());
        assert!(sources.is_empty());
    }

    #[test]
    fn stale_only_treats_configured_provider_missing_from_catalog_as_runnable() {
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::OpenaiApi);
        config.provider_key = Some(crate::secret::SecretString::new("sk-test".into()));
        let plan =
            build_sources_from_config(&config).stale_only(&ModelsCatalog::default(), 1_000_000);
        let (report, runnable) = plan.into_execution();
        assert_eq!(report.configured, vec![OPENAI_CATALOG_PROVIDER]);
        assert!(report.fresh.is_empty());
        assert_eq!(
            runnable
                .iter()
                .map(|(provider, _, _)| *provider)
                .collect::<Vec<_>>(),
            vec![OPENAI_CATALOG_PROVIDER]
        );
    }

    #[tokio::test]
    async fn stale_only_fetches_stale_provider_and_never_fetches_fresh_provider() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.ttl_secs = Some(1_000);
        catalog.providers.insert(
            ANTHROPIC_CATALOG_PROVIDER.into(),
            crate::models::catalog::ProviderCatalog {
                fetched_at_unix: 1_000_000,
                binding_hash: Some(catalog_binding_hmac(
                    b"neoth-injected-catalog-source-v1",
                    ANTHROPIC_CATALOG_PROVIDER,
                    &[("source", "injected")],
                )),
                ..Default::default()
            },
        );
        catalog.providers.insert(
            OPENAI_CATALOG_PROVIDER.into(),
            crate::models::catalog::ProviderCatalog {
                fetched_at_unix: 1,
                ..Default::default()
            },
        );
        catalog.save().unwrap();

        let anthropic_fetches = Arc::new(AtomicUsize::new(0));
        let openai_fetches = Arc::new(AtomicUsize::new(0));
        let sources: Vec<Box<dyn ModelSource>> = vec![
            Box::new(CountingSource {
                name: ANTHROPIC_CATALOG_PROVIDER,
                fetches: Arc::clone(&anthropic_fetches),
            }),
            Box::new(CountingSource {
                name: OPENAI_CATALOG_PROVIDER,
                fetches: Arc::clone(&openai_fetches),
            }),
        ];
        let plan = SourcePlan::from_sources(sources).stale_only(&catalog, 1_000_500);
        let report = discover_with_plan(&path, plan).await.unwrap();

        assert_eq!(report.configured, vec!["anthropic_api", "openai_api"]);
        assert_eq!(report.fresh, vec!["anthropic_api"]);
        assert_eq!(report.refreshed, vec!["openai_api"]);
        assert_eq!(anthropic_fetches.load(Ordering::SeqCst), 0);
        assert_eq!(openai_fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn source_plan_reports_missing_credentials_without_silent_omission() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::OpenaiApi);

        let report = discover_with_plan(&path, build_sources_from_config(&config))
            .await
            .unwrap();
        assert_eq!(report.configured, vec![OPENAI_CATALOG_PROVIDER]);
        assert_eq!(report.skipped_no_creds, vec![OPENAI_CATALOG_PROVIDER]);
        assert!(report.refreshed.is_empty());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn source_plan_reports_bedrock_credential_resolution_failure_without_error_text() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::AwsBedrock);
        let plan = build_sources_with_bedrock_resolver(&config, |_, _| {
            anyhow::bail!("secret credential resolver diagnostic")
        });

        let report = discover_with_plan(&path, plan).await.unwrap();
        assert_eq!(report.configured, vec![BEDROCK_CATALOG_PROVIDER]);
        assert_eq!(report.credential_failures, vec![BEDROCK_CATALOG_PROVIDER]);
        assert!(!format!("{report:?}").contains("secret credential resolver diagnostic"));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn source_plan_reports_missing_openai_compat_endpoint() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::OpenaiCompat);

        let report = discover_with_plan(&path, build_sources_from_config(&config))
            .await
            .unwrap();
        assert_eq!(report.configured, vec![OPENAI_COMPAT_CATALOG_PROVIDER]);
        assert_eq!(
            report.configuration_failures,
            vec![OPENAI_COMPAT_CATALOG_PROVIDER]
        );
        assert!(!path.exists());
    }

    #[test]
    fn summary_line_renders_counts() {
        let mut report = DiscoveryReport::default();
        report.refreshed = vec!["a".into(), "b".into()];
        report.failed = vec!["c".into()];
        report.skipped_no_creds = vec!["d".into()];
        report.credential_failures = vec!["e".into()];
        report.configuration_failures = vec!["f".into()];
        let line = report.summary_line();
        assert!(line.contains("2 refreshed"));
        assert!(line.contains("1 failed"));
        assert!(line.contains("1 skipped"));
        assert!(line.contains("1 credential failures"));
        assert!(line.contains("1 configuration failures"));
    }
}
