//! Permission-gated, bounded DOI transport for the closed citation provider set.
//!
//! This layer receives a prevalidated [`CitationQuery`] from `citation_lookup`.
//! It never accepts a provider URL, never fans out, and uses the core's
//! query-aware live constructor before it reports a record.  Cache policy stays
//! in the core; [`lookup_cache_first`] makes its required pre-egress order
//! explicit for the future CLI and GUI ingress.

use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde_json::Value;

use crate::providers::http_client;
use crate::tools::citation_consent::{CitationConsentPreflight, ConsumedGuiCitationLookupApproval};
use crate::tools::citation_lookup::{
    CitationCache, CitationLookupResult, CitationLookupState, CitationProvider, CitationQuery,
    CitationRecord, MAX_PROVIDER_RESPONSE_BYTES, REQUEST_TIMEOUT_SECS, validate_claim,
};
use crate::tools::external_http::{
    ExternalHttpAuthorizer, ExternalHttpRequest, ExternalHttpResponse, ExternalHttpSurface,
    ExternalHttpTransportFailure, ExternalHttpTransportRequest,
};

/// Cache persistence is a separate outcome from a live provider result.  A
/// failed private write must remain visible to the caller, but it must never
/// erase a record that the core has already validated for this exact query and
/// claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationCacheWriteState {
    NotAttempted,
    Stored,
    WriteFailed,
}

/// The cache read is separately typed so a caller can distinguish a normal
/// miss from a degraded private-cache boundary without surfacing I/O details.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationCacheReadState {
    NotConfigured,
    Hit,
    Miss,
    ReadFailed,
}

/// The cache-first facade keeps the closed core lookup state and the separate,
/// data-free cache persistence diagnostic together for CLI/GUI projection.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CitationCacheFirstReport {
    pub lookup: CitationLookupResult,
    pub cache_read: CitationCacheReadState,
    pub cache_write: CitationCacheWriteState,
}

/// Unforgeable, crate-private evidence that the cache-first citation facade
/// has reached a valid, non-offline live miss.  Only this module can create
/// it, so GUI consent cannot mint a challenge for an input failure, cache hit,
/// or offline result.
pub(crate) struct GuiCitationLiveMiss {
    query: CitationQuery,
    normalized_claim: String,
}

impl GuiCitationLiveMiss {
    /// Consent must use the same exact normalized lookup selected by this
    /// cache decision.  The capability's fields remain module-private so no
    /// sibling module can construct or retarget it.
    pub(crate) fn matches_lookup(&self, query: &CitationQuery, claim: &str) -> bool {
        &self.query == query
            && validate_claim(claim)
                .map(|normalized_claim| normalized_claim == self.normalized_claim)
                .unwrap_or(false)
    }
}

/// GUI preflight is either a terminal cache-first outcome or the consent-core
/// answer for the one remaining live-miss path.  It intentionally does not
/// expose the live-miss capability to the GUI/CLI caller.
pub(crate) enum GuiCitationPreflightCacheFirst {
    Terminal(Box<CitationCacheFirstReport>),
    Consent {
        cache_read: CitationCacheReadState,
        preflight: CitationConsentPreflight,
    },
}

enum CitationCacheFirstDecision {
    Terminal(Box<CitationCacheFirstReport>),
    Live {
        cache_read: CitationCacheReadState,
        normalized_claim: String,
    },
}

/// A valid provider `Retry-After` is capped so an upstream response cannot
/// create an effectively permanent local outage.  We support only the numeric
/// delta-seconds form: HTTP-date values depend on another clock and therefore
/// deliberately become a typed rate limit without a process cooldown.
const MAX_RETRY_AFTER_SECS: u64 = 60 * 60;

/// There is one async permit per provider.  A caller selects exactly one
/// provider in its `CitationQuery`; holding this permit prevents concurrent
/// same-provider probes, preserves request order, and lets a 429 cooldown stop
/// the next probe before it creates an authorizer request or client.
static PROVIDER_LOOKUP_LOCKS: OnceLock<[tokio::sync::Mutex<()>; 3]> = OnceLock::new();
static PROVIDER_COOLDOWNS_UNTIL: OnceLock<Mutex<[u64; 3]>> = OnceLock::new();

fn provider_lookup_locks() -> &'static [tokio::sync::Mutex<()>; 3] {
    PROVIDER_LOOKUP_LOCKS.get_or_init(|| std::array::from_fn(|_| tokio::sync::Mutex::new(())))
}

fn provider_cooldowns_until() -> &'static Mutex<[u64; 3]> {
    PROVIDER_COOLDOWNS_UNTIL.get_or_init(|| Mutex::new([0; 3]))
}

const fn provider_index(provider: CitationProvider) -> usize {
    match provider {
        CitationProvider::Crossref => 0,
        CitationProvider::OpenAlex => 1,
        CitationProvider::SemanticScholar => 2,
    }
}

const fn surface_for(provider: CitationProvider) -> ExternalHttpSurface {
    match provider {
        CitationProvider::Crossref => ExternalHttpSurface::Crossref,
        CitationProvider::OpenAlex => ExternalHttpSurface::OpenAlex,
        CitationProvider::SemanticScholar => ExternalHttpSurface::SemanticScholar,
    }
}

/// Cache first, then optionally perform one live lookup.  `offline` returns a
/// core-owned `OfflineCacheMiss` without constructing an authorizer, request,
/// HTTP client, or audit event.  A fresh cache hit always wins over a later
/// permission denial and receives a new core binding for `claim`.
pub async fn lookup_cache_first(
    query: &CitationQuery,
    claim: &str,
    cache: Option<&CitationCache>,
    now_secs: u64,
    offline: bool,
    authorizer_factory: impl FnOnce() -> anyhow::Result<ExternalHttpAuthorizer>,
) -> CitationCacheFirstReport {
    let cache_read = match cache_first_decision(query, claim, cache, now_secs, offline) {
        CitationCacheFirstDecision::Terminal(report) => return *report,
        CitationCacheFirstDecision::Live { cache_read, .. } => cache_read,
    };

    // Do not construct an authorizer before a cache hit/offline result: its
    // setup owns WAL routing and is part of the live egress path.
    let authorizer = match authorizer_factory() {
        Ok(authorizer) => authorizer,
        Err(_) => {
            return CitationCacheFirstReport {
                lookup: CitationLookupResult::unavailable(
                    query.provider,
                    CitationLookupState::PermissionDenied,
                ),
                cache_read,
                cache_write: CitationCacheWriteState::NotAttempted,
            };
        }
    };
    let result = lookup_live(query, claim, &authorizer).await;
    let cache_write = if let CitationLookupResult::Found { record, .. } = &result
        && let Some(cache) = cache
    {
        // Cache persistence is intentionally non-authoritative: the returned
        // live result was already fully validated by the core.  `put` rejects
        // any non-live or query-mismatched record before it writes.
        match cache.put(query, record, now_secs) {
            Ok(()) => CitationCacheWriteState::Stored,
            Err(_) => CitationCacheWriteState::WriteFailed,
        }
    } else {
        CitationCacheWriteState::NotAttempted
    };
    CitationCacheFirstReport {
        lookup: result,
        cache_read,
        cache_write,
    }
}

/// Apply the one cache/offline decision shared by ordinary lookup and GUI
/// preflight.  The result is deliberately private: callers receive only a
/// terminal report or the narrowly scoped live-miss capability.
fn cache_first_decision(
    query: &CitationQuery,
    claim: &str,
    cache: Option<&CitationCache>,
    now_secs: u64,
    offline: bool,
) -> CitationCacheFirstDecision {
    if query.validate().is_err() {
        return CitationCacheFirstDecision::Terminal(Box::new(CitationCacheFirstReport {
            lookup: CitationLookupResult::unavailable(
                query.provider,
                CitationLookupState::InvalidQuery,
            ),
            cache_read: CitationCacheReadState::NotConfigured,
            cache_write: CitationCacheWriteState::NotAttempted,
        }));
    }
    let normalized_claim = match validate_claim(claim) {
        Ok(normalized_claim) => normalized_claim,
        Err(_) => {
            return CitationCacheFirstDecision::Terminal(Box::new(CitationCacheFirstReport {
                lookup: CitationLookupResult::unavailable(
                    query.provider,
                    CitationLookupState::InvalidQuery,
                ),
                cache_read: CitationCacheReadState::NotConfigured,
                cache_write: CitationCacheWriteState::NotAttempted,
            }));
        }
    };

    let cache_read = match cache {
        Some(cache) => match cache.get(query, &normalized_claim, now_secs) {
            Ok(Some(cached)) => {
                return CitationCacheFirstDecision::Terminal(Box::new(CitationCacheFirstReport {
                    lookup: cached,
                    cache_read: CitationCacheReadState::Hit,
                    cache_write: CitationCacheWriteState::NotAttempted,
                }));
            }
            Ok(None) => CitationCacheReadState::Miss,
            Err(_) => CitationCacheReadState::ReadFailed,
        },
        None => CitationCacheReadState::NotConfigured,
    };
    if offline {
        return CitationCacheFirstDecision::Terminal(Box::new(CitationCacheFirstReport {
            lookup: CitationLookupResult::unavailable(
                query.provider,
                CitationLookupState::OfflineCacheMiss,
            ),
            cache_read,
            cache_write: CitationCacheWriteState::NotAttempted,
        }));
    }
    CitationCacheFirstDecision::Live {
        cache_read,
        normalized_claim,
    }
}

/// Cache-first GUI preflight.  The supplied consent factory can only run on a
/// live miss, and receives the unforgeable evidence required by the consent
/// core.  A cache hit, an offline miss, or invalid input returns without
/// challenge creation, proof consumption, authorizer construction, or WAL.
pub(crate) fn gui_citation_preflight_cache_first(
    query: &CitationQuery,
    claim: &str,
    cache: Option<&CitationCache>,
    now_secs: u64,
    offline: bool,
    consent_factory: impl FnOnce(GuiCitationLiveMiss) -> anyhow::Result<CitationConsentPreflight>,
) -> anyhow::Result<GuiCitationPreflightCacheFirst> {
    match cache_first_decision(query, claim, cache, now_secs, offline) {
        CitationCacheFirstDecision::Terminal(report) => {
            Ok(GuiCitationPreflightCacheFirst::Terminal(report))
        }
        CitationCacheFirstDecision::Live {
            cache_read,
            normalized_claim,
        } => consent_factory(GuiCitationLiveMiss {
            query: query.clone(),
            normalized_claim,
        })
        .map(|preflight| GuiCitationPreflightCacheFirst::Consent {
            cache_read,
            preflight,
        }),
    }
}

/// GUI-only live continuation for an already approved citation proof.  The
/// opaque proof is supplied by a lazy consume closure, so a cache hit or
/// offline result returns before proof consumption, authorizer construction,
/// permission gating, or an HTTP WAL event.  Ordinary terminal CLI lookup
/// continues to call [`lookup_cache_first`] and never reaches this API.
pub(crate) async fn lookup_cache_first_with_gui_citation_approval(
    query: &CitationQuery,
    claim: &str,
    cache: Option<&CitationCache>,
    now_secs: u64,
    offline: bool,
    home: &Path,
    gui_request_id: &str,
    consume_approval: impl FnOnce() -> anyhow::Result<ConsumedGuiCitationLookupApproval>,
) -> CitationCacheFirstReport {
    let home = home.to_path_buf();
    let query_for_authorizer = query.clone();
    let claim_for_authorizer = claim.to_owned();
    let gui_request_id = gui_request_id.to_owned();
    lookup_cache_first(query, claim, cache, now_secs, offline, move || {
        // The proof has already been minted by a user-visible GUI Approve;
        // consuming it here is intentionally after cache/offline policy.
        let approval = consume_approval()?;
        let (policy, _generation_sha256) =
            crate::tools::citation_consent::current_citation_consent_policy_generation(&home)
                .context("read GUI citation consent policy generation")?;
        let authorizer = ExternalHttpAuthorizer::interactive(policy.clone())?;
        authorizer.attach_consumed_gui_citation_lookup_approval(
            home,
            policy,
            query_for_authorizer,
            &claim_for_authorizer,
            &gui_request_id,
            approval,
        )
    })
    .await
}

/// GUI-only continuation for a preflight answer of `Ready` (current policy
/// `Allow`).  This path has no proof and never reads stdin.  It remains lazy
/// behind the same cache/offline decision and attaches a citation-specific
/// ready context whose real execute seam reloads the coherent current policy:
/// a later `Confirm` or `Deny` therefore cannot use the stale Ready result.
pub(crate) async fn lookup_cache_first_with_gui_citation_ready(
    query: &CitationQuery,
    claim: &str,
    cache: Option<&CitationCache>,
    now_secs: u64,
    offline: bool,
    home: &Path,
    gui_request_id: &str,
) -> CitationCacheFirstReport {
    let home = home.to_path_buf();
    let query_for_authorizer = query.clone();
    let claim_for_authorizer = claim.to_owned();
    let gui_request_id = gui_request_id.to_owned();
    lookup_cache_first(query, claim, cache, now_secs, offline, move || {
        let (policy, _) =
            crate::tools::citation_consent::current_citation_consent_policy_generation(&home)
                .context("read GUI citation ready policy generation")?;
        let authorizer = ExternalHttpAuthorizer::interactive(policy.clone())?;
        authorizer.attach_gui_citation_lookup_ready(
            home,
            policy,
            query_for_authorizer,
            &claim_for_authorizer,
            &gui_request_id,
        )
    })
    .await
}

/// Perform exactly one authorized request to the fixed provider endpoint in
/// [`CitationQuery::fixed_request_url`].  This function has no fallback or
/// provider iteration; callers that intentionally choose another provider do
/// so in a later, explicit call after this terminal outcome.
pub async fn lookup_live(
    query: &CitationQuery,
    claim: &str,
    authorizer: &ExternalHttpAuthorizer,
) -> CitationLookupResult {
    let timeout = Duration::from_secs(REQUEST_TIMEOUT_SECS);
    lookup_live_at(query, claim, authorizer, query.fixed_request_url(), timeout).await
}

async fn lookup_live_at(
    query: &CitationQuery,
    claim: &str,
    authorizer: &ExternalHttpAuthorizer,
    endpoint: String,
    timeout: Duration,
) -> CitationLookupResult {
    let provider = query.provider;
    // `CitationQuery` is public/deserializable.  Revalidate both it and the
    // claim before even waiting for a provider permit, creating an HTTP
    // request, or constructing an authorizer client.
    if query.validate().is_err() || validate_claim(claim).is_err() {
        return CitationLookupResult::unavailable(provider, CitationLookupState::InvalidQuery);
    }
    let started = Instant::now();
    let index = provider_index(provider);
    let _serial = match tokio::time::timeout(timeout, provider_lookup_locks()[index].lock()).await {
        Ok(guard) => guard,
        Err(_) => return CitationLookupResult::unavailable(provider, CitationLookupState::Timeout),
    };
    let remaining = match timeout.checked_sub(started.elapsed()) {
        Some(remaining) if !remaining.is_zero() => remaining,
        _ => return CitationLookupResult::unavailable(provider, CitationLookupState::Timeout),
    };
    let now_secs = crate::time::now_unix_secs();

    if let Some(retry_after_secs) = active_cooldown(provider, now_secs) {
        return CitationLookupResult::unavailable(
            provider,
            CitationLookupState::RateLimited {
                retry_after_secs: Some(retry_after_secs),
            },
        );
    }

    let request = ExternalHttpRequest::get(&endpoint, surface_for(provider));
    let client = match http_client::build_client_no_redirect() {
        Ok(client) => client,
        Err(_) => {
            return CitationLookupResult::unavailable(
                provider,
                CitationLookupState::ProviderUnavailable,
            );
        }
    };
    let deadline = tokio::time::Instant::now() + remaining;
    let transport =
        match ExternalHttpTransportRequest::new(&request, client.get(&endpoint).timeout(remaining))
        {
            Ok(transport) => transport,
            Err(_) => {
                return CitationLookupResult::unavailable(
                    provider,
                    CitationLookupState::InvalidQuery,
                );
            }
        };
    let terminal = match authorizer
        .execute_transport(request, transport, move |response| async move {
            let response = fetch_one_bounded(response, deadline).await?;
            if response.status == reqwest::StatusCode::TOO_MANY_REQUESTS.as_u16() {
                // A rate limit means this lookup did not complete. Return an error
                // so the required lifecycle result is durably `failure`; cooldown
                // state is installed only after that terminal append succeeds.
                return Err(CitationTransportFailure::RateLimited(
                    response
                        .retry_after
                        .as_deref()
                        .and_then(parse_retry_after_secs),
                )
                .into());
            }
            if response.status == reqwest::StatusCode::NOT_FOUND.as_u16() {
                // A documented 404 is a complete, valid lookup with no record.
                return Ok(CitationTransportTerminal::NotFound);
            }
            if !(200..300).contains(&response.status) {
                // A no-redirect client leaves 3xx here.  The response is an
                // unsuccessful provider exchange and must receive a failure frame.
                return Err(CitationTransportFailure::ProviderUnavailable.into());
            }
            let record = parse_provider_record(query, &response.body, now_secs)
                .ok_or(CitationTransportFailure::ProviderUnavailable)?;
            let result = CitationLookupResult::from_live(query, claim, record)
                .map_err(|_| CitationTransportFailure::ProviderUnavailable)?;
            Ok(CitationTransportTerminal::Found(result))
        })
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            if let Some(CitationTransportFailure::RateLimited(retry_after_secs)) =
                error.downcast_ref::<CitationTransportFailure>()
            {
                let retry_after_secs = *retry_after_secs;
                if let Some(retry_after_secs) = retry_after_secs {
                    install_cooldown(provider, now_secs, retry_after_secs);
                }
                return CitationLookupResult::unavailable(
                    provider,
                    CitationLookupState::RateLimited { retry_after_secs },
                );
            }
            if matches!(
                error.downcast_ref::<CitationTransportFailure>(),
                Some(CitationTransportFailure::Timeout)
            ) || matches!(
                error.downcast_ref::<ExternalHttpTransportFailure>(),
                Some(ExternalHttpTransportFailure::Timeout)
            ) {
                return CitationLookupResult::unavailable(provider, CitationLookupState::Timeout);
            }
            if matches!(
                error.downcast_ref::<CitationTransportFailure>(),
                Some(CitationTransportFailure::ProviderUnavailable)
            ) || matches!(
                error.downcast_ref::<ExternalHttpTransportFailure>(),
                Some(ExternalHttpTransportFailure::Unavailable)
            ) {
                return CitationLookupResult::unavailable(
                    provider,
                    CitationLookupState::ProviderUnavailable,
                );
            }
            return CitationLookupResult::unavailable(
                provider,
                CitationLookupState::PermissionDenied,
            );
        }
    };

    match terminal {
        CitationTransportTerminal::Found(result) => result,
        CitationTransportTerminal::NotFound => {
            CitationLookupResult::unavailable(provider, CitationLookupState::NotFound)
        }
    }
}

fn active_cooldown(provider: CitationProvider, now_secs: u64) -> Option<u64> {
    let until = provider_cooldowns_until()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)[provider_index(provider)];
    until
        .checked_sub(now_secs)
        .filter(|remaining| *remaining > 0)
}

fn install_cooldown(provider: CitationProvider, now_secs: u64, retry_after_secs: u64) {
    let until = now_secs.saturating_add(retry_after_secs);
    let mut cooldowns = provider_cooldowns_until()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cooldowns[provider_index(provider)] = cooldowns[provider_index(provider)].max(until);
}

fn parse_retry_after_secs(value: &str) -> Option<u64> {
    let value = value.trim();
    let seconds = value.parse::<u64>().ok()?;
    (seconds <= MAX_RETRY_AFTER_SECS).then_some(seconds)
}

enum CitationTransportTerminal {
    Found(CitationLookupResult),
    NotFound,
}

#[derive(Debug, thiserror::Error)]
enum CitationTransportFailure {
    #[error("citation provider response timed out")]
    Timeout,
    #[error("citation provider rate limited the lookup")]
    RateLimited(Option<u64>),
    #[error("citation provider response was unavailable")]
    ProviderUnavailable,
}

struct ProviderHttpResponse {
    status: u16,
    retry_after: Option<String>,
    body: Vec<u8>,
}

async fn fetch_one_bounded(
    mut response: ExternalHttpResponse,
    deadline: tokio::time::Instant,
) -> Result<ProviderHttpResponse, CitationTransportFailure> {
    let exchange = async {
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|header| header.to_str().ok())
            .map(ToOwned::to_owned);
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
        {
            return Err(CitationTransportFailure::ProviderUnavailable);
        }
        let mut body = Vec::with_capacity(8 * 1024);
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| CitationTransportFailure::ProviderUnavailable)?
        {
            let total = body
                .len()
                .checked_add(chunk.len())
                .ok_or(CitationTransportFailure::ProviderUnavailable)?;
            if total > MAX_PROVIDER_RESPONSE_BYTES {
                return Err(CitationTransportFailure::ProviderUnavailable);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(ProviderHttpResponse {
            status,
            retry_after,
            body,
        })
    };

    match tokio::time::timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        exchange,
    )
    .await
    {
        Err(_) => Err(CitationTransportFailure::Timeout),
        Ok(response) => response,
    }
}

fn parse_provider_record(
    query: &CitationQuery,
    body: &[u8],
    fetched_at_unix: u64,
) -> Option<CitationRecord> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let parsed = match query.provider {
        CitationProvider::Crossref => parse_crossref(&value)?,
        CitationProvider::OpenAlex => parse_openalex(&value)?,
        CitationProvider::SemanticScholar => parse_semantic_scholar(&value)?,
    };
    let record = CitationRecord::new(
        query,
        &parsed.record_id,
        Some(&parsed.canonical_doi),
        &parsed.title,
        &parsed.authors,
        parsed.year,
        parsed.venue.as_deref(),
        fetched_at_unix,
        None,
    )
    .ok()?;
    // Provider DOI spellings may use the canonical https://doi.org/ URI.
    // Compare only after the core normalizes it, never by accepting a raw
    // provider string as an identity match.
    (record.canonical_doi.as_deref() == Some(query.doi.as_str())).then_some(record)
}

struct ParsedProviderRecord {
    record_id: String,
    canonical_doi: String,
    title: String,
    authors: Vec<String>,
    year: Option<u16>,
    venue: Option<String>,
}

fn parse_crossref(value: &Value) -> Option<ParsedProviderRecord> {
    let message = value.get("message")?;
    let canonical_doi = required_string(message, "DOI")?;
    Some(ParsedProviderRecord {
        record_id: canonical_doi.clone(),
        canonical_doi,
        title: first_string(message.get("title"))?,
        authors: crossref_authors(message.get("author")),
        year: crossref_year(message),
        venue: first_string(message.get("container-title")),
    })
}

fn parse_openalex(value: &Value) -> Option<ParsedProviderRecord> {
    let id = required_string(value, "id")?;
    let record_id = id.strip_prefix("https://openalex.org/")?.to_owned();
    Some(ParsedProviderRecord {
        record_id,
        canonical_doi: required_string(value, "doi")?,
        title: required_string(value, "title")?,
        authors: openalex_authors(value.get("authorships")),
        year: value
            .get("publication_year")
            .and_then(Value::as_u64)
            .and_then(|year| u16::try_from(year).ok()),
        venue: value
            .pointer("/primary_location/source/display_name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn parse_semantic_scholar(value: &Value) -> Option<ParsedProviderRecord> {
    Some(ParsedProviderRecord {
        record_id: required_string(value, "paperId")?,
        canonical_doi: value.pointer("/externalIds/DOI")?.as_str()?.to_owned(),
        title: required_string(value, "title")?,
        authors: named_authors(value.get("authors")),
        year: value
            .get("year")
            .and_then(Value::as_u64)
            .and_then(|year| u16::try_from(year).ok()),
        venue: value
            .get("venue")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn required_string(object: &Value, key: &str) -> Option<String> {
    object.get(key)?.as_str().map(ToOwned::to_owned)
}

fn first_string(value: Option<&Value>) -> Option<String> {
    value?.as_array()?.first()?.as_str().map(ToOwned::to_owned)
}

fn crossref_authors(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|author| {
            let given = author.get("given").and_then(Value::as_str).unwrap_or("");
            let family = author.get("family").and_then(Value::as_str).unwrap_or("");
            let name = format!("{given} {family}").trim().to_owned();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

fn openalex_authors(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|authorship| {
            authorship
                .pointer("/author/display_name")?
                .as_str()
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn named_authors(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|author| author.get("name")?.as_str().map(ToOwned::to_owned))
        .collect()
}

fn crossref_year(message: &Value) -> Option<u16> {
    ["published-print", "published-online"]
        .into_iter()
        .find_map(|key| message.pointer(&format!("/{key}/date-parts/0/0")))
        .and_then(Value::as_u64)
        .and_then(|year| u16::try_from(year).ok())
}

#[cfg(test)]
async fn lookup_live_against(
    query: &CitationQuery,
    claim: &str,
    authorizer: &ExternalHttpAuthorizer,
    endpoint: String,
) -> CitationLookupResult {
    lookup_live_at(
        query,
        claim,
        authorizer,
        endpoint,
        Duration::from_secs(REQUEST_TIMEOUT_SECS),
    )
    .await
}

#[cfg(test)]
async fn lookup_live_against_with_timeout(
    query: &CitationQuery,
    claim: &str,
    authorizer: &ExternalHttpAuthorizer,
    endpoint: String,
    timeout: Duration,
) -> CitationLookupResult {
    lookup_live_at(query, claim, authorizer, endpoint, timeout).await
}

#[cfg(test)]
fn clear_cooldowns_for_test() {
    *provider_cooldowns_until()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = [0; 3];
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::tools::external_http::ExternalHttpAuditSink;
    use crate::wal::events::ExtendedSubtype;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    static TEST_SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

    async fn serial_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
        TEST_SERIAL
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await
    }

    fn query(provider: CitationProvider) -> CitationQuery {
        CitationQuery::new(provider, "10.1000/example").unwrap()
    }

    fn crossref_body(doi: &str) -> String {
        format!(
            r#"{{"message":{{"DOI":"{doi}","title":["Citation title"],"author":[{{"given":"Ada","family":"Lovelace"}}],"published-online":{{"date-parts":[[2024]]}},"container-title":["Journal"]}}}}"#
        )
    }

    #[derive(Default)]
    struct TerminalSink {
        events: Mutex<Vec<(ExtendedSubtype, serde_json::Value)>>,
    }
    #[async_trait::async_trait]
    impl ExternalHttpAuditSink for TerminalSink {
        fn requires_permission_audit(&self) -> bool {
            false
        }
        async fn append_external_http(
            &self,
            subtype: ExtendedSubtype,
            payload: Vec<u8>,
        ) -> anyhow::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push((subtype, serde_json::from_slice(&payload)?));
            Ok(())
        }
    }
    fn terminal_authorizer(sink: Arc<TerminalSink>) -> ExternalHttpAuthorizer {
        ExternalHttpAuthorizer::test_policy_with_sink(
            crate::permissions::AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Standard,
            ),
            crate::permissions::ConfirmStrategy::AlwaysAllow,
            sink,
        )
    }
    fn assert_terminal_status(sink: &TerminalSink, status: &str) {
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, ExtendedSubtype::ExternalHttpIntent);
        assert_eq!(events[1].0, ExtendedSubtype::ExternalHttpResult);
        assert_eq!(events[1].1["status"], status);
    }

    #[test]
    fn fixed_endpoints_and_surfaces_are_provider_specific() {
        assert_eq!(surface_for(CitationProvider::Crossref).as_str(), "crossref");
        assert_eq!(surface_for(CitationProvider::OpenAlex).as_str(), "openalex");
        assert_eq!(
            surface_for(CitationProvider::SemanticScholar).as_str(),
            "semantic_scholar"
        );
        assert_eq!(
            query(CitationProvider::Crossref).fixed_request_url(),
            "https://api.crossref.org/works/10.1000%2Fexample"
        );
        assert!(
            query(CitationProvider::OpenAlex)
                .fixed_request_url()
                .starts_with("https://api.openalex.org/works/https://doi.org/")
        );
    }

    #[tokio::test]
    async fn cache_hit_and_offline_miss_never_construct_an_authorizer() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let directory = tempfile::tempdir().unwrap();
        let cache = CitationCache::new(
            directory.path().canonicalize().unwrap().join("citations"),
            60,
            8,
            100_000,
        )
        .unwrap();
        let query = query(CitationProvider::Crossref);
        let record = CitationRecord::new(
            &query,
            "10.1000/example",
            Some("10.1000/example"),
            "Citation title",
            &["Ada Lovelace".to_owned()],
            Some(2024),
            Some("Journal"),
            10,
            None,
        )
        .unwrap();
        cache.put(&query, &record, 10).unwrap();
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let hit_calls = Arc::clone(&factory_calls);
        let hit = lookup_cache_first(&query, "claim", Some(&cache), 11, false, move || {
            hit_calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("factory must remain uncalled on cache hit")
        })
        .await;
        assert!(matches!(hit.lookup, CitationLookupResult::Found { .. }));
        assert_eq!(hit.cache_read, CitationCacheReadState::Hit);
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);

        let offline_calls = Arc::clone(&factory_calls);
        let offline = lookup_cache_first(&query, "claim", None, 11, true, move || {
            offline_calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("factory must remain uncalled offline")
        })
        .await;
        assert!(matches!(
            offline.lookup,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::OfflineCacheMiss,
                ..
            }
        ));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn gui_cache_and_offline_paths_never_mint_or_consume_a_proof() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let directory = tempfile::tempdir().unwrap();
        let cache = CitationCache::new(
            directory.path().canonicalize().unwrap().join("citations"),
            60,
            8,
            100_000,
        )
        .unwrap();
        let home = tempfile::tempdir().unwrap();
        let query = query(CitationProvider::Crossref);
        let record = CitationRecord::new(
            &query,
            "10.1000/example",
            Some("10.1000/example"),
            "Citation title",
            &["Ada Lovelace".to_owned()],
            Some(2024),
            Some("Journal"),
            10,
            None,
        )
        .unwrap();
        cache.put(&query, &record, 10).unwrap();

        let mint_calls = Arc::new(AtomicUsize::new(0));
        let hit_mint_calls = Arc::clone(&mint_calls);
        let hit = gui_citation_preflight_cache_first(
            &query,
            "claim",
            Some(&cache),
            11,
            false,
            move |_| {
                hit_mint_calls.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("preflight must remain uncalled on cache hit")
            },
        )
        .unwrap();
        let GuiCitationPreflightCacheFirst::Terminal(hit) = hit else {
            panic!()
        };
        assert!(matches!(
            *hit,
            CitationCacheFirstReport {
                cache_read: CitationCacheReadState::Hit,
                ..
            }
        ));

        let offline_mint_calls = Arc::clone(&mint_calls);
        let offline_preflight =
            gui_citation_preflight_cache_first(&query, "claim", None, 11, true, move |_| {
                offline_mint_calls.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("preflight must remain uncalled offline")
            })
            .unwrap();
        let GuiCitationPreflightCacheFirst::Terminal(offline_preflight) = offline_preflight else {
            panic!()
        };
        assert!(matches!(
            *offline_preflight,
            CitationCacheFirstReport {
                lookup: CitationLookupResult::Unavailable {
                    state: CitationLookupState::OfflineCacheMiss,
                    ..
                },
                ..
            }
        ));
        assert_eq!(mint_calls.load(Ordering::SeqCst), 0);

        let consume_calls = Arc::new(AtomicUsize::new(0));
        let hit_consume_calls = Arc::clone(&consume_calls);
        let hit_lookup = lookup_cache_first_with_gui_citation_approval(
            &query,
            "claim",
            Some(&cache),
            11,
            false,
            home.path(),
            "gui-request-1",
            move || {
                hit_consume_calls.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("proof must remain unconsumed on cache hit")
            },
        )
        .await;
        assert_eq!(hit_lookup.cache_read, CitationCacheReadState::Hit);

        let offline_consume_calls = Arc::clone(&consume_calls);
        let offline_lookup = lookup_cache_first_with_gui_citation_approval(
            &query,
            "claim",
            None,
            11,
            true,
            home.path(),
            "gui-request-1",
            move || {
                offline_consume_calls.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("proof must remain unconsumed offline")
            },
        )
        .await;
        assert!(matches!(
            offline_lookup.lookup,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::OfflineCacheMiss,
                ..
            }
        ));
        assert_eq!(consume_calls.load(Ordering::SeqCst), 0);

        // No `freedom.yaml` exists in this home.  A cache/offline Ready path
        // must still return before it can read policy or create an authorizer.
        let ready_hit = lookup_cache_first_with_gui_citation_ready(
            &query,
            "claim",
            Some(&cache),
            11,
            false,
            home.path(),
            "gui-request-1",
        )
        .await;
        assert_eq!(ready_hit.cache_read, CitationCacheReadState::Hit);
        let ready_offline = lookup_cache_first_with_gui_citation_ready(
            &query,
            "claim",
            None,
            11,
            true,
            home.path(),
            "gui-request-1",
        )
        .await;
        assert!(matches!(
            ready_offline.lookup,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::OfflineCacheMiss,
                ..
            }
        ));
    }

    #[test]
    fn gui_live_miss_capability_is_bound_to_its_exact_lookup() {
        let crossref_query = query(CitationProvider::Crossref);
        let other_query = query(CitationProvider::OpenAlex);
        let outcome = gui_citation_preflight_cache_first(
            &crossref_query,
            "bound claim",
            None,
            11,
            false,
            |live_miss| {
                assert!(live_miss.matches_lookup(&crossref_query, "bound claim"));
                assert!(!live_miss.matches_lookup(&other_query, "bound claim"));
                assert!(!live_miss.matches_lookup(&crossref_query, "other claim"));
                Ok(CitationConsentPreflight::Ready)
            },
        )
        .unwrap();
        assert!(matches!(
            outcome,
            GuiCitationPreflightCacheFirst::Consent {
                cache_read: CitationCacheReadState::NotConfigured,
                preflight: CitationConsentPreflight::Ready,
            }
        ));
    }

    #[tokio::test]
    async fn real_authorized_request_builds_a_canonical_live_record() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/works/10.1000/example"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(crossref_body("10.1000/example")),
            )
            .mount(&server)
            .await;
        let query = query(CitationProvider::Crossref);
        let result = lookup_live_against(
            &query,
            "displayed claim",
            &ExternalHttpAuthorizer::test_allow(),
            format!("{}/works/10.1000%2Fexample", server.uri()),
        )
        .await;
        assert!(result.validate_for_claim(&query, "displayed claim"));
    }

    #[test]
    fn provider_response_mappings_are_identity_bound() {
        let openalex = CitationQuery::new(CitationProvider::OpenAlex, "10.1000/example").unwrap();
        let openalex_body = br#"{
            "id":"https://openalex.org/W123",
            "doi":"https://doi.org/10.1000/example",
            "title":"OpenAlex title",
            "authorships":[{"author":{"display_name":"Ada Lovelace"}}],
            "publication_year":2024,
            "primary_location":{"source":{"display_name":"Journal"}}
        }"#;
        let semantic =
            CitationQuery::new(CitationProvider::SemanticScholar, "10.1000/example").unwrap();
        let semantic_body = br#"{
            "paperId":"0123456789abcdef0123456789abcdef01234567",
            "externalIds":{"DOI":"10.1000/example"},
            "title":"Semantic Scholar title",
            "authors":[{"name":"Ada Lovelace"}],
            "year":2024,
            "venue":"Journal"
        }"#;
        for (query, body) in [
            (openalex, openalex_body.as_slice()),
            (semantic, semantic_body.as_slice()),
        ] {
            let record = parse_provider_record(&query, body, 1).unwrap();
            let result = CitationLookupResult::from_live(&query, "claim", record).unwrap();
            assert!(result.validate_for_claim(&query, "claim"));
        }
    }

    #[tokio::test]
    async fn malformed_or_mismatched_provider_json_is_closed_unavailable() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(crossref_body("10.1000/other")),
            )
            .mount(&server)
            .await;
        let result = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &ExternalHttpAuthorizer::test_allow(),
            server.uri(),
        )
        .await;
        assert_eq!(
            result,
            CitationLookupResult::unavailable(
                CitationProvider::Crossref,
                CitationLookupState::ProviderUnavailable,
            )
        );
    }

    #[tokio::test]
    async fn response_status_decode_and_size_failures_write_failure_terminals() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        for response in [
            ResponseTemplate::new(500).set_body_string("provider-status-failure"),
            ResponseTemplate::new(200).set_body_string("not-provider-json"),
            ResponseTemplate::new(200).set_body_string("x".repeat(MAX_PROVIDER_RESPONSE_BYTES + 1)),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(response)
                .mount(&server)
                .await;
            let sink = Arc::new(TerminalSink::default());
            let result = lookup_live_against(
                &query(CitationProvider::Crossref),
                "claim",
                &terminal_authorizer(sink.clone()),
                server.uri(),
            )
            .await;
            assert_eq!(
                result,
                CitationLookupResult::unavailable(
                    CitationProvider::Crossref,
                    CitationLookupState::ProviderUnavailable
                )
            );
            assert_terminal_status(&sink, "failure");
        }
    }

    #[tokio::test]
    async fn truncated_stream_writes_failure_terminal_and_valid_record_writes_success_terminal() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\nshort",
                )
                .await
                .unwrap();
        });
        let truncated_sink = Arc::new(TerminalSink::default());
        let truncated = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &terminal_authorizer(truncated_sink.clone()),
            endpoint,
        )
        .await;
        assert_eq!(
            truncated,
            CitationLookupResult::unavailable(
                CitationProvider::Crossref,
                CitationLookupState::ProviderUnavailable
            )
        );
        assert_terminal_status(&truncated_sink, "failure");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(crossref_body("10.1000/example")),
            )
            .mount(&server)
            .await;
        let success_sink = Arc::new(TerminalSink::default());
        let valid = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &terminal_authorizer(success_sink.clone()),
            server.uri(),
        )
        .await;
        assert!(matches!(valid, CitationLookupResult::Found { .. }));
        assert_terminal_status(&success_sink, "success");
    }

    #[tokio::test]
    async fn timeout_maps_to_a_typed_outcome_through_the_authorized_client_path() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(100))
                    .set_body_string(crossref_body("10.1000/example")),
            )
            .mount(&server)
            .await;
        let result = lookup_live_against_with_timeout(
            &query(CitationProvider::Crossref),
            "claim",
            &ExternalHttpAuthorizer::test_allow(),
            server.uri(),
            Duration::from_millis(1),
        )
        .await;
        assert!(matches!(
            result,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::Timeout,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn header_timeout_preserves_timeout_state_and_writes_failure_terminal() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(100))
                    .set_body_string(crossref_body("10.1000/example")),
            )
            .mount(&server)
            .await;
        let sink = Arc::new(TerminalSink::default());
        let timed_out = lookup_live_against_with_timeout(
            &query(CitationProvider::Crossref),
            "claim",
            &terminal_authorizer(sink.clone()),
            server.uri(),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(
            timed_out,
            CitationLookupResult::unavailable(
                CitationProvider::Crossref,
                CitationLookupState::Timeout
            )
        );
        assert_terminal_status(&sink, "failure");
    }

    #[tokio::test]
    async fn redirect_is_not_followed_and_returns_closed_unavailable() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let second = MockServer::start().await;
        let first = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/second", second.uri())),
            )
            .mount(&first)
            .await;
        let result = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &ExternalHttpAuthorizer::test_allow(),
            first.uri(),
        )
        .await;
        assert!(matches!(
            result,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::ProviderUnavailable,
                ..
            }
        ));
        assert!(second.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn valid_429_sets_only_its_provider_cooldown_without_egress() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
            .mount(&server)
            .await;
        let auth = ExternalHttpAuthorizer::test_allow();
        let first = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &auth,
            server.uri(),
        )
        .await;
        let second = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &auth,
            server.uri(),
        )
        .await;
        assert!(matches!(
            first,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::RateLimited {
                    retry_after_secs: Some(30)
                },
                ..
            }
        ));
        assert!(matches!(
            second,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::RateLimited {
                    retry_after_secs: Some(_)
                },
                ..
            }
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rate_limit_is_failure_terminal_before_cooldown_and_not_found_is_success_terminal() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let limited_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
            .mount(&limited_server)
            .await;
        let limited_sink = Arc::new(TerminalSink::default());
        let limited_auth = terminal_authorizer(limited_sink.clone());
        let first = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &limited_auth,
            limited_server.uri(),
        )
        .await;
        assert_eq!(
            first,
            CitationLookupResult::unavailable(
                CitationProvider::Crossref,
                CitationLookupState::RateLimited {
                    retry_after_secs: Some(30)
                }
            )
        );
        assert_terminal_status(&limited_sink, "failure");
        let second = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &limited_auth,
            limited_server.uri(),
        )
        .await;
        assert!(matches!(
            second,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::RateLimited {
                    retry_after_secs: Some(_)
                },
                ..
            }
        ));
        assert_eq!(limited_server.received_requests().await.unwrap().len(), 1);

        clear_cooldowns_for_test();
        let missing_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&missing_server)
            .await;
        let missing_sink = Arc::new(TerminalSink::default());
        let missing = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &terminal_authorizer(missing_sink.clone()),
            missing_server.uri(),
        )
        .await;
        assert_eq!(
            missing,
            CitationLookupResult::unavailable(
                CitationProvider::Crossref,
                CitationLookupState::NotFound
            )
        );
        assert_terminal_status(&missing_sink, "success");
    }

    #[tokio::test]
    async fn invalid_or_missing_retry_after_does_not_install_a_cooldown() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        for retry_after in [Some("untrusted-date"), None] {
            let server = MockServer::start().await;
            let mut response = ResponseTemplate::new(429);
            if let Some(retry_after) = retry_after {
                response = response.insert_header("retry-after", retry_after);
            }
            Mock::given(method("GET"))
                .respond_with(response)
                .mount(&server)
                .await;
            let auth = ExternalHttpAuthorizer::test_allow();
            for _ in 0..2 {
                let result = lookup_live_against(
                    &query(CitationProvider::Crossref),
                    "claim",
                    &auth,
                    server.uri(),
                )
                .await;
                assert!(matches!(
                    result,
                    CitationLookupResult::Unavailable {
                        state: CitationLookupState::RateLimited {
                            retry_after_secs: None
                        },
                        ..
                    }
                ));
            }
            assert_eq!(server.received_requests().await.unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn cooldown_is_scoped_to_one_provider() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
            .mount(&server)
            .await;
        let auth = ExternalHttpAuthorizer::test_allow();
        let _ = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &auth,
            server.uri(),
        )
        .await;
        let _ = lookup_live_against(
            &query(CitationProvider::OpenAlex),
            "claim",
            &auth,
            server.uri(),
        )
        .await;
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn denied_authorizer_never_enters_the_transport_closure() {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        let server = MockServer::start().await;
        let authorizer = ExternalHttpAuthorizer::test_policy(
            crate::permissions::AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Strict,
            ),
            crate::permissions::ConfirmStrategy::FailClosed,
        );
        let result = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &authorizer,
            server.uri(),
        )
        .await;
        assert!(matches!(
            result,
            CitationLookupResult::Unavailable {
                state: CitationLookupState::PermissionDenied,
                ..
            }
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn authorized_send_failure_is_provider_unavailable_while_gate_denial_is_permission_denied()
     {
        let _serial = serial_test_guard().await;
        clear_cooldowns_for_test();
        // Accept one connection and close it without an HTTP response. This is
        // a bounded localhost send/response failure through execute_transport,
        // without relying on a public address or a timing-sensitive closed port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let unavailable = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &ExternalHttpAuthorizer::test_allow(),
            endpoint,
        )
        .await;
        assert_eq!(
            unavailable,
            CitationLookupResult::unavailable(
                CitationProvider::Crossref,
                CitationLookupState::ProviderUnavailable
            )
        );

        let server = MockServer::start().await;
        let denied = ExternalHttpAuthorizer::test_policy(
            crate::permissions::AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Strict,
            ),
            crate::permissions::ConfirmStrategy::FailClosed,
        );
        let refused = lookup_live_against(
            &query(CitationProvider::Crossref),
            "claim",
            &denied,
            server.uri(),
        )
        .await;
        assert_eq!(
            refused,
            CitationLookupResult::unavailable(
                CitationProvider::Crossref,
                CitationLookupState::PermissionDenied
            )
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn retry_after_parser_is_bounded_and_data_free() {
        assert_eq!(parse_retry_after_secs("42"), Some(42));
        assert_eq!(parse_retry_after_secs("garbage"), None);
        assert_eq!(parse_retry_after_secs("3601"), None);
    }

    #[test]
    fn provider_response_text_never_enters_the_typed_outcome() {
        let query = query(CitationProvider::Crossref);
        let result = parse_provider_record(&query, br#"raw-provider-response-marker"#, 1)
            .map(|record| CitationLookupResult::from_live(&query, "claim", record).unwrap())
            .unwrap_or_else(|| {
                CitationLookupResult::unavailable(
                    CitationProvider::Crossref,
                    CitationLookupState::ProviderUnavailable,
                )
            });
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("raw-provider-response-marker"));
    }
}
