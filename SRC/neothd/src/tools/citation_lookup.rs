//! Bounded, local citation identity and cache core (GOLD-LF-P1-12).
//!
//! This module deliberately has no HTTP implementation.  An operator-facing
//! adapter must implement [`CitationProviderAdapter`] and must perform a fixed
//! provider request through `ExternalHttpAuthorizer` before calling
//! [`CitationRecord::new`].  That keeps permission/WAL ownership out of the
//! cache and prevents model or GUI text from becoming an egress capability.
//!
//! Cached entries contain a validated, canonical record only.  They never
//! contain provider response bodies, credentials, claims, GUI objects, or a
//! precomputed claim binding.  A fresh [`ClaimCitationBinding`] is recreated
//! for the caller's current claim on every cache read.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Format of canonical records and their record fingerprints.
pub const CITATION_RECORD_SCHEMA_VERSION: u16 = 1;
/// Format of cache entries and cache-key input.
pub const CITATION_CACHE_SCHEMA_VERSION: u16 = 1;
/// Format of claim-to-record bindings.
pub const CITATION_BINDING_SCHEMA_VERSION: u16 = 1;

/// Maximum UTF-8 bytes in one explicitly displayed claim.
pub const MAX_CLAIM_BYTES: usize = 4 * 1024;
/// Maximum UTF-8 bytes accepted for a DOI lookup key.
pub const MAX_QUERY_BYTES: usize = 512;
/// Maximum title bytes retained from an untrusted provider response.
pub const MAX_TITLE_BYTES: usize = 1024;
/// Maximum bytes in one normalized author name.
pub const MAX_AUTHOR_BYTES: usize = 128;
/// Maximum number of authors retained in the canonical record.
pub const MAX_AUTHORS: usize = 16;
/// Maximum total retained author metadata bytes.
pub const MAX_AUTHORS_BYTES: usize = 2 * 1024;
/// A future adapter must discard abstracts at this bound; abstracts are not
/// retained in [`CitationRecord`] because they are unnecessary for identity.
pub const MAX_ABSTRACT_METADATA_BYTES: usize = 8 * 1024;
/// Maximum venue bytes retained from an untrusted provider response.
pub const MAX_VENUE_BYTES: usize = 512;
/// A future adapter must reject a provider body beyond this bound before JSON parsing.
pub const MAX_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;
/// DOI resolution selects exactly one canonical record per provider attempt.
pub const MAX_RECORDS_PER_LOOKUP: usize = 1;
/// Upper bound for one canonical private cache entry.
pub const MAX_CACHE_ENTRY_BYTES: usize = 16 * 1024;
/// Default private cache count cap.
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 128;
/// Default private cache byte cap.
pub const DEFAULT_MAX_CACHE_BYTES: u64 = 4 * 1024 * 1024;
/// Cache freshness is anchored to the cached live record, not an access time.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// A future transport must enforce this timeout around send and bounded decode.
pub const REQUEST_TIMEOUT_SECS: u64 = 10;

const CACHE_KEY_DOMAIN: &[u8] = b"neoth.citation.cache-key.v1\0";
const RECORD_FINGERPRINT_DOMAIN: &[u8] = b"neoth.citation.record-fingerprint.v1\0";
const CLAIM_FINGERPRINT_DOMAIN: &[u8] = b"neoth.citation.claim.v1\0";
const BINDING_DOMAIN: &[u8] = b"neoth.citation.binding.v1\0";

/// The closed provider set.  Stable wire values are intentionally independent
/// of Rust variant spelling and are used by cache keys and display projections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CitationProvider {
    #[serde(rename = "crossref")]
    Crossref,
    #[serde(rename = "openalex")]
    OpenAlex,
    #[serde(rename = "semantic-scholar")]
    SemanticScholar,
}

impl CitationProvider {
    pub const ALL: [Self; 3] = [Self::Crossref, Self::OpenAlex, Self::SemanticScholar];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Crossref => "crossref",
            Self::OpenAlex => "openalex",
            Self::SemanticScholar => "semantic-scholar",
        }
    }

    /// Fixed public origin used by the future permission-gated adapter.
    pub const fn origin(self) -> &'static str {
        match self {
            Self::Crossref => "https://api.crossref.org",
            Self::OpenAlex => "https://api.openalex.org",
            Self::SemanticScholar => "https://api.semanticscholar.org",
        }
    }

    fn validate_record_id(self, id: &str) -> bool {
        if id.is_empty() || id.len() > MAX_QUERY_BYTES || !is_printable_ascii(id) {
            return false;
        }
        match self {
            // Crossref returns a DOI as its work identifier.
            Self::Crossref => normalize_doi(id).is_ok(),
            // OpenAlex work IDs are a fixed `W` plus decimal identity.
            Self::OpenAlex => {
                let bytes = id.as_bytes();
                bytes.len() > 1 && bytes[0] == b'W' && bytes[1..].iter().all(u8::is_ascii_digit)
            }
            // Semantic Scholar may return a 40-hex paper id or a numeric CorpusId.
            Self::SemanticScholar => {
                (id.len() == 40 && id.as_bytes().iter().all(u8::is_ascii_hexdigit))
                    || id.as_bytes().iter().all(u8::is_ascii_digit)
            }
        }
    }

    fn canonical_permalink(self, record_id: &str, doi: Option<&str>) -> String {
        match self {
            Self::Crossref => format!(
                "https://doi.org/{}",
                percent_encode_path(doi.unwrap_or(record_id))
            ),
            Self::OpenAlex => format!("https://openalex.org/{record_id}"),
            Self::SemanticScholar => format!(
                "https://www.semanticscholar.org/paper/{}",
                percent_encode_path(record_id)
            ),
        }
    }
}

/// Explicit, normalized DOI query.  It has no URL field and its construction
/// rejects arbitrary origins, paths, control bytes, and oversized inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitationQuery {
    pub provider: CitationProvider,
    pub doi: String,
}

impl CitationQuery {
    pub fn new(provider: CitationProvider, doi: &str) -> Result<Self, CitationValidationError> {
        Ok(Self {
            provider,
            doi: normalize_doi(doi)?,
        })
    }

    /// Revalidate a deserialized or cross-process query before it can reach a
    /// cache key, authorizer, transport request, or live record constructor.
    pub fn validate(&self) -> Result<(), CitationValidationError> {
        if Self::new(self.provider, &self.doi)?.doi == self.doi {
            Ok(())
        } else {
            Err(CitationValidationError::Doi)
        }
    }

    /// SHA-256 binding for the precise normalized request key; never log the DOI.
    pub fn request_key_sha256(&self) -> String {
        digest_hex(&[
            b"neoth.citation.request-key.v1\0",
            self.provider.wire_name().as_bytes(),
            self.doi.as_bytes(),
        ])
    }

    /// The only future adapter URL constructor.  Its origin and path shape are
    /// selected from the enum, while the DOI is encoded as one path component.
    pub fn fixed_request_url(&self) -> String {
        let doi = percent_encode_path(&self.doi);
        match self.provider {
            CitationProvider::Crossref => format!("{}/works/{doi}", self.provider.origin()),
            CitationProvider::OpenAlex => {
                format!("{}/works/https://doi.org/{doi}", self.provider.origin())
            }
            CitationProvider::SemanticScholar => format!(
                "{}/graph/v1/paper/DOI:{doi}?fields=paperId,title,authors,year,venue,externalIds",
                self.provider.origin()
            ),
        }
    }
}

/// Source of a validated canonical record.  This is provenance, not a trust
/// signal for arbitrary fetched text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordSource {
    Live,
    Cache,
}

/// Persisted provenance fields are bounded data, never raw HTTP response text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordProvenance {
    pub provider: CitationProvider,
    pub request_key_sha256: String,
    pub source: RecordSource,
    pub fetched_at_unix: u64,
    /// Provider response/schema version, if explicitly supplied and bounded.
    pub response_version: Option<String>,
}

/// A canonical bibliographic record selected by one provider.  Constructors
/// and cache reads revalidate every persisted identity and bounded field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitationRecord {
    pub schema_version: u16,
    pub provider: CitationProvider,
    pub provider_record_id: String,
    pub canonical_doi: Option<String>,
    pub title: String,
    pub authors: Vec<String>,
    pub year: Option<u16>,
    pub venue: Option<String>,
    pub provider_permalink: String,
    pub fetched_at_unix: u64,
    pub provenance: RecordProvenance,
}

impl CitationRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        query: &CitationQuery,
        provider_record_id: &str,
        canonical_doi: Option<&str>,
        title: &str,
        authors: &[String],
        year: Option<u16>,
        venue: Option<&str>,
        fetched_at_unix: u64,
        response_version: Option<&str>,
    ) -> Result<Self, CitationValidationError> {
        query.validate()?;
        let provider = query.provider;
        let provider_record_id = canonical_record_id(provider, provider_record_id)?;
        let canonical_doi = canonical_doi.map(normalize_doi).transpose()?;
        if canonical_doi.as_deref() != Some(query.doi.as_str())
            || (provider == CitationProvider::Crossref && provider_record_id != query.doi)
        {
            return Err(CitationValidationError::QueryBinding);
        }
        let title =
            normalize_required_text(title, MAX_TITLE_BYTES, CitationValidationError::Title)?;
        let authors = normalize_authors(authors)?;
        let venue = venue
            .map(|value| {
                normalize_required_text(value, MAX_VENUE_BYTES, CitationValidationError::Venue)
            })
            .transpose()?;
        let response_version = response_version
            .map(|value| normalize_required_text(value, 64, CitationValidationError::Provenance))
            .transpose()?;
        let record = Self {
            schema_version: CITATION_RECORD_SCHEMA_VERSION,
            provider,
            provider_record_id: provider_record_id.clone(),
            provider_permalink: provider
                .canonical_permalink(&provider_record_id, canonical_doi.as_deref()),
            canonical_doi,
            title,
            authors,
            year,
            venue,
            fetched_at_unix,
            provenance: RecordProvenance {
                provider,
                request_key_sha256: query.request_key_sha256(),
                source: RecordSource::Live,
                fetched_at_unix,
                response_version,
            },
        };
        record.validate()?;
        Ok(record)
    }

    pub fn fingerprint_sha256(&self) -> Result<String, CitationValidationError> {
        self.validate()?;
        let mut bytes = Vec::new();
        append_field(
            &mut bytes,
            CITATION_RECORD_SCHEMA_VERSION.to_string().as_bytes(),
        );
        append_field(&mut bytes, self.provider.wire_name().as_bytes());
        append_field(&mut bytes, self.provider_record_id.as_bytes());
        append_field(
            &mut bytes,
            self.canonical_doi.as_deref().unwrap_or("").as_bytes(),
        );
        append_field(&mut bytes, self.title.as_bytes());
        for author in &self.authors {
            append_field(&mut bytes, author.as_bytes());
        }
        append_field(
            &mut bytes,
            self.year
                .map(|year| year.to_string())
                .unwrap_or_default()
                .as_bytes(),
        );
        append_field(&mut bytes, self.venue.as_deref().unwrap_or("").as_bytes());
        Ok(digest_hex(&[RECORD_FINGERPRINT_DOMAIN, &bytes]))
    }

    pub fn validate(&self) -> Result<(), CitationValidationError> {
        if self.schema_version != CITATION_RECORD_SCHEMA_VERSION {
            return Err(CitationValidationError::SchemaVersion);
        }
        if canonical_record_id(self.provider, &self.provider_record_id)? != self.provider_record_id
        {
            return Err(CitationValidationError::ProviderRecordId);
        }
        if let Some(doi) = &self.canonical_doi
            && normalize_doi(doi)? != *doi
        {
            return Err(CitationValidationError::Doi);
        }
        if normalize_required_text(&self.title, MAX_TITLE_BYTES, CitationValidationError::Title)?
            != self.title
        {
            return Err(CitationValidationError::Title);
        }
        if normalize_authors(&self.authors)? != self.authors {
            return Err(CitationValidationError::Authors);
        }
        if let Some(venue) = &self.venue
            && normalize_required_text(venue, MAX_VENUE_BYTES, CitationValidationError::Venue)?
                != *venue
        {
            return Err(CitationValidationError::Venue);
        }
        if self.provenance.provider != self.provider
            || self.provenance.fetched_at_unix != self.fetched_at_unix
            || !is_sha256_hex(&self.provenance.request_key_sha256)
        {
            return Err(CitationValidationError::Provenance);
        }
        if let Some(version) = &self.provenance.response_version
            && normalize_required_text(version, 64, CitationValidationError::Provenance)?
                != *version
        {
            return Err(CitationValidationError::Provenance);
        }
        let expected = self
            .provider
            .canonical_permalink(&self.provider_record_id, self.canonical_doi.as_deref());
        if self.provider_permalink != expected {
            return Err(CitationValidationError::Permalink);
        }
        Ok(())
    }

    fn as_cache_record(&self) -> Self {
        let mut cached = self.clone();
        cached.provenance.source = RecordSource::Cache;
        cached
    }
}

/// Claim-specific, domain-separated binding emitted only by trusted core code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimCitationBinding {
    pub schema_version: u16,
    pub claim_sha256: String,
    pub record_fingerprint_sha256: String,
    pub provider: CitationProvider,
    pub provider_record_id: String,
    pub binding_sha256: String,
}

impl ClaimCitationBinding {
    pub fn new(claim: &str, record: &CitationRecord) -> Result<Self, CitationValidationError> {
        let claim = normalize_claim(claim)?;
        let record_fingerprint_sha256 = record.fingerprint_sha256()?;
        let claim_sha256 = digest_hex(&[CLAIM_FINGERPRINT_DOMAIN, claim.as_bytes()]);
        let binding_sha256 = binding_digest(
            &claim_sha256,
            &record_fingerprint_sha256,
            record.provider,
            &record.provider_record_id,
        );
        Ok(Self {
            schema_version: CITATION_BINDING_SCHEMA_VERSION,
            claim_sha256,
            record_fingerprint_sha256,
            provider: record.provider,
            provider_record_id: record.provider_record_id.clone(),
            binding_sha256,
        })
    }

    /// Reject serialized, GUI, or model-supplied bindings unless they exactly
    /// recompute for this current claim and canonical record.
    pub fn verify_for(&self, claim: &str, record: &CitationRecord) -> bool {
        let Ok(expected) = Self::new(claim, record) else {
            return false;
        };
        self == &expected
    }
}

/// Origin of a successful lookup result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupSource {
    Live,
    Cache,
}

/// Closed terminal states for a lookup with no selected record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CitationLookupState {
    OfflineCacheMiss,
    Timeout,
    RateLimited { retry_after_secs: Option<u64> },
    ProviderUnavailable,
    NotFound,
    PermissionDenied,
    InvalidQuery,
}

/// A result is either one fully validated record/binding pair or a typed failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CitationLookupResult {
    Found {
        record: Box<CitationRecord>,
        binding: ClaimCitationBinding,
        source: LookupSource,
    },
    Unavailable {
        provider: CitationProvider,
        state: CitationLookupState,
    },
}

impl CitationLookupResult {
    pub fn from_live(
        query: &CitationQuery,
        claim: &str,
        record: CitationRecord,
    ) -> Result<Self, CitationValidationError> {
        query.validate()?;
        record.validate()?;
        if record.provenance.source != RecordSource::Live || !record_matches_query(&record, query) {
            return Err(CitationValidationError::QueryBinding);
        }
        Ok(Self::Found {
            binding: ClaimCitationBinding::new(claim, &record)?,
            record: Box::new(record),
            source: LookupSource::Live,
        })
    }

    pub fn unavailable(provider: CitationProvider, state: CitationLookupState) -> Self {
        Self::Unavailable { provider, state }
    }

    pub fn validate_for_claim(&self, query: &CitationQuery, claim: &str) -> bool {
        match self {
            Self::Found {
                record,
                binding,
                source,
            } => {
                query.validate().is_ok()
                    && record_matches_query(record, query)
                    && record.validate().is_ok()
                    && record.provenance.source
                        == match source {
                            LookupSource::Live => RecordSource::Live,
                            LookupSource::Cache => RecordSource::Cache,
                        }
                    && binding.verify_for(claim, record)
            }
            Self::Unavailable { .. } => true,
        }
    }

    /// Single shared, display-safe projection for the future CLI and GUI.
    pub fn display_for_claim(&self, query: &CitationQuery, claim: &str) -> Option<CitationDisplay> {
        let Self::Found {
            record,
            binding,
            source,
        } = self
        else {
            return None;
        };
        if !self.validate_for_claim(query, claim) {
            return None;
        }
        Some(CitationDisplay {
            claim: normalize_claim(claim).ok()?,
            provider: record.provider,
            provider_record_id: record.provider_record_id.clone(),
            canonical_doi: record.canonical_doi.clone(),
            title: record.title.clone(),
            authors: record.authors.clone(),
            year: record.year,
            venue: record.venue.clone(),
            record_fingerprint_sha256: binding.record_fingerprint_sha256.clone(),
            provenance: record.provenance.clone(),
            source: *source,
            fetched_at_unix: record.fetched_at_unix,
            provider_permalink: record.provider_permalink.clone(),
            binding_sha256: binding.binding_sha256.clone(),
        })
    }
}

fn record_matches_query(record: &CitationRecord, query: &CitationQuery) -> bool {
    record.provider == query.provider
        && record.provenance.request_key_sha256 == query.request_key_sha256()
        && record.canonical_doi.as_deref() == Some(query.doi.as_str())
        && (query.provider != CitationProvider::Crossref || record.provider_record_id == query.doi)
}

/// Stable projection shared by human/JSON CLI output and a future typed GUI chip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitationDisplay {
    pub claim: String,
    pub provider: CitationProvider,
    pub provider_record_id: String,
    pub canonical_doi: Option<String>,
    pub title: String,
    pub authors: Vec<String>,
    pub year: Option<u16>,
    pub venue: Option<String>,
    pub record_fingerprint_sha256: String,
    pub provenance: RecordProvenance,
    pub source: LookupSource,
    pub fetched_at_unix: u64,
    pub provider_permalink: String,
    pub binding_sha256: String,
}

/// Seam for the later explicit, permission-gated HTTP layer.  No default or
/// fake-success implementation exists; callers must provide a real adapter.
pub trait CitationProviderAdapter {
    /// Return raw bounded core data only. The caller must pass this through
    /// [`CitationAdapterOutcome::into_lookup_result`] for the same query and
    /// claim; an adapter cannot manufacture a `Found` result directly.
    fn lookup(&self, query: &CitationQuery) -> CitationAdapterOutcome;
}

/// Provider-adapter terminal data before the core performs current-query and
/// claim binding. This deliberately cannot carry a caller-made binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CitationAdapterOutcome {
    Record(Box<CitationRecord>),
    Unavailable(CitationLookupState),
}

impl CitationAdapterOutcome {
    pub fn into_lookup_result(
        self,
        query: &CitationQuery,
        claim: &str,
    ) -> Result<CitationLookupResult, CitationValidationError> {
        match self {
            Self::Record(record) => CitationLookupResult::from_live(query, claim, *record),
            Self::Unavailable(state) => {
                Ok(CitationLookupResult::unavailable(query.provider, state))
            }
        }
    }
}

/// Private on-disk cache policy.  `dir` and `now_secs` are injected by callers
/// so cache behavior is deterministic in source tests and production remains at
/// `~/.neoth/cache/citations/`.
pub struct CitationCache {
    dir: PathBuf,
    ttl_secs: u64,
    max_entries: usize,
    max_bytes: u64,
}

/// Cache failures are intentionally separate from a live lookup result: a
/// caller may return a validated live citation while reporting cache persistence
/// as degraded, but it must never claim the configured bound was enforced.
#[derive(Debug)]
pub enum CitationCacheError {
    InvalidPolicy,
    Io(std::io::Error),
}

impl std::fmt::Display for CitationCacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPolicy => {
                formatter.write_str("citation cache policy has a zero cap or TTL")
            }
            Self::Io(error) => write!(formatter, "citation cache I/O: {error}"),
        }
    }
}

impl std::error::Error for CitationCacheError {}

impl From<std::io::Error> for CitationCacheError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

static CITATION_CACHE_MUTATION_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

struct CitationCacheMutationGuard<'a> {
    _process_guard: std::sync::MutexGuard<'a, ()>,
    _file_guard: std::fs::File,
}

impl CitationCache {
    pub fn new(
        dir: PathBuf,
        ttl_secs: u64,
        max_entries: usize,
        max_bytes: u64,
    ) -> Result<Self, CitationCacheError> {
        if ttl_secs == 0 || max_entries == 0 || max_bytes == 0 {
            return Err(CitationCacheError::InvalidPolicy);
        }
        Ok(Self {
            dir,
            ttl_secs,
            max_entries,
            max_bytes,
        })
    }

    pub fn at_default() -> Result<Self, CitationCacheError> {
        let dir = crate::config::FreedomConfig::default_neoth_home()
            .join("cache")
            .join("citations");
        Self::new(
            dir,
            DEFAULT_CACHE_TTL_SECS,
            DEFAULT_MAX_CACHE_ENTRIES,
            DEFAULT_MAX_CACHE_BYTES,
        )
    }

    pub fn cache_key(query: &CitationQuery) -> String {
        digest_hex(&[
            CACHE_KEY_DOMAIN,
            &CITATION_CACHE_SCHEMA_VERSION.to_le_bytes(),
            query.provider.wire_name().as_bytes(),
            query.doi.as_bytes(),
            // DOI lookup always selects exactly one provider record.
            b"single-canonical-record",
        ])
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        debug_assert!(is_sha256_hex(key));
        self.dir.join(format!("{key}.json"))
    }

    /// Offline-safe cache read.  It cannot construct a transport request; a
    /// caller maps `None` to `OfflineCacheMiss` in offline mode.  Every hit is
    /// rebound to `claim`, therefore old claim text is never persisted or reused.
    pub fn get(
        &self,
        query: &CitationQuery,
        claim: &str,
        now_secs: u64,
    ) -> Result<Option<CitationLookupResult>, CitationCacheError> {
        query.validate().map_err(validation_io_error)?;
        self.ensure_private_directory()?;
        let _guard = self.lock_mutation()?;
        let claim = normalize_claim(claim).map_err(validation_io_error)?;
        let key = Self::cache_key(query);
        let path = self.entry_path(&key);
        let bytes = match self.read_cache_child(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if bytes.len() > MAX_CACHE_ENTRY_BYTES {
            self.remove_cache_child(&path)?;
            return Ok(None);
        }
        let mut entry: CitationCacheEntry = match serde_json::from_slice(&bytes) {
            Ok(entry) => entry,
            Err(_) => {
                self.remove_cache_child(&path)?;
                return Ok(None);
            }
        };
        if !entry.matches(query, now_secs, self.ttl_secs) {
            self.remove_cache_child(&path)?;
            return Ok(None);
        }
        entry.last_accessed_unix = now_secs;
        let body = serde_json::to_vec(&entry)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if body.len() > MAX_CACHE_ENTRY_BYTES || body.len() as u64 > self.max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "citation cache touch exceeds bounded policy",
            )
            .into());
        }
        self.ensure_replace_target(&path)?;
        crate::util::atomic_write::atomic_write_private(&path, &body)?;
        self.enforce_cap(now_secs)?;
        let record = entry.record.as_cache_record();
        let binding = ClaimCitationBinding::new(&claim, &record).map_err(validation_io_error)?;
        Ok(Some(CitationLookupResult::Found {
            record: Box::new(record),
            binding,
            source: LookupSource::Cache,
        }))
    }

    /// Complete cache-only policy used by the later `--offline` command path.
    /// It performs no authorizer, request, HTTP-client, or WAL work.
    pub fn lookup_offline(
        &self,
        query: &CitationQuery,
        claim: &str,
        now_secs: u64,
    ) -> Result<CitationLookupResult, CitationCacheError> {
        Ok(self.get(query, claim, now_secs)?.unwrap_or_else(|| {
            CitationLookupResult::unavailable(query.provider, CitationLookupState::OfflineCacheMiss)
        }))
    }

    /// Store only a fully validated live record.  Cache errors are returned for
    /// diagnostics but must not invalidate the caller's successful live result.
    pub fn put(
        &self,
        query: &CitationQuery,
        record: &CitationRecord,
        now_secs: u64,
    ) -> Result<(), CitationCacheError> {
        query.validate().map_err(validation_io_error)?;
        record.validate().map_err(validation_io_error)?;
        if record.provenance.source != RecordSource::Live
            || !record_matches_query(record, query)
            || record.fetched_at_unix > now_secs
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "citation record does not match the live query",
            )
            .into());
        }
        self.ensure_private_directory()?;
        let _guard = self.lock_mutation()?;
        let entry = CitationCacheEntry {
            schema_version: CITATION_CACHE_SCHEMA_VERSION,
            provider: query.provider,
            query_doi: query.doi.clone(),
            cached_at_unix: now_secs,
            last_accessed_unix: now_secs,
            record: record.clone(),
            record_fingerprint_sha256: record.fingerprint_sha256().map_err(validation_io_error)?,
        };
        let body = serde_json::to_vec(&entry)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if body.len() > MAX_CACHE_ENTRY_BYTES || body.len() as u64 > self.max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "citation cache entry exceeds its bounded policy",
            )
            .into());
        }
        let path = self.entry_path(&Self::cache_key(query));
        self.ensure_replace_target(&path)?;
        crate::util::atomic_write::atomic_write_private(&path, &body)?;
        self.enforce_cap(now_secs)?;
        Ok(())
    }

    fn ensure_private_directory(&self) -> Result<(), CitationCacheError> {
        ensure_no_redirected_ancestor(&self.dir)?;
        match create_private_cache_directory(&self.dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        ensure_no_redirected_ancestor(&self.dir)?;
        verify_private_cache_directory(&self.dir)?;
        Ok(())
    }

    fn lock_mutation(&self) -> Result<CitationCacheMutationGuard<'static>, CitationCacheError> {
        let process_guard = CITATION_CACHE_MUTATION_MUTEX
            .lock()
            .map_err(|_| std::io::Error::other("citation cache mutation mutex poisoned"))?;
        let path = self.dir.join(".citation-cache.lock");
        ensure_regular_or_absent(&path)?;
        let file_guard = crate::util::locked_file::lock_file_blocking(&path, "citation cache")
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        ensure_regular_cache_file(&path)?;
        Ok(CitationCacheMutationGuard {
            _process_guard: process_guard,
            _file_guard: file_guard,
        })
    }

    fn read_cache_child(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        if !fixed_cache_entry_path(&self.dir, path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "citation cache child name is not a fixed digest filename",
            ));
        }
        ensure_regular_cache_file(path)?;
        let file = open_cache_child_nofollow(path)?;
        let metadata = file.metadata()?;
        ensure_regular_metadata(&metadata)?;
        let mut bytes = Vec::new();
        // The cache is local but still untrusted at this boundary: never let a
        // corrupt or replaced fixed-name child allocate beyond the entry cap.
        let mut limited = file.take((MAX_CACHE_ENTRY_BYTES as u64).saturating_add(1));
        limited.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn ensure_replace_target(&self, path: &Path) -> std::io::Result<()> {
        if !fixed_cache_entry_path(&self.dir, path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "citation cache child name is not a fixed digest filename",
            ));
        }
        ensure_regular_or_absent(path)
    }

    fn remove_cache_child(&self, path: &Path) -> std::io::Result<()> {
        if !fixed_cache_entry_path(&self.dir, path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "citation cache child name is not a fixed digest filename",
            ));
        }
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => ensure_regular_metadata(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
        std::fs::remove_file(path)
    }

    /// Deterministic LRU over valid, private fixed-name entries.  Invalid
    /// entries in this dedicated directory are cleaned only when their filename
    /// is a generated 64-hex cache key, never through provider-controlled paths.
    fn enforce_cap(&self, now_secs: u64) -> Result<(), CitationCacheError> {
        let read_dir = std::fs::read_dir(&self.dir)?;
        let mut entries = Vec::new();
        for item in read_dir {
            let path = item?.path();
            if !fixed_cache_entry_path(&self.dir, &path) {
                continue;
            }
            let bytes = self.read_cache_child(&path)?;
            if bytes.len() > MAX_CACHE_ENTRY_BYTES {
                self.remove_cache_child(&path)?;
                continue;
            };
            let Ok(entry) = serde_json::from_slice::<CitationCacheEntry>(&bytes) else {
                self.remove_cache_child(&path)?;
                continue;
            };
            if !entry.valid_at(now_secs, self.ttl_secs) {
                self.remove_cache_child(&path)?;
                continue;
            }
            entries.push((path, entry.last_accessed_unix, bytes.len() as u64));
        }
        entries.sort_by(|left, right| {
            left.1
                .cmp(&right.1)
                .then_with(|| left.0.file_name().cmp(&right.0.file_name()))
        });
        let mut total_bytes = entries.iter().map(|entry| entry.2).sum::<u64>();
        while entries.len() > self.max_entries || total_bytes > self.max_bytes {
            let (path, _, bytes) = entries.remove(0);
            total_bytes = total_bytes.saturating_sub(bytes);
            self.remove_cache_child(&path)?;
        }
        Ok(())
    }
}

fn ensure_no_redirected_ancestor(path: &Path) -> std::io::Result<()> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "citation cache directory contains a redirected path component",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn create_private_cache_directory(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::create_private_directory_new(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir(path)
    }
}

fn verify_private_cache_directory(path: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&metadata)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "citation cache directory is not a direct private directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        // SAFETY: `geteuid` has no preconditions and does not retain a pointer.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "citation cache directory is not owned by the current user",
            ));
        }
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "citation cache directory mode is not 0700",
            ));
        }
        crate::util::darwin_acl::verify_directory_has_no_extended_acl(path)?;
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_directory_dacl(path)?;
    Ok(())
}

fn ensure_regular_or_absent(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => ensure_regular_metadata(&metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn ensure_regular_cache_file(path: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure_regular_metadata(&metadata)
}

fn ensure_regular_metadata(metadata: &std::fs::Metadata) -> std::io::Result<()> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata_is_reparse_point(metadata)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "citation cache child is not a direct regular file",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_cache_child_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    options.open(path)
}

#[cfg(windows)]
fn open_cache_child_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{FromRawHandle as _, RawHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ,
        OPEN_EXISTING,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: the UTF-16 path is NUL-terminated and remains live for this call.
    // OPEN_REPARSE_POINT opens the leaf itself, so the post-open metadata check
    // below sees and rejects every reparse tag instead of its target.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned one owned valid HANDLE on the success path.
    Ok(unsafe { std::fs::File::from_raw_handle(handle as RawHandle) })
}

#[cfg(not(any(unix, windows)))]
fn open_cache_child_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CitationCacheEntry {
    schema_version: u16,
    provider: CitationProvider,
    query_doi: String,
    cached_at_unix: u64,
    last_accessed_unix: u64,
    record: CitationRecord,
    record_fingerprint_sha256: String,
}

impl CitationCacheEntry {
    fn matches(&self, query: &CitationQuery, now_secs: u64, ttl_secs: u64) -> bool {
        self.provider == query.provider
            && self.query_doi == query.doi
            && self.valid_at(now_secs, ttl_secs)
            && self.record.provenance.request_key_sha256 == query.request_key_sha256()
    }

    fn valid_at(&self, now_secs: u64, ttl_secs: u64) -> bool {
        if self.schema_version != CITATION_CACHE_SCHEMA_VERSION
            || self.cached_at_unix > now_secs
            || self.last_accessed_unix > now_secs
            || self.record.fetched_at_unix > now_secs
            || now_secs.saturating_sub(self.cached_at_unix) >= ttl_secs
            || self.record.provenance.source != RecordSource::Live
            || self.record.validate().is_err()
            || !is_sha256_hex(&self.record_fingerprint_sha256)
        {
            return false;
        }
        // This follows the same policy on direct reads and cap sweeps: stale
        // records never compete in LRU eviction with a fresh cache entry.
        match self.record.fingerprint_sha256() {
            Ok(fingerprint) => fingerprint == self.record_fingerprint_sha256,
            Err(_) => false,
        }
    }
}

/// Validation errors are deliberately closed and contain no raw provider data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CitationValidationError {
    Claim,
    Doi,
    QueryBinding,
    ProviderRecordId,
    Title,
    Authors,
    Venue,
    Permalink,
    Provenance,
    SchemaVersion,
}

impl std::fmt::Display for CitationValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Claim => "invalid citation claim",
            Self::Doi => "invalid DOI citation query",
            Self::QueryBinding => "citation record does not bind to the current query",
            Self::ProviderRecordId => "invalid provider citation record id",
            Self::Title => "invalid citation title",
            Self::Authors => "invalid citation authors",
            Self::Venue => "invalid citation venue",
            Self::Permalink => "invalid canonical provider permalink",
            Self::Provenance => "invalid citation provenance",
            Self::SchemaVersion => "unsupported citation schema version",
        })
    }
}

impl std::error::Error for CitationValidationError {}

/// Normalize and bound a claim before cache, authorizer, transport, or display
/// work. CLI and GUI callers must use this one core boundary.
pub fn validate_claim(value: &str) -> Result<String, CitationValidationError> {
    normalize_required_text(value, MAX_CLAIM_BYTES, CitationValidationError::Claim)
}

fn normalize_claim(value: &str) -> Result<String, CitationValidationError> {
    validate_claim(value)
}

fn normalize_doi(value: &str) -> Result<String, CitationValidationError> {
    let mut value = value.trim();
    if let Some(stripped) = value
        .strip_prefix("doi:")
        .or_else(|| value.strip_prefix("DOI:"))
    {
        value = stripped;
    }
    if let Some(stripped) = value
        .strip_prefix("https://doi.org/")
        .or_else(|| value.strip_prefix("http://doi.org/"))
    {
        value = stripped;
    }
    if value.is_empty()
        || value.len() > MAX_QUERY_BYTES
        || !is_printable_ascii(value)
        || value.contains(char::is_whitespace)
        || value.contains('#')
        || value.contains('?')
    {
        return Err(CitationValidationError::Doi);
    }
    let normalized = value.to_ascii_lowercase();
    let Some((prefix, suffix)) = normalized.split_once('/') else {
        return Err(CitationValidationError::Doi);
    };
    let Some(prefix_digits) = prefix.strip_prefix("10.") else {
        return Err(CitationValidationError::Doi);
    };
    if prefix_digits.is_empty()
        || !prefix_digits.as_bytes().iter().all(u8::is_ascii_digit)
        || suffix.is_empty()
    {
        return Err(CitationValidationError::Doi);
    }
    Ok(normalized)
}

fn canonical_record_id(
    provider: CitationProvider,
    value: &str,
) -> Result<String, CitationValidationError> {
    let value = value.trim();
    let canonical = match provider {
        CitationProvider::Crossref => normalize_doi(value)?,
        CitationProvider::OpenAlex => value.to_ascii_uppercase(),
        CitationProvider::SemanticScholar => value.to_ascii_lowercase(),
    };
    if provider.validate_record_id(&canonical) {
        Ok(canonical)
    } else {
        Err(CitationValidationError::ProviderRecordId)
    }
}

fn normalize_required_text(
    value: &str,
    max_bytes: usize,
    error: CitationValidationError,
) -> Result<String, CitationValidationError> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty()
        || normalized.len() > max_bytes
        || normalized.chars().any(|character| character.is_control())
    {
        return Err(error);
    }
    Ok(normalized)
}

fn normalize_authors(authors: &[String]) -> Result<Vec<String>, CitationValidationError> {
    if authors.len() > MAX_AUTHORS {
        return Err(CitationValidationError::Authors);
    }
    let mut total = 0usize;
    let mut normalized = Vec::with_capacity(authors.len());
    for author in authors {
        let author =
            normalize_required_text(author, MAX_AUTHOR_BYTES, CitationValidationError::Authors)?;
        total = total.saturating_add(author.len());
        if total > MAX_AUTHORS_BYTES {
            return Err(CitationValidationError::Authors);
        }
        normalized.push(author);
    }
    Ok(normalized)
}

fn binding_digest(
    claim_sha256: &str,
    record_fingerprint_sha256: &str,
    provider: CitationProvider,
    provider_record_id: &str,
) -> String {
    digest_hex(&[
        BINDING_DOMAIN,
        &CITATION_BINDING_SCHEMA_VERSION.to_le_bytes(),
        claim_sha256.as_bytes(),
        record_fingerprint_sha256.as_bytes(),
        provider.wire_name().as_bytes(),
        provider_record_id.as_bytes(),
    ])
}

fn digest_hex(parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    hex::encode(digest.finalize())
}

fn append_field(target: &mut Vec<u8>, field: &[u8]) {
    target.extend_from_slice(&(field.len() as u64).to_le_bytes());
    target.extend_from_slice(field);
}

fn is_printable_ascii(value: &str) -> bool {
    value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn percent_encode_path(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn fixed_cache_entry_path(dir: &Path, path: &Path) -> bool {
    if path.parent() != Some(dir)
        || path.extension().and_then(|value| value.to_str()) != Some("json")
    {
        return false;
    }
    path.file_stem()
        .and_then(|value| value.to_str())
        .is_some_and(is_sha256_hex)
}

fn validation_io_error(error: CitationValidationError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(provider: CitationProvider, doi: &str) -> CitationQuery {
        CitationQuery::new(provider, doi).unwrap()
    }

    fn live_record(query: &CitationQuery, id: &str, title: &str, now: u64) -> CitationRecord {
        CitationRecord::new(
            query,
            id,
            Some(&query.doi),
            title,
            &["Ada Lovelace".to_string()],
            Some(2026),
            Some("NEOTH Journal"),
            now,
            Some("v1"),
        )
        .unwrap()
    }

    fn cache(
        tmp: &tempfile::TempDir,
        ttl_secs: u64,
        max_entries: usize,
        max_bytes: u64,
    ) -> CitationCache {
        CitationCache::new(
            tmp.path().join("citations"),
            ttl_secs,
            max_entries,
            max_bytes,
        )
        .unwrap()
    }

    #[test]
    fn doi_canonicalization_rejects_arbitrary_urls_and_has_fixed_endpoints() {
        let query = query(
            CitationProvider::Crossref,
            " HTTPS://doi.org/10.1000/ABC.def ",
        );
        assert_eq!(query.doi, "10.1000/abc.def");
        assert_eq!(
            query.fixed_request_url(),
            "https://api.crossref.org/works/10.1000%2Fabc.def"
        );
        assert!(
            CitationQuery::new(CitationProvider::OpenAlex, "https://evil.invalid/10.1/x").is_err()
        );
        assert!(CitationQuery::new(CitationProvider::OpenAlex, "10.1/a?host=evil").is_err());
        assert!(CitationQuery::new(CitationProvider::SemanticScholar, "10.1/a bad").is_err());
        assert!(
            CitationQuery {
                provider: CitationProvider::Crossref,
                doi: "10.1000/Upper".into(),
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn record_fingerprint_and_binding_are_claim_and_identity_bound() {
        let q = query(CitationProvider::Crossref, "10.1000/a");
        let record = live_record(&q, "10.1000/a", "One", 100);
        let binding = ClaimCitationBinding::new("A claim", &record).unwrap();
        assert!(binding.verify_for("A claim", &record));
        assert!(!binding.verify_for("Another claim", &record));

        let other = live_record(&q, "10.1000/a", "Different title", 100);
        assert!(!binding.verify_for("A claim", &other));
        let mut forged = binding.clone();
        forged.provider_record_id = "10.1000/forged".into();
        assert!(!forged.verify_for("A claim", &record));
        let display = CitationLookupResult::from_live(&q, "A claim", record)
            .unwrap()
            .display_for_claim(&q, "A claim")
            .unwrap();
        assert_eq!(display.title, "One");
        assert_eq!(display.authors, vec!["Ada Lovelace"]);
        assert_eq!(display.canonical_doi.as_deref(), Some("10.1000/a"));
    }

    #[test]
    fn record_bounds_and_serialized_invariant_tampering_are_rejected() {
        let q = query(CitationProvider::OpenAlex, "10.1000/a");
        assert!(
            CitationRecord::new(
                &q,
                "W123",
                Some(&q.doi),
                &"x".repeat(MAX_TITLE_BYTES + 1),
                &[],
                None,
                None,
                1,
                None,
            )
            .is_err()
        );
        let mut record = live_record(&q, "W123", "Good", 1);
        record.provider_permalink = "https://evil.invalid/record".into();
        assert!(record.validate().is_err());
    }

    #[test]
    fn cache_rebinds_current_claim_and_is_offline_safe_hit_or_miss() {
        let tmp = tempfile::tempdir().unwrap();
        let q = query(CitationProvider::Crossref, "10.1000/a");
        let cache = cache(&tmp, 100, 8, 100_000);
        cache
            .put(&q, &live_record(&q, "10.1000/a", "One", 10), 10)
            .unwrap();
        let first = cache.get(&q, "claim one", 20).unwrap().unwrap();
        let second = cache.get(&q, "claim two", 20).unwrap().unwrap();
        let CitationLookupResult::Found {
            binding: first,
            source,
            ..
        } = first
        else {
            panic!()
        };
        let CitationLookupResult::Found {
            binding: second,
            source: second_source,
            ..
        } = second
        else {
            panic!()
        };
        assert_eq!(source, LookupSource::Cache);
        assert_eq!(second_source, LookupSource::Cache);
        assert_ne!(first.binding_sha256, second.binding_sha256);
        let expired = cache.lookup_offline(&q, "claim one", 110).unwrap();
        assert_eq!(
            expired,
            CitationLookupResult::unavailable(q.provider, CitationLookupState::OfflineCacheMiss),
            "expired is an explicit offline cache miss"
        );
    }

    #[test]
    fn cache_rejects_corrupt_future_and_fingerprint_mismatch_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let q = query(CitationProvider::OpenAlex, "10.1000/a");
        let cache = cache(&tmp, 100, 8, 100_000);
        cache
            .put(&q, &live_record(&q, "W1", "One", 10), 10)
            .unwrap();
        let path = cache.entry_path(&CitationCache::cache_key(&q));
        std::fs::write(&path, b"not json").unwrap();
        assert!(cache.get(&q, "claim", 20).unwrap().is_none());
        assert!(!path.exists());

        cache
            .put(&q, &live_record(&q, "W1", "One", 30), 30)
            .unwrap();
        assert!(
            cache.get(&q, "claim", 20).unwrap().is_none(),
            "future entry is evicted"
        );
        cache
            .put(&q, &live_record(&q, "W1", "One", 40), 40)
            .unwrap();
        let mut entry: CitationCacheEntry =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        entry.record_fingerprint_sha256 = "0".repeat(64);
        std::fs::write(&path, serde_json::to_vec(&entry).unwrap()).unwrap();
        assert!(cache.get(&q, "claim", 50).unwrap().is_none());
    }

    #[test]
    fn cache_capacity_and_atomic_replacement_keep_only_valid_bounded_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = cache(&tmp, 1000, 2, 2_000);
        for (index, doi) in ["10.1000/a", "10.1000/b", "10.1000/c"].iter().enumerate() {
            let q = query(CitationProvider::Crossref, doi);
            cache
                .put(
                    &q,
                    &live_record(&q, doi, doi, 10 + index as u64),
                    10 + index as u64,
                )
                .unwrap();
        }
        let names: Vec<_> = std::fs::read_dir(tmp.path().join("citations"))
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names.iter().filter(|name| name.ends_with(".json")).count(),
            2
        );
        assert!(names.iter().all(|name| !name.ends_with(".tmp")));
        let total_bytes: u64 = std::fs::read_dir(tmp.path().join("citations"))
            .unwrap()
            .flatten()
            .filter_map(|entry| entry.metadata().ok())
            .map(|metadata| metadata.len())
            .sum();
        assert!(total_bytes <= 2_000, "byte cap is enforced with count cap");

        let q = query(CitationProvider::Crossref, "10.1000/c");
        cache
            .put(&q, &live_record(&q, "10.1000/c", "Replacement", 20), 20)
            .unwrap();
        let CitationLookupResult::Found { record, .. } =
            cache.get(&q, "claim", 21).unwrap().unwrap()
        else {
            panic!()
        };
        assert_eq!(record.title, "Replacement");
    }

    #[test]
    fn query_aware_live_constructor_rejects_record_reassociation() {
        let query_a = query(CitationProvider::Crossref, "10.1000/a");
        let query_b = query(CitationProvider::Crossref, "10.1000/b");
        let result_a = CitationLookupResult::from_live(
            &query_a,
            "claim",
            live_record(&query_a, "10.1000/a", "One", 1),
        )
        .unwrap();
        assert!(!result_a.validate_for_claim(&query_b, "claim"));
        assert!(result_a.display_for_claim(&query_b, "claim").is_none());
        let mut record = live_record(&query_a, "10.1000/a", "One", 1);
        record.canonical_doi = Some(query_b.doi.clone());
        record.provider_permalink = record
            .provider
            .canonical_permalink(&record.provider_record_id, record.canonical_doi.as_deref());
        assert!(CitationLookupResult::from_live(&query_a, "claim", record.clone()).is_err());
        assert!(
            CitationAdapterOutcome::Record(Box::new(record))
                .into_lookup_result(&query_a, "claim")
                .is_err()
        );
        assert!(CitationCache::new(std::env::temp_dir().join("citation-zero"), 0, 1, 1).is_err());
    }

    #[test]
    fn cache_touch_cannot_silently_exceed_its_byte_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let q = query(CitationProvider::Crossref, "10.1000/a");
        let mut cache = cache(&tmp, 100, 8, 100_000);
        cache
            .put(&q, &live_record(&q, "10.1000/a", "One", 9), 9)
            .unwrap();
        let path = cache.entry_path(&CitationCache::cache_key(&q));
        cache.max_bytes = std::fs::metadata(path).unwrap().len();
        assert!(
            cache.get(&q, "claim", 10).is_err(),
            "touch growth is observable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_rejects_fixed_name_final_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let q = query(CitationProvider::Crossref, "10.1000/a");
        let cache = cache(&tmp, 100, 8, 100_000);
        cache
            .put(&q, &live_record(&q, "10.1000/a", "One", 1), 1)
            .unwrap();
        let path = cache.entry_path(&CitationCache::cache_key(&q));
        std::fs::remove_file(&path).unwrap();
        let outside = tmp.path().join("outside.json");
        std::fs::write(&outside, b"outside stays untouched").unwrap();
        symlink(&outside, &path).unwrap();
        assert!(cache.get(&q, "claim", 2).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside stays untouched");
    }
}
