//! One-time desktop-GUI consent for one live citation lookup.
//!
//! This is deliberately separate from chat consent.  The only authority it
//! can yield is an opaque, consumed proof for one normalized provider/DOI,
//! normalized claim, GUI request revision, and `freedom.yaml` generation.
//! It never stores a DOI, claim, URL, request body, or reusable permission.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::FreedomConfig;
use crate::permissions::{self, Action, Decision};
use crate::tools::citation_lookup::{CitationProvider, CitationQuery, validate_claim};
use crate::tools::external_http::{ExternalHttpRequest, ExternalHttpSurface};

/// Both records are intentionally short-lived.  A proof starts only after an
/// explicit Approve and is consumed before the external-HTTP gate is reached.
pub(crate) const CITATION_CONSENT_TTL_SECS: u64 = 120;
const RECORD_VERSION: u16 = 1;
const MAX_RECORD_BYTES: usize = 8 * 1024;
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 256;
const MAX_GUI_REQUEST_ID_BYTES: usize = 128;
const SHA256_HEX_LEN: usize = 64;

const CHALLENGE_FILE_DOMAIN: &[u8] = b"neoth.citation-consent.challenge-file.v1\0";
const PROOF_FILE_DOMAIN: &[u8] = b"neoth.citation-consent.proof-file.v1\0";
const CLAIM_DOMAIN: &[u8] = b"neoth.citation-consent.claim.v1\0";
const GUI_REQUEST_DOMAIN: &[u8] = b"neoth.citation-consent.gui-request.v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CitationConsentDecision {
    Approve,
    Deny,
}

/// A preflight answer is display-safe except for the challenge token.  The
/// GUI must keep that token in its private child pipe and never put it in a
/// command line, model prompt, log, or user-visible status string.
pub(crate) enum CitationConsentPreflight {
    Ready,
    ConfirmationRequired {
        challenge_token: Zeroizing<String>,
        expires_unix: u64,
        request_key_sha256: String,
    },
    Denied,
}

impl fmt::Debug for CitationConsentPreflight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => formatter.write_str("CitationConsentPreflight::Ready"),
            Self::ConfirmationRequired {
                expires_unix,
                request_key_sha256,
                ..
            } => formatter
                .debug_struct("CitationConsentPreflight::ConfirmationRequired")
                .field("challenge_token", &"<redacted>")
                .field("expires_unix", expires_unix)
                .field("request_key_sha256", request_key_sha256)
                .finish(),
            Self::Denied => formatter.write_str("CitationConsentPreflight::Denied"),
        }
    }
}

/// A proof can only be created by [`consume_gui_citation_lookup_approval`].
/// Its fields are private so a caller cannot turn a preconfirmation string or
/// an old chat approval into citation egress authority.
pub(crate) struct ConsumedGuiCitationLookupApproval {
    request_key_sha256: String,
    claim_sha256: String,
    gui_request_sha256: String,
    config_sha256: String,
    provider: CitationProvider,
}

impl fmt::Debug for ConsumedGuiCitationLookupApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumedGuiCitationLookupApproval")
            .field("request_key_sha256", &"<redacted>")
            .field("claim_sha256", &"<redacted>")
            .field("gui_request_sha256", &"<redacted>")
            .field("config_sha256", &"<redacted>")
            .field("provider", &self.provider)
            .finish()
    }
}

impl ConsumedGuiCitationLookupApproval {
    /// The external-HTTP integration must call this immediately before it
    /// attaches `gui_citation_lookup` to a Gate.  It verifies the entire
    /// fixed citation request shape, including an empty body.  It does not
    /// accept a generic surface label or arbitrary URL as proof of authority.
    pub(crate) fn authorizes_fixed_get(
        &self,
        query: &CitationQuery,
        claim: &str,
        gui_request_id: &str,
        current_config_sha256: &str,
        request: &ExternalHttpRequest,
    ) -> bool {
        self.matches_lookup(query, claim, gui_request_id, current_config_sha256)
            && request.is_fixed_citation_get_for(query)
    }

    /// Internal binding for the existing authorizer hook.  These hashes never
    /// leave the process and are intentionally not a generic confirmation ID.
    fn matches_lookup(
        &self,
        query: &CitationQuery,
        claim: &str,
        gui_request_id: &str,
        current_config_sha256: &str,
    ) -> bool {
        let Ok(claim_sha256) = claim_digest(claim) else {
            return false;
        };
        let Ok(gui_request_sha256) = gui_request_digest(gui_request_id) else {
            return false;
        };
        query.validate().is_ok()
            && query.provider == self.provider
            && query.request_key_sha256() == self.request_key_sha256
            && claim_sha256 == self.claim_sha256
            && gui_request_sha256 == self.gui_request_sha256
            && current_config_sha256 == self.config_sha256
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationChallengeRecord {
    version: u16,
    id: String,
    secret_sha256: String,
    provider: CitationProvider,
    request_key_sha256: String,
    claim_sha256: String,
    gui_request_sha256: String,
    config_sha256: String,
    created_unix: u64,
    expires_unix: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationProofRecord {
    version: u16,
    id: String,
    secret_sha256: String,
    provider: CitationProvider,
    request_key_sha256: String,
    claim_sha256: String,
    gui_request_sha256: String,
    config_sha256: String,
    created_unix: u64,
    expires_unix: u64,
}

struct CitationRecordLiveness<'a> {
    version: u16,
    id: &'a str,
    secret_sha256: &'a str,
    request_key_sha256: &'a str,
    claim_sha256: &'a str,
    gui_request_sha256: &'a str,
    config_sha256: &'a str,
    created_unix: u64,
    expires_unix: u64,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct TokenParts {
    id: String,
    secret: String,
}

fn store_dir(home: &Path) -> PathBuf {
    home.join("consent").join(".gui-citation")
}

fn challenge_dir(home: &Path) -> PathBuf {
    store_dir(home).join("challenges")
}

fn proof_dir(home: &Path) -> PathBuf {
    store_dir(home).join("proofs")
}

/// The only record filenames are domain-separated SHA-256 values of an
/// opaque random UUID.  No DOI, claim, request ID, or secret appears in a
/// directory entry.
fn record_file_name(kind_domain: &[u8], id: &str) -> Result<OsString> {
    let id = canonical_uuid(id)?;
    let name = domain_hash(kind_domain, &[id.as_bytes()]);
    if kind_domain != CHALLENGE_FILE_DOMAIN && kind_domain != PROOF_FILE_DOMAIN {
        anyhow::bail!("invalid citation consent record domain")
    }
    Ok(OsString::from(format!("{name}.json")))
}

struct CitationRecordSlot {
    dir: cap_std::fs::Dir,
    file_name: OsString,
    display_path: PathBuf,
}

struct CitationRecordLock {
    _file: std::fs::File,
    binding: crate::skills::store::BoundChildObject,
    lock_name: OsString,
    lock_path: PathBuf,
}

impl CitationRecordLock {
    fn verify_current(&self, slot: &CitationRecordSlot) -> Result<()> {
        anyhow::ensure!(
            self.binding.matches_regular_file_child_readonly(
                &slot.dir,
                &self.lock_name,
                &self.lock_path,
            )?,
            "citation consent lock changed before record operation"
        );
        Ok(())
    }
}

fn verify_private_store_dir(dir: &cap_std::fs::Dir, display_path: &Path) -> Result<()> {
    let metadata = dir.dir_metadata().with_context(|| {
        format!(
            "inspect private citation consent directory {}",
            display_path.display()
        )
    })?;
    anyhow::ensure!(
        metadata.is_dir() && !crate::skills::store::cap_metadata_is_link_like(&metadata),
        "citation consent namespace is not a real non-link directory"
    );
    crate::util::darwin_acl::verify_directory_has_no_extended_acl(display_path)
        .with_context(|| "verify private citation consent directory ACL")?;
    #[cfg(unix)]
    {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o7777 == 0o700,
            "citation consent namespace is not current-user private"
        );
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_directory_handle_dacl(dir)
        .with_context(|| "verify private citation consent directory DACL")?;
    Ok(())
}

/// Build the record/lock namespace from the trusted NEOTH home capability.
/// Every component below `home` is opened or created no-follow, then both
/// private descendants are checked through their retained directory handles.
fn record_slot(home: &Path, kind_domain: &[u8], id: &str) -> Result<CitationRecordSlot> {
    let consent_path = home.join("consent");
    let consent = crate::skills::store::open_bound_directory_from_trusted_anchor(
        home,
        &consent_path,
        true,
        "citation consent parent",
    )?
    .ok_or_else(|| anyhow::anyhow!("citation consent parent is unavailable"))?;
    let root_path = store_dir(home);
    let root = crate::skills::store::open_or_create_private_child_dir(
        &consent.dir,
        OsStr::new(".gui-citation"),
        &root_path,
    )?;
    verify_private_store_dir(&root, &root_path)?;
    let (child_name, child_path) = if kind_domain == CHALLENGE_FILE_DOMAIN {
        ("challenges", challenge_dir(home))
    } else if kind_domain == PROOF_FILE_DOMAIN {
        ("proofs", proof_dir(home))
    } else {
        anyhow::bail!("invalid citation consent record domain")
    };
    let dir = crate::skills::store::open_or_create_private_child_dir(
        &root,
        OsStr::new(child_name),
        &child_path,
    )?;
    verify_private_store_dir(&dir, &child_path)?;
    let file_name = record_file_name(kind_domain, id)?;
    let display_path = child_path.join(&file_name);
    Ok(CitationRecordSlot {
        dir,
        file_name,
        display_path,
    })
}

fn record_lock(slot: &CitationRecordSlot) -> Result<CitationRecordLock> {
    let lock_name = OsString::from(format!("{}.lock", slot.file_name.to_string_lossy()));
    let lock_path = slot.display_path.with_extension("lock");
    let (file, binding) =
        crate::skills::store::open_or_create_bound_lockfile(&slot.dir, &lock_name, &lock_path)?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= Duration::from_secs(5) {
                    anyhow::bail!("citation consent record lock held for >5s")
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).context("lock citation consent record");
            }
        }
    }
    anyhow::ensure!(
        binding.matches_regular_file_child_readonly(&slot.dir, &lock_name, &lock_path)?,
        "citation consent lock changed while it was acquired"
    );
    Ok(CitationRecordLock {
        _file: file,
        binding,
        lock_name,
        lock_path,
    })
}

fn canonical_uuid(value: &str) -> Result<String> {
    let parsed = uuid::Uuid::parse_str(value).context("invalid citation consent record id")?;
    let canonical = parsed.hyphenated().to_string();
    anyhow::ensure!(
        value == canonical,
        "citation consent record id must be a canonical lowercase UUID"
    );
    Ok(canonical)
}

fn domain_hash(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hex::encode(hasher.finalize())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn random_secret() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(bytes.as_mut()).context("generate citation consent secret")?;
    Ok(Zeroizing::new(hex::encode(bytes.as_ref())))
}

fn secrets_equal(candidate: &str, expected_sha256: &str) -> bool {
    let actual = Sha256::digest(candidate.as_bytes());
    let Ok(expected) = hex::decode(expected_sha256) else {
        return false;
    };
    bool::from(actual.as_slice().ct_eq(expected.as_slice()))
}

fn claim_digest(claim: &str) -> Result<String> {
    let claim = validate_claim(claim).context("validate citation claim")?;
    Ok(domain_hash(CLAIM_DOMAIN, &[claim.as_bytes()]))
}

fn gui_request_digest(request_id: &str) -> Result<String> {
    anyhow::ensure!(
        !request_id.is_empty()
            && request_id.len() <= MAX_GUI_REQUEST_ID_BYTES
            && request_id
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') }),
        "invalid opaque GUI citation request id"
    );
    Ok(domain_hash(GUI_REQUEST_DOMAIN, &[request_id.as_bytes()]))
}

fn surface_for(provider: CitationProvider) -> ExternalHttpSurface {
    match provider {
        CitationProvider::Crossref => ExternalHttpSurface::Crossref,
        CitationProvider::OpenAlex => ExternalHttpSurface::OpenAlex,
        CitationProvider::SemanticScholar => ExternalHttpSurface::SemanticScholar,
    }
}

fn write_record<T: Serialize>(home: &Path, kind_domain: &[u8], id: &str, record: &T) -> Result<()> {
    let bytes = serde_json::to_vec(record).context("serialize citation consent record")?;
    anyhow::ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "citation consent record exceeds its size limit"
    );
    let slot = record_slot(home, kind_domain, id)?;
    crate::skills::store::atomic_write_private_child_create_new(
        &slot.dir,
        &slot.file_name,
        &slot.display_path,
        &bytes,
    )
    .with_context(|| "create private citation consent record")
}

fn read_record<T: for<'de> Deserialize<'de>>(slot: &CitationRecordSlot) -> Result<T> {
    let bytes = crate::skills::store::read_regular_file_bounded(
        &slot.dir,
        &slot.file_name,
        &slot.display_path,
        MAX_RECORD_BYTES,
    )?;
    serde_json::from_slice(&bytes).context("parse citation consent record")
}

fn consume_record(slot: &CitationRecordSlot) -> Result<()> {
    anyhow::ensure!(
        crate::skills::store::remove_child_file_if_present(
            &slot.dir,
            &slot.file_name,
            &slot.display_path,
        )?,
        "citation consent record was already consumed"
    );
    let _ = crate::skills::store::sync_parent_directory(&slot.dir, &slot.display_path)
        .with_context(|| "durably consume citation consent record")?;
    Ok(())
}

fn split_token(token: &str) -> Result<TokenParts> {
    anyhow::ensure!(
        !token.is_empty() && token.len() <= MAX_TOKEN_BYTES,
        "citation consent token is missing or too large"
    );
    let (id, secret) = token
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("invalid citation consent token"))?;
    anyhow::ensure!(
        !secret.is_empty() && !secret.contains('.') && secret.len() == SHA256_HEX_LEN,
        "invalid citation consent token"
    );
    canonical_uuid(id)?;
    anyhow::ensure!(
        secret.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid citation consent token"
    );
    Ok(TokenParts {
        id: id.to_owned(),
        secret: secret.to_owned(),
    })
}

fn record_is_live(record: CitationRecordLiveness<'_>, now: u64) -> Result<()> {
    anyhow::ensure!(
        record.version == RECORD_VERSION,
        "unsupported citation consent record version"
    );
    canonical_uuid(record.id)?;
    for value in [
        record.secret_sha256,
        record.request_key_sha256,
        record.claim_sha256,
        record.gui_request_sha256,
        record.config_sha256,
    ] {
        anyhow::ensure!(
            is_sha256_hex(value),
            "invalid citation consent record binding"
        );
    }
    anyhow::ensure!(
        record.created_unix <= now
            && record.expires_unix > record.created_unix
            && record.expires_unix.saturating_sub(record.created_unix) <= CITATION_CONSENT_TTL_SECS
            && now <= record.expires_unix,
        "citation consent record is expired or has an invalid clock"
    );
    Ok(())
}

fn assert_challenge(
    record: &CitationChallengeRecord,
    token: &TokenParts,
    query: &CitationQuery,
    claim_sha256: &str,
    gui_request_sha256: &str,
    config_sha256: &str,
    now: u64,
) -> Result<()> {
    record_is_live(
        CitationRecordLiveness {
            version: record.version,
            id: &record.id,
            secret_sha256: &record.secret_sha256,
            request_key_sha256: &record.request_key_sha256,
            claim_sha256: &record.claim_sha256,
            gui_request_sha256: &record.gui_request_sha256,
            config_sha256: &record.config_sha256,
            created_unix: record.created_unix,
            expires_unix: record.expires_unix,
        },
        now,
    )?;
    anyhow::ensure!(
        record.id == token.id
            && secrets_equal(&token.secret, &record.secret_sha256)
            && record.provider == query.provider
            && record.request_key_sha256 == query.request_key_sha256()
            && record.claim_sha256 == claim_sha256
            && record.gui_request_sha256 == gui_request_sha256
            && record.config_sha256 == config_sha256,
        "citation consent challenge does not match this lookup"
    );
    Ok(())
}

fn assert_proof(
    record: &CitationProofRecord,
    token: &TokenParts,
    query: &CitationQuery,
    claim_sha256: &str,
    gui_request_sha256: &str,
    config_sha256: &str,
    now: u64,
) -> Result<()> {
    record_is_live(
        CitationRecordLiveness {
            version: record.version,
            id: &record.id,
            secret_sha256: &record.secret_sha256,
            request_key_sha256: &record.request_key_sha256,
            claim_sha256: &record.claim_sha256,
            gui_request_sha256: &record.gui_request_sha256,
            config_sha256: &record.config_sha256,
            created_unix: record.created_unix,
            expires_unix: record.expires_unix,
        },
        now,
    )?;
    anyhow::ensure!(
        record.id == token.id
            && secrets_equal(&token.secret, &record.secret_sha256)
            && record.provider == query.provider
            && record.request_key_sha256 == query.request_key_sha256()
            && record.claim_sha256 == claim_sha256
            && record.gui_request_sha256 == gui_request_sha256
            && record.config_sha256 == config_sha256,
        "citation consent proof does not match this lookup"
    );
    Ok(())
}

fn open_config_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::File::open(path)
    }
}

fn metadata_is_link_like(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Hash the exact bytes read from one stable, bounded, no-follow config handle.
/// The policy preview is parsed from those same bytes; a changed generation is
/// rejected at decision and final proof consumption.
fn config_snapshot(home: &Path) -> Result<(FreedomConfig, String)> {
    let path = home.join("freedom.yaml");
    for _ in 0..3 {
        let mut file = open_config_no_follow(&path).context("open citation consent config")?;
        let before = file.metadata().context("inspect citation consent config")?;
        anyhow::ensure!(
            before.file_type().is_file()
                && !metadata_is_link_like(&before)
                && before.len() <= MAX_CONFIG_BYTES,
            "citation consent config must be a bounded regular non-link file"
        );
        let mut bytes = Zeroizing::new(Vec::with_capacity(before.len() as usize));
        file.seek(SeekFrom::Start(0))
            .context("seek citation consent config")?;
        (&mut file)
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("read citation consent config")?;
        let after = file
            .metadata()
            .context("reinspect citation consent config")?;
        if bytes.len() as u64 != before.len()
            || before.len() != after.len()
            || !after.file_type().is_file()
            || metadata_is_link_like(&after)
        {
            continue;
        }
        let config = serde_yaml::from_slice(&bytes).context("parse citation consent config")?;
        return Ok((config, sha256(bytes.as_slice())));
    }
    anyhow::bail!("citation consent config changed repeatedly during snapshot")
}

/// Obtain the exact policy and generation from one bounded, no-follow config
/// read. The GUI proof hook must use this pair when it constructs the final
/// authorizer: a config replacement cannot pair a newer policy with an older
/// proof-generation check (or the reverse).
pub(crate) fn current_citation_consent_policy_generation(
    home: &Path,
) -> Result<(crate::permissions::AutonomyPolicySnapshot, String)> {
    config_snapshot(home).map(|(config, generation)| (config.autonomy_policy(), generation))
}

fn preflight_action(query: &CitationQuery) -> Action {
    Action::ExternalHttpRequest {
        method: "GET".to_owned(),
        destination: query.provider.origin().to_owned(),
        surface: surface_for(query.provider).as_str().to_owned(),
        // The final authorizer creates its own audit correlation.  Policy is
        // action-kind based, while the proof itself carries the exact request.
        request_id: "gui_citation_preflight".to_owned(),
        request_binding_sha256: query.request_key_sha256(),
    }
}

fn create_challenge_at(
    home: &Path,
    query: &CitationQuery,
    claim: &str,
    gui_request_id: &str,
    config_sha256: &str,
    now: u64,
) -> Result<Zeroizing<String>> {
    query.validate().context("validate citation query")?;
    anyhow::ensure!(
        is_sha256_hex(config_sha256),
        "invalid citation consent config generation"
    );
    let claim_sha256 = claim_digest(claim)?;
    let gui_request_sha256 = gui_request_digest(gui_request_id)?;
    let id = uuid::Uuid::now_v7().hyphenated().to_string();
    let secret = random_secret()?;
    let record = CitationChallengeRecord {
        version: RECORD_VERSION,
        id: id.clone(),
        secret_sha256: sha256(secret.as_bytes()),
        provider: query.provider,
        request_key_sha256: query.request_key_sha256(),
        claim_sha256,
        gui_request_sha256,
        config_sha256: config_sha256.to_owned(),
        created_unix: now,
        expires_unix: now.saturating_add(CITATION_CONSENT_TTL_SECS),
    };
    write_record(home, CHALLENGE_FILE_DOMAIN, &id, &record)?;
    Ok(Zeroizing::new(format!("{id}.{}", secret.as_str())))
}

/// Preflight for a live cache miss only.  Cache and offline handling stay in
/// `citation_http::lookup_cache_first`; callers must not invoke this facade
/// for either of those paths, because neither path may mint or consume proof.
pub(crate) fn create_gui_citation_lookup_preflight(
    home: &Path,
    query: &CitationQuery,
    claim: &str,
    gui_request_id: &str,
    now: u64,
    live_miss: crate::tools::citation_http::GuiCitationLiveMiss,
) -> Result<CitationConsentPreflight> {
    query.validate().context("validate citation query")?;
    anyhow::ensure!(
        live_miss.matches_lookup(query, claim),
        "GUI citation live-miss capability does not match this lookup"
    );
    let _ = claim_digest(claim)?;
    let _ = gui_request_digest(gui_request_id)?;
    let (config, config_sha256) = config_snapshot(home)?;
    match permissions::evaluate(&preflight_action(query), &config.autonomy_policy()) {
        Decision::Allow => Ok(CitationConsentPreflight::Ready),
        Decision::Deny(_) => Ok(CitationConsentPreflight::Denied),
        Decision::Confirm(_) => {
            let token =
                create_challenge_at(home, query, claim, gui_request_id, &config_sha256, now)?;
            Ok(CitationConsentPreflight::ConfirmationRequired {
                challenge_token: token,
                expires_unix: now.saturating_add(CITATION_CONSENT_TTL_SECS),
                request_key_sha256: query.request_key_sha256(),
            })
        }
    }
}

/// Process one explicit GUI Approve or Cancel.  Both decisions consume the
/// exact challenge under its lock.  On Approve the challenge is removed before
/// a proof is written: an interrupted handoff can lose an approval but cannot
/// leave two usable proofs or reopen an already-decided challenge.
fn decide_at(
    home: &Path,
    challenge_token: &str,
    query: &CitationQuery,
    claim_sha256: &str,
    gui_request_sha256: &str,
    config_sha256: &str,
    decision: CitationConsentDecision,
    now: u64,
) -> Result<Option<Zeroizing<String>>> {
    query.validate().context("validate citation query")?;
    anyhow::ensure!(
        is_sha256_hex(claim_sha256)
            && is_sha256_hex(gui_request_sha256)
            && is_sha256_hex(config_sha256),
        "invalid citation consent decision binding"
    );
    let token = split_token(challenge_token)?;
    let slot = record_slot(home, CHALLENGE_FILE_DOMAIN, &token.id)?;
    let lock = record_lock(&slot)?;
    lock.verify_current(&slot)?;
    let record: CitationChallengeRecord = read_record(&slot)?;
    assert_challenge(
        &record,
        &token,
        query,
        claim_sha256,
        gui_request_sha256,
        config_sha256,
        now,
    )?;
    lock.verify_current(&slot)?;
    consume_record(&slot)?;
    drop(lock);

    if decision == CitationConsentDecision::Deny {
        return Ok(None);
    }
    let proof_id = uuid::Uuid::now_v7().hyphenated().to_string();
    let proof_secret = random_secret()?;
    let proof = CitationProofRecord {
        version: RECORD_VERSION,
        id: proof_id.clone(),
        secret_sha256: sha256(proof_secret.as_bytes()),
        provider: query.provider,
        request_key_sha256: query.request_key_sha256(),
        claim_sha256: claim_sha256.to_owned(),
        gui_request_sha256: gui_request_sha256.to_owned(),
        config_sha256: config_sha256.to_owned(),
        created_unix: now,
        expires_unix: now.saturating_add(CITATION_CONSENT_TTL_SECS),
    };
    write_record(home, PROOF_FILE_DOMAIN, &proof_id, &proof)?;
    Ok(Some(Zeroizing::new(format!(
        "{proof_id}.{}",
        proof_secret.as_str()
    ))))
}

pub(crate) fn decide_gui_citation_lookup(
    home: &Path,
    challenge_token: &str,
    query: &CitationQuery,
    claim: &str,
    gui_request_id: &str,
    decision: CitationConsentDecision,
    now: u64,
) -> Result<Option<Zeroizing<String>>> {
    let claim_sha256 = claim_digest(claim)?;
    let gui_request_sha256 = gui_request_digest(gui_request_id)?;
    let (_, config_sha256) = config_snapshot(home)?;
    decide_at(
        home,
        challenge_token,
        query,
        &claim_sha256,
        &gui_request_sha256,
        &config_sha256,
        decision,
        now,
    )
}

/// Consume a proof before the existing `ExternalHttpAuthorizer` executes.  A
/// malformed, expired, future-dated, mismatched, or replayed record is a hard
/// failure.  Returning this opaque type is the only success path.
fn consume_at(
    home: &Path,
    proof_token: &str,
    query: &CitationQuery,
    claim_sha256: &str,
    gui_request_sha256: &str,
    config_sha256: &str,
    now: u64,
) -> Result<ConsumedGuiCitationLookupApproval> {
    query.validate().context("validate citation query")?;
    anyhow::ensure!(
        is_sha256_hex(claim_sha256)
            && is_sha256_hex(gui_request_sha256)
            && is_sha256_hex(config_sha256),
        "invalid citation consent consume binding"
    );
    let token = split_token(proof_token)?;
    let slot = record_slot(home, PROOF_FILE_DOMAIN, &token.id)?;
    let lock = record_lock(&slot)?;
    lock.verify_current(&slot)?;
    let record: CitationProofRecord = read_record(&slot)?;
    assert_proof(
        &record,
        &token,
        query,
        claim_sha256,
        gui_request_sha256,
        config_sha256,
        now,
    )?;
    lock.verify_current(&slot)?;
    consume_record(&slot)?;
    drop(lock);
    Ok(ConsumedGuiCitationLookupApproval {
        request_key_sha256: record.request_key_sha256,
        claim_sha256: record.claim_sha256,
        gui_request_sha256: record.gui_request_sha256,
        config_sha256: record.config_sha256,
        provider: record.provider,
    })
}

pub(crate) fn consume_gui_citation_lookup_approval(
    home: &Path,
    proof_token: &str,
    query: &CitationQuery,
    claim: &str,
    gui_request_id: &str,
    now: u64,
) -> Result<ConsumedGuiCitationLookupApproval> {
    let claim_sha256 = claim_digest(claim)?;
    let gui_request_sha256 = gui_request_digest(gui_request_id)?;
    let (_, config_sha256) = config_snapshot(home)?;
    consume_at(
        home,
        proof_token,
        query,
        &claim_sha256,
        &gui_request_sha256,
        &config_sha256,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CONFIG_A: &str = "a1";
    const TEST_CONFIG_B: &str = "b2";

    fn config_hash(marker: &str) -> String {
        sha256(marker.as_bytes())
    }

    fn query() -> CitationQuery {
        CitationQuery::new(CitationProvider::Crossref, "10.1000/example").unwrap()
    }

    fn issue_challenge(home: &Path, now: u64) -> Zeroizing<String> {
        create_challenge_at(
            home,
            &query(),
            "the concrete claim",
            "gui-revision-7",
            &config_hash(TEST_CONFIG_A),
            now,
        )
        .unwrap()
    }

    #[test]
    fn store_create_consume_and_replay_are_one_shot() {
        let home = tempfile::tempdir().unwrap();
        let challenge = issue_challenge(home.path(), 100);
        let proof = decide_at(
            home.path(),
            challenge.as_str(),
            &query(),
            &claim_digest("the concrete claim").unwrap(),
            &gui_request_digest("gui-revision-7").unwrap(),
            &config_hash(TEST_CONFIG_A),
            CitationConsentDecision::Approve,
            101,
        )
        .unwrap()
        .unwrap();
        let consumed = consume_at(
            home.path(),
            proof.as_str(),
            &query(),
            &claim_digest("the concrete claim").unwrap(),
            &gui_request_digest("gui-revision-7").unwrap(),
            &config_hash(TEST_CONFIG_A),
            102,
        )
        .unwrap();
        assert!(consumed.matches_lookup(
            &query(),
            "the concrete claim",
            "gui-revision-7",
            &config_hash(TEST_CONFIG_A)
        ));
        let fixed_request = ExternalHttpRequest::get(
            query().fixed_request_url(),
            ExternalHttpSurface::Crossref,
        );
        assert!(consumed.authorizes_fixed_get(
            &query(),
            "the concrete claim",
            "gui-revision-7",
            &config_hash(TEST_CONFIG_A),
            &fixed_request
        ));
        assert!(!consumed.authorizes_fixed_get(
            &query(),
            "changed claim",
            "gui-revision-7",
            &config_hash(TEST_CONFIG_A),
            &fixed_request
        ));
        assert!(!consumed.authorizes_fixed_get(
            &query(),
            "the concrete claim",
            "gui-revision-8",
            &config_hash(TEST_CONFIG_A),
            &fixed_request
        ));
        assert!(
            consume_at(
                home.path(),
                proof.as_str(),
                &query(),
                &claim_digest("the concrete claim").unwrap(),
                &gui_request_digest("gui-revision-7").unwrap(),
                &config_hash(TEST_CONFIG_A),
                103
            )
            .is_err()
        );
    }

    #[test]
    fn mismatch_and_expiry_fail_before_consumption() {
        let home = tempfile::tempdir().unwrap();
        let challenge = issue_challenge(home.path(), 300);
        let proof = decide_at(
            home.path(),
            challenge.as_str(),
            &query(),
            &claim_digest("the concrete claim").unwrap(),
            &gui_request_digest("gui-revision-7").unwrap(),
            &config_hash(TEST_CONFIG_A),
            CitationConsentDecision::Approve,
            301,
        )
        .unwrap()
        .unwrap();
        assert!(
            consume_at(
                home.path(),
                proof.as_str(),
                &query(),
                &claim_digest("other claim").unwrap(),
                &gui_request_digest("gui-revision-7").unwrap(),
                &config_hash(TEST_CONFIG_A),
                302
            )
            .is_err()
        );
        assert!(
            consume_at(
                home.path(),
                proof.as_str(),
                &query(),
                &claim_digest("the concrete claim").unwrap(),
                &gui_request_digest("gui-revision-7").unwrap(),
                &config_hash(TEST_CONFIG_A),
                422
            )
            .is_err()
        );
    }

    #[test]
    fn deny_consumes_exact_challenge_without_proof() {
        let home = tempfile::tempdir().unwrap();
        let token = issue_challenge(home.path(), 100);
        assert!(
            decide_at(
                home.path(),
                token.as_str(),
                &query(),
                &claim_digest("the concrete claim").unwrap(),
                &gui_request_digest("gui-revision-7").unwrap(),
                &config_hash(TEST_CONFIG_A),
                CitationConsentDecision::Deny,
                101
            )
            .unwrap()
            .is_none()
        );
        assert!(
            decide_at(
                home.path(),
                token.as_str(),
                &query(),
                &claim_digest("the concrete claim").unwrap(),
                &gui_request_digest("gui-revision-7").unwrap(),
                &config_hash(TEST_CONFIG_A),
                CitationConsentDecision::Deny,
                102
            )
            .is_err()
        );
    }

    #[test]
    fn config_generation_invalidation_fails_closed() {
        let home = tempfile::tempdir().unwrap();
        let challenge = issue_challenge(home.path(), 100);
        let proof = decide_at(
            home.path(),
            challenge.as_str(),
            &query(),
            &claim_digest("the concrete claim").unwrap(),
            &gui_request_digest("gui-revision-7").unwrap(),
            &config_hash(TEST_CONFIG_A),
            CitationConsentDecision::Approve,
            101,
        )
        .unwrap()
        .unwrap();
        assert!(
            consume_at(
                home.path(),
                proof.as_str(),
                &query(),
                &claim_digest("the concrete claim").unwrap(),
                &gui_request_digest("gui-revision-7").unwrap(),
                &config_hash(TEST_CONFIG_B),
                102
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_store_rejects_redirected_or_non_private_namespace() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let redirected_home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), redirected_home.path().join("consent")).unwrap();
        assert!(
            create_challenge_at(
                redirected_home.path(),
                &query(),
                "the concrete claim",
                "gui-revision-7",
                &config_hash(TEST_CONFIG_A),
                100,
            )
            .is_err()
        );

        let home = tempfile::tempdir().unwrap();
        let _ = issue_challenge(home.path(), 100);
        let root = home.path().join("consent").join(".gui-citation");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            create_challenge_at(
                home.path(),
                &query(),
                "the concrete claim",
                "gui-revision-7",
                &config_hash(TEST_CONFIG_A),
                101,
            )
            .is_err()
        );
    }
}
