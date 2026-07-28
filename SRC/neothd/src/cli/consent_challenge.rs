//! Private cross-process consent hand-off used by the desktop GUI.
//!
//! The GUI never puts an authority-bearing value in argv. A read-only
//! preflight creates a short-lived challenge and returns its random secret on
//! stdout to the directly spawned GUI process. `decide-chat` accepts that
//! secret only on stdin. `allow-once` produces a second short-lived token,
//! transferred inside a bounded, request-bound launch envelope on stdin to
//! `neoth chat`. Both records are mode-private, SHA-bound to the exact public
//! config bytes and canonical required-route set, TTL-limited, and consumed
//! before granting any authority.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cli::OutputFormat;
use crate::cli::init::ProviderKind;
use crate::config::FreedomConfig;
use crate::consent::{self, ConsentDecision, ConsentRoute, EphemeralConsent};

const RECORD_VERSION: u32 = 1;
const CHALLENGE_TTL_SECS: u64 = 5 * 60;
const TOKEN_TTL_SECS: u64 = 2 * 60;
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const SECRET_HEX_LEN: usize = 64;
const MAX_STDIN_SECRET_BYTES: u64 = 256;
const MAX_EXPIRY_SCAN_ENTRIES: usize = 256;
const MAX_EXPIRY_REMOVALS: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "snake_case")]
pub enum ConsentCommandSource {
    #[default]
    Cli,
    Gui,
}

impl ConsentCommandSource {
    pub(crate) fn mutation_source(self) -> crate::cli::consent::ConsentMutationSource {
        match self {
            Self::Cli => crate::cli::consent::ConsentMutationSource::Cli,
            Self::Gui => crate::cli::consent::ConsentMutationSource::Gui,
        }
    }

    fn require_gui(self) -> Result<()> {
        anyhow::ensure!(
            self == Self::Gui,
            "the private chat-consent challenge surface requires `--source gui`"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum ChatConsentDecision {
    AllowOnce,
    AllowAlways,
    Deny,
}

impl ChatConsentDecision {
    fn core(self) -> ConsentDecision {
        match self {
            Self::AllowOnce => ConsentDecision::AllowOnce,
            Self::AllowAlways => ConsentDecision::AllowAlways,
            Self::Deny => ConsentDecision::Deny,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::AllowOnce => "allow_once",
            Self::AllowAlways => "allow_always",
            Self::Deny => "deny",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecisionStatus {
    Decided,
    CommittedPartial,
    CommittedButBindingStale,
}

impl DecisionStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Decided => "decided",
            Self::CommittedPartial => "committed_partial",
            Self::CommittedButBindingStale => "committed_but_binding_stale",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteBinding {
    #[serde(with = "provider_slug")]
    provider: ProviderKind,
    endpoint_origin: Option<String>,
}

mod provider_slug {
    use serde::{Deserialize as _, Deserializer, Serializer};

    use crate::cli::init::ProviderKind;

    pub(super) fn serialize<S>(provider: &ProviderKind, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(crate::consent::slug(*provider))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<ProviderKind, D::Error>
    where
        D: Deserializer<'de>,
    {
        let slug = String::deserialize(deserializer)?;
        crate::consent::kind_from_slug(&slug)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown consent provider `{slug}`")))
    }
}

impl RouteBinding {
    fn from_route(route: &ConsentRoute) -> Result<Self> {
        Ok(Self {
            provider: route.kind,
            endpoint_origin: consent::route_endpoint_origin(route)?,
        })
    }

    fn to_route(&self) -> ConsentRoute {
        ConsentRoute::new(self.provider, self.endpoint_origin.as_deref())
    }

    fn sort_key(&self) -> String {
        format!(
            "{}\0{}",
            consent::slug(self.provider),
            self.endpoint_origin.as_deref().unwrap_or("provider")
        )
    }
}

struct ConfigSnapshot {
    config: FreedomConfig,
    config_sha256: String,
    routes: Vec<RouteBinding>,
    route_set_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRecord {
    version: u32,
    challenge_id: String,
    secret_sha256: String,
    config_sha256: String,
    route_set_sha256: String,
    required_routes: Vec<RouteBinding>,
    missing_routes: Vec<RouteBinding>,
    created_unix: u64,
    expires_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OneTimeTokenRecord {
    version: u32,
    token_id: String,
    secret_sha256: String,
    config_sha256: String,
    route_set_sha256: String,
    routes: Vec<RouteBinding>,
    created_unix: u64,
    expires_unix: u64,
}

#[derive(Deserialize)]
struct ExpiryRecord {
    expires_unix: u64,
}

#[derive(Debug)]
pub(crate) struct ConsumedChatConsent {
    pub(crate) config: FreedomConfig,
    pub(crate) ephemeral: EphemeralConsent,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct GuiChatLaunchEnvelope {
    version: u8,
    launch: String,
    stream_control_token: String,
    consent_token: Option<String>,
}

pub(crate) struct GuiChatLaunch {
    pub(crate) stream_control_token: Zeroizing<String>,
    pub(crate) consent_token: Option<Zeroizing<String>>,
}

struct PreflightResult {
    config_sha256: String,
    route_set_sha256: String,
    required_routes: Vec<RouteBinding>,
    missing_routes: Vec<RouteBinding>,
    challenge_id: Option<String>,
    challenge_secret: Option<Zeroizing<String>>,
    expires_unix: Option<u64>,
}

#[derive(Debug)]
struct DecisionResult {
    status: DecisionStatus,
    decision: ChatConsentDecision,
    config_sha256: String,
    route_set_sha256: String,
    receipts: Vec<serde_json::Value>,
    readback: Vec<serde_json::Value>,
    authority_persisted: bool,
    failure: Option<String>,
    one_time_token: Option<Zeroizing<String>>,
    token_expires_unix: Option<u64>,
}

struct LiveReadback {
    rows: Vec<serde_json::Value>,
    all_required_granted: bool,
    missing_authority_persisted: bool,
}

fn store_dir(home: &Path) -> PathBuf {
    home.join("consent").join(".gui-chat")
}

fn challenge_path(home: &Path, id: &str) -> Result<PathBuf> {
    Ok(store_dir(home)
        .join("challenges")
        .join(format!("{}.json", canonical_uuid(id)?)))
}

fn token_path(home: &Path, id: &str) -> Result<PathBuf> {
    Ok(store_dir(home)
        .join("tokens")
        .join(format!("{}.json", canonical_uuid(id)?)))
}

fn lock_path(path: &Path) -> PathBuf {
    path.with_extension("lock")
}

fn canonical_uuid(value: &str) -> Result<String> {
    let parsed = uuid::Uuid::parse_str(value).context("invalid consent challenge/token id")?;
    let canonical = parsed.to_string();
    anyhow::ensure!(
        value == canonical,
        "consent challenge/token id must use canonical lowercase UUID form"
    );
    Ok(canonical)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn random_secret() -> Result<Zeroizing<String>> {
    let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(bytes.as_mut())
        .map_err(|error| anyhow::anyhow!("generate consent challenge secret: {error}"))?;
    Ok(Zeroizing::new(hex::encode(bytes.as_ref())))
}

fn validate_digest(value: &str, field: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == SECRET_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{field} must be a 64-character hexadecimal SHA-256 digest"
    );
    Ok(())
}

fn secrets_equal(candidate: &str, expected_sha256: &str) -> bool {
    let actual = Sha256::digest(candidate.as_bytes());
    let Ok(expected) = hex::decode(expected_sha256) else {
        return false;
    };
    bool::from(actual.as_slice().ct_eq(expected.as_slice()))
}

fn route_set_hash(routes: &[RouteBinding]) -> Result<String> {
    Ok(sha256(
        &serde_json::to_vec(routes).context("serialize canonical consent route set")?,
    ))
}

fn canonical_routes(config: &FreedomConfig) -> Result<Vec<RouteBinding>> {
    let mut routes = consent::required_consent_routes(config)
        .into_iter()
        .filter(|route| consent::route_requires_consent(route.kind, route.endpoint.as_deref()))
        .map(|route| RouteBinding::from_route(&route))
        .collect::<Result<Vec<_>>>()?;
    routes.sort_by_key(RouteBinding::sort_key);
    routes.dedup();
    Ok(routes)
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

fn read_open_config_generation(
    file: &mut std::fs::File,
    config_path: &Path,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("seek consent config {}", config_path.display()))?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read consent config {}", config_path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_CONFIG_BYTES,
        "consent config {} exceeds the {}-byte size limit",
        config_path.display(),
        MAX_CONFIG_BYTES
    );
    Ok(bytes)
}

/// Read one regular-file generation through one no-follow handle. Re-reading
/// the same handle rejects torn in-place edits, while atomic path replacement
/// leaves this descriptor pinned to one complete generation.
fn read_stable_config_bytes(config_path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    for _ in 0..3 {
        let mut file = open_config_no_follow(config_path)
            .with_context(|| format!("open consent config {}", config_path.display()))?;
        let before = file
            .metadata()
            .with_context(|| format!("inspect consent config {}", config_path.display()))?;
        anyhow::ensure!(
            before.file_type().is_file() && !metadata_is_link_like(&before),
            "consent config {} must be a regular, non-link file",
            config_path.display()
        );
        anyhow::ensure!(
            before.len() <= MAX_CONFIG_BYTES,
            "consent config {} exceeds the {}-byte size limit",
            config_path.display(),
            MAX_CONFIG_BYTES
        );

        let first = read_open_config_generation(&mut file, config_path)?;
        let second = read_open_config_generation(&mut file, config_path)?;
        let after = file
            .metadata()
            .with_context(|| format!("re-inspect consent config {}", config_path.display()))?;
        if before.file_type().is_file()
            && after.file_type().is_file()
            && !metadata_is_link_like(&after)
            && before.len() == after.len()
            && first.as_slice() == second.as_slice()
        {
            return Ok(first);
        }
    }
    anyhow::bail!(
        "freedom.yaml changed repeatedly during consent snapshot; retry after edits settle"
    )
}

fn clear_effective_credentials(config: &mut FreedomConfig) {
    config.provider_key = None;
    config.telegram_token = None;
    config.inference.left.key = None;
    config.inference.right.key = None;
    config.inference.cerebellum.key = None;
    config.inference.default_slot.key = None;
}

/// Parse the exact hashed bytes, then merge only the credential generation
/// loaded by the normal coherent config/credentials reader. Comparing the
/// complete secret-free typed shape makes that reader double as validation
/// without allowing its independently opened freedom.yaml object to escape.
fn config_from_exact_bytes(config_path: &Path, bytes: &[u8]) -> Result<FreedomConfig> {
    let mut exact: FreedomConfig = serde_yaml::from_slice(bytes)
        .with_context(|| format!("parse YAML at {}", config_path.display()))?;
    let runtime = crate::config::load_runtime_config_pair_from_path(config_path)
        .with_context(|| format!("load consent config {}", config_path.display()))?;

    let mut exact_public = exact.clone();
    clear_effective_credentials(&mut exact_public);
    let mut runtime_public = runtime.config;
    clear_effective_credentials(&mut runtime_public);
    anyhow::ensure!(
        serde_yaml::to_value(&exact_public)
            .context("serialize exact consent config for generation validation")?
            == serde_yaml::to_value(&runtime_public)
                .context("serialize runtime consent config for generation validation")?,
        "freedom.yaml changed while its exact consent snapshot was validated"
    );

    if let Some(value) = runtime.credentials.provider_key {
        exact.provider_key = Some(value);
    }
    if let Some(value) = runtime.credentials.telegram_token {
        exact.telegram_token = Some(value);
    }
    if let Some(value) = runtime.credentials.inference_left_key {
        exact.inference.left.key = Some(value);
    }
    if let Some(value) = runtime.credentials.inference_right_key {
        exact.inference.right.key = Some(value);
    }
    if let Some(value) = runtime.credentials.inference_cerebellum_key {
        exact.inference.cerebellum.key = Some(value);
    }
    if let Some(value) = runtime.credentials.inference_default_slot_key {
        exact.inference.default_slot.key = Some(value);
    }
    Ok(exact)
}

/// Load one config generation whose returned typed object is parsed from the
/// exact bounded, no-follow bytes used for `config_sha256`.
fn config_snapshot(config_path: &Path) -> Result<ConfigSnapshot> {
    let bytes = read_stable_config_bytes(config_path)?;
    let config = config_from_exact_bytes(config_path, &bytes)?;
    let routes = canonical_routes(&config)?;
    Ok(ConfigSnapshot {
        config,
        config_sha256: sha256(&bytes),
        route_set_sha256: route_set_hash(&routes)?,
        routes,
    })
}

fn assert_snapshot_binding(snapshot: &ConfigSnapshot, record: &ChallengeRecord) -> Result<()> {
    anyhow::ensure!(
        snapshot.config_sha256 == record.config_sha256,
        "consent challenge rejected: freedom.yaml changed after preflight"
    );
    anyhow::ensure!(
        snapshot.route_set_sha256 == record.route_set_sha256
            && snapshot.routes == record.required_routes,
        "consent challenge rejected: required provider routes changed after preflight"
    );
    Ok(())
}

fn assert_expected_binding(
    snapshot: &ConfigSnapshot,
    expected_config_sha256: &str,
    expected_route_set_sha256: &str,
) -> Result<()> {
    validate_digest(expected_config_sha256, "expected config SHA-256")?;
    validate_digest(expected_route_set_sha256, "expected route-set SHA-256")?;
    anyhow::ensure!(
        snapshot.config_sha256 == expected_config_sha256,
        "GUI consent mutation rejected: freedom.yaml changed after preflight"
    );
    anyhow::ensure!(
        snapshot.route_set_sha256 == expected_route_set_sha256,
        "GUI consent mutation rejected: required provider routes changed after preflight"
    );
    Ok(())
}

fn write_record<T: Serialize>(path: &Path, record: &T) -> Result<()> {
    let bytes = serde_json::to_vec(record).context("serialize private GUI consent record")?;
    anyhow::ensure!(
        bytes.len() <= MAX_RECORD_BYTES as usize,
        "GUI consent record exceeds the {MAX_RECORD_BYTES}-byte safety ceiling"
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "create private GUI consent record directory {}",
                parent.display()
            )
        })?;
    }
    crate::util::atomic_write::write_private_create_new_durable(path, &bytes)
        .with_context(|| format!("create private GUI consent record {}", path.display()))
}

fn read_record<T: for<'de> Deserialize<'de>>(home: &Path, path: &Path) -> Result<T> {
    let bytes = crate::updater::self_update::read_private_control_file_bounded(
        home,
        path,
        MAX_RECORD_BYTES as usize,
        "GUI consent record",
    )?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse GUI consent record {}", path.display()))
}

fn consume_record(path: &Path) -> Result<()> {
    crate::util::atomic_write::durable_remove_file(path)
        .with_context(|| format!("consume GUI consent record {}", path.display()))
}

fn remove_consumed_lock(path: &Path) {
    let lock = lock_path(path);
    if let Err(error) = std::fs::remove_file(&lock)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            path = %lock.display(),
            error = %error,
            "could not remove consumed GUI consent lock file"
        );
    }
}

fn sweep_expired_record_dir(home: &Path, dir: &Path, now: u64, label: &str) -> Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("enumerate private GUI {label} directory {}", dir.display())
            });
        }
    };
    let mut paths = Vec::new();
    for entry in entries.take(MAX_EXPIRY_SCAN_ENTRIES) {
        let entry = entry.with_context(|| format!("enumerate private GUI {label} record entry"))?;
        let file_type = entry.file_type().with_context(|| {
            format!(
                "inspect private GUI {label} record type {}",
                entry.path().display()
            )
        })?;
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if canonical_uuid(stem).is_err() {
            continue;
        }
        paths.push(path);
    }
    paths.sort();

    let mut removed = 0;
    for path in paths {
        if removed >= MAX_EXPIRY_REMOVALS {
            break;
        }
        let lock = lock_path(&path);
        let guard =
            crate::util::locked_file::lock_file_blocking(&lock, "expired GUI consent record")
                .with_context(|| format!("lock private GUI {label} record {}", path.display()))?;
        let record: ExpiryRecord = match read_record(home, &path) {
            Ok(record) => record,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                drop(guard);
                remove_consumed_lock(&path);
                continue;
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %crate::security::redact::redact_text(&format!("{error:#}")),
                    "retaining unreadable private GUI consent record during expiry cleanup"
                );
                drop(guard);
                continue;
            }
        };
        if now <= record.expires_unix {
            drop(guard);
            continue;
        }
        if let Err(error) = consume_record(&path) {
            drop(guard);
            return Err(error)
                .with_context(|| format!("remove expired private GUI {label} record"));
        }
        drop(guard);
        remove_consumed_lock(&path);
        removed += 1;
    }
    Ok(removed)
}

fn sweep_expired_records(home: &Path, now: u64) {
    for (dir, label) in [
        (store_dir(home).join("challenges"), "challenge"),
        (store_dir(home).join("tokens"), "one-time token"),
    ] {
        if let Err(error) = sweep_expired_record_dir(home, &dir, now, label) {
            tracing::warn!(
                path = %dir.display(),
                error = %crate::security::redact::redact_text(&format!("{error:#}")),
                "private GUI consent expiry cleanup did not complete"
            );
        }
    }
}

fn read_secret_from_stdin(label: &str) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(MAX_STDIN_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label} from stdin"))?;
    anyhow::ensure!(
        bytes.len() <= MAX_STDIN_SECRET_BYTES as usize,
        "{label} on stdin exceeds the size limit"
    );
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{label} is not UTF-8"))?;
    let secret = Zeroizing::new(text.trim().to_owned());
    anyhow::ensure!(
        !secret.is_empty(),
        "{label} is required on stdin and must not be passed in argv"
    );
    Ok(secret)
}

async fn recover_consent_outbox(home: &Path) -> Result<()> {
    // Recovery may leave an optional terminal audit queued. That state is
    // allowed by the runtime gate and must not globally block unrelated GUI
    // routes. Relevant required/prepared mutations are checked route-by-route
    // after the exact config snapshot is known.
    crate::cli::consent_outbox::recover_pending(home)
        .await
        .context("recover consent transaction before GUI preflight")?;
    Ok(())
}

fn ensure_routes_not_blocked_by_outbox(home: &Path, routes: &[RouteBinding]) -> Result<()> {
    let mut checked = std::collections::BTreeSet::new();
    for route in routes {
        if !checked.insert(consent::slug(route.provider)) {
            continue;
        }
        if crate::cli::consent_outbox::blocks_provider_use(home, route.provider)
            .context("validate consent mutation state for GUI route")?
        {
            anyhow::bail!(
                "pending consent mutation for `{}` is not acknowledged; GUI provider use remains blocked",
                consent::slug(route.provider)
            );
        }
    }
    Ok(())
}

fn create_preflight_at(home: &Path, now: u64) -> Result<PreflightResult> {
    sweep_expired_records(home, now);
    let config_path = home.join("freedom.yaml");
    let snapshot = config_snapshot(&config_path)?;
    ensure_routes_not_blocked_by_outbox(home, &snapshot.routes)?;
    let missing_routes = snapshot
        .routes
        .iter()
        .filter(|route| !consent::is_route_granted(home, &route.to_route()))
        .cloned()
        .collect::<Vec<_>>();
    if missing_routes.is_empty() {
        return Ok(PreflightResult {
            config_sha256: snapshot.config_sha256,
            route_set_sha256: snapshot.route_set_sha256,
            required_routes: snapshot.routes,
            missing_routes,
            challenge_id: None,
            challenge_secret: None,
            expires_unix: None,
        });
    }

    let challenge_id = uuid::Uuid::now_v7().to_string();
    let secret = random_secret()?;
    let expires_unix = now.saturating_add(CHALLENGE_TTL_SECS);
    let record = ChallengeRecord {
        version: RECORD_VERSION,
        challenge_id: challenge_id.clone(),
        secret_sha256: sha256(secret.as_bytes()),
        config_sha256: snapshot.config_sha256.clone(),
        route_set_sha256: snapshot.route_set_sha256.clone(),
        required_routes: snapshot.routes.clone(),
        missing_routes: missing_routes.clone(),
        created_unix: now,
        expires_unix,
    };
    write_record(&challenge_path(home, &challenge_id)?, &record)?;

    Ok(PreflightResult {
        config_sha256: snapshot.config_sha256,
        route_set_sha256: snapshot.route_set_sha256,
        required_routes: snapshot.routes,
        missing_routes,
        challenge_id: Some(challenge_id),
        challenge_secret: Some(secret),
        expires_unix: Some(expires_unix),
    })
}

pub(crate) async fn render_preflight_chat(
    home: &Path,
    source: ConsentCommandSource,
    output: OutputFormat,
) -> Result<()> {
    source.require_gui()?;
    anyhow::ensure!(
        matches!(output, OutputFormat::Json | OutputFormat::Jsonl),
        "`consent preflight-chat` requires `--output json`"
    );
    recover_consent_outbox(home).await?;
    let result = create_preflight_at(home, crate::time::now_unix_secs())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": if result.challenge_id.is_some() { "consent_required" } else { "ready" },
            "config_sha256": result.config_sha256,
            "route_set_sha256": result.route_set_sha256,
            "required_routes": result.required_routes,
            "missing_routes": result.missing_routes,
            "challenge_id": result.challenge_id,
            "challenge_token": result.challenge_secret.as_deref(),
            "expires_unix": result.expires_unix,
        }))?
    );
    Ok(())
}

pub(crate) fn render_mutation_binding(
    home: &Path,
    source: ConsentCommandSource,
    output: OutputFormat,
) -> Result<()> {
    source.require_gui()?;
    anyhow::ensure!(
        matches!(output, OutputFormat::Json | OutputFormat::Jsonl),
        "`consent mutation-binding` requires `--output json`"
    );
    let snapshot = config_snapshot(&home.join("freedom.yaml"))?;
    let readback = snapshot
        .routes
        .iter()
        .map(|route| {
            serde_json::json!({
                "provider": consent::slug(route.provider),
                "endpoint_origin": route.endpoint_origin,
                "granted": consent::is_route_granted(home, &route.to_route()),
            })
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "config_sha256": snapshot.config_sha256,
            "route_set_sha256": snapshot.route_set_sha256,
            "required_routes": snapshot.routes,
            "readback": readback,
        }))?
    );
    Ok(())
}

async fn audit_decision_routes(
    home: &Path,
    routes: &[RouteBinding],
    decision: ChatConsentDecision,
) -> Result<()> {
    for binding in routes {
        crate::cli::consent::emit_consent_decision(
            home,
            &binding.to_route(),
            decision.core(),
            crate::cli::consent::ConsentMutationSource::Gui,
        )
        .await
        .context("durably audit GUI outbound-LLM consent decision")?;
    }
    Ok(())
}

fn receipt_json(receipt: &crate::cli::consent::ConsentChangeReceipt) -> serde_json::Value {
    serde_json::json!({
        "provider": consent::slug(receipt.provider),
        "was_granted": receipt.was_granted,
        "changed": receipt.changed,
        "configured_endpoint_origins": receipt.configured_endpoint_origins,
        "endpoint_origins": receipt.endpoint_origins,
        "added_endpoint_origins": receipt.added_endpoint_origins,
        "removed_endpoint_origins": receipt.removed_endpoint_origins,
        "endpoint_delta_known": receipt.endpoint_delta_known,
        "marker_source_malformed": receipt.marker_source_malformed,
        "audit_pending": receipt.audit_pending,
        "operation_id": receipt.operation_id,
    })
}

fn live_readback(
    home: &Path,
    required_routes: &[RouteBinding],
    initially_missing: &[RouteBinding],
) -> LiveReadback {
    let mut all_required_granted = true;
    let mut missing_authority_persisted = false;
    let rows = required_routes
        .iter()
        .map(|route| {
            let granted = consent::is_route_granted(home, &route.to_route());
            let marker_authority_persisted =
                consent::list_route_grants_for_kind(home, route.provider)
                    .map(|grants| {
                        grants.iter().any(|grant| {
                            grant.endpoint_origin.as_deref() == route.endpoint_origin.as_deref()
                                || route.endpoint_origin.is_none()
                        })
                    })
                    .unwrap_or(false);
            all_required_granted &= granted;
            missing_authority_persisted |=
                (granted || marker_authority_persisted) && initially_missing.contains(route);
            serde_json::json!({
                "provider": consent::slug(route.provider),
                "endpoint_origin": route.endpoint_origin,
                "granted": granted,
                "marker_authority_persisted": marker_authority_persisted,
            })
        })
        .collect();
    LiveReadback {
        rows,
        all_required_granted,
        missing_authority_persisted,
    }
}

fn committed_failure_result(
    home: &Path,
    record: &ChallengeRecord,
    decision: ChatConsentDecision,
    status: DecisionStatus,
    receipts: Vec<serde_json::Value>,
    known_commit: bool,
    error: anyhow::Error,
) -> Result<DecisionResult> {
    let readback = live_readback(home, &record.required_routes, &record.missing_routes);
    if !known_commit && !readback.missing_authority_persisted {
        return Err(error);
    }
    Ok(DecisionResult {
        status,
        decision,
        config_sha256: record.config_sha256.clone(),
        route_set_sha256: record.route_set_sha256.clone(),
        receipts,
        readback: readback.rows,
        authority_persisted: readback.missing_authority_persisted,
        failure: Some(crate::security::redact::redact_text(&format!("{error:#}"))),
        one_time_token: None,
        token_expires_unix: None,
    })
}

async fn decide_at(
    home: &Path,
    challenge_id: &str,
    challenge_secret: &str,
    decision: ChatConsentDecision,
    now: u64,
) -> Result<DecisionResult> {
    validate_digest(challenge_secret, "challenge token")?;
    let path = challenge_path(home, challenge_id)?;
    let _lock =
        crate::util::locked_file::lock_file_blocking(&lock_path(&path), "GUI consent challenge")?;
    let record: ChallengeRecord = read_record(home, &path)?;
    anyhow::ensure!(
        record.version == RECORD_VERSION && record.challenge_id == challenge_id,
        "unsupported or mismatched GUI consent challenge record"
    );
    validate_digest(&record.secret_sha256, "stored challenge-token SHA-256")?;
    anyhow::ensure!(
        now <= record.expires_unix,
        "GUI consent challenge expired; run preflight-chat again"
    );
    anyhow::ensure!(
        secrets_equal(challenge_secret, &record.secret_sha256),
        "GUI consent challenge token is invalid"
    );

    let config_path = home.join("freedom.yaml");
    let snapshot = config_snapshot(&config_path)?;
    assert_snapshot_binding(&snapshot, &record)?;
    let current_missing = record
        .required_routes
        .iter()
        .filter(|route| !consent::is_route_granted(home, &route.to_route()))
        .cloned()
        .collect::<Vec<_>>();
    anyhow::ensure!(
        current_missing == record.missing_routes,
        "GUI consent challenge rejected: consent markers changed after preflight"
    );

    // Recovery is intentionally after the challenge/config/route verification:
    // an unauthenticated or drifted decision request must not mutate even an
    // older consent journal. Recovery can itself resolve a marker, so bind and
    // compare the complete state once more afterwards.
    recover_consent_outbox(home).await?;
    let after_recovery = config_snapshot(&config_path)?;
    assert_snapshot_binding(&after_recovery, &record)?;
    ensure_routes_not_blocked_by_outbox(home, &record.required_routes)?;
    let missing_after_recovery = record
        .required_routes
        .iter()
        .filter(|route| !consent::is_route_granted(home, &route.to_route()))
        .cloned()
        .collect::<Vec<_>>();
    anyhow::ensure!(
        missing_after_recovery == record.missing_routes,
        "GUI consent challenge rejected: consent markers changed during recovery"
    );
    if decision == ChatConsentDecision::AllowAlways {
        anyhow::ensure!(
            !crate::cli::consent_outbox::blocks_new_grant(home)
                .context("validate consent journal before GUI durable grant")?,
            "GUI durable consent grant is temporarily blocked by a pending required mutation; retry after audit recovery"
        );
    }

    // Decision intent is durable before the challenge is consumed. Removing
    // the challenge before any authority mutation makes replay impossible.
    // If a later batch step fails after authority commits, the exact receipts
    // and forced readback are returned as a typed partial outcome.
    audit_decision_routes(home, &record.missing_routes, decision).await?;
    consume_record(&path)?;
    drop(_lock);
    remove_consumed_lock(&path);

    let mut receipts = Vec::new();
    let mut one_time_token = None;
    let mut token_expires_unix = None;
    let mut known_commit = false;
    match decision {
        ChatConsentDecision::Deny => {}
        ChatConsentDecision::AllowOnce => {
            let token_id = uuid::Uuid::now_v7().to_string();
            let secret = random_secret()?;
            let expires_unix = now.saturating_add(TOKEN_TTL_SECS);
            let token_record = OneTimeTokenRecord {
                version: RECORD_VERSION,
                token_id: token_id.clone(),
                secret_sha256: sha256(secret.as_bytes()),
                config_sha256: record.config_sha256.clone(),
                route_set_sha256: record.route_set_sha256.clone(),
                routes: record.missing_routes.clone(),
                created_unix: now,
                expires_unix,
            };
            write_record(&token_path(home, &token_id)?, &token_record)?;
            one_time_token = Some(Zeroizing::new(format!("{token_id}.{}", secret.as_str())));
            token_expires_unix = Some(expires_unix);
        }
        ChatConsentDecision::AllowAlways => {
            let mut providers = record
                .missing_routes
                .iter()
                .map(|route| route.provider)
                .collect::<Vec<_>>();
            providers.sort_by_key(|provider| consent::slug(*provider));
            providers.dedup();
            for provider in providers {
                // Re-read immediately before every journaled mutation. A later
                // config edit cannot widen authority: the shared service uses
                // this immutable snapshot, and the live leaf gate checks the
                // concrete route again.
                let current = match config_snapshot(&config_path) {
                    Ok(current) => current,
                    Err(error) => {
                        return committed_failure_result(
                            home,
                            &record,
                            decision,
                            DecisionStatus::CommittedButBindingStale,
                            receipts,
                            known_commit,
                            error,
                        );
                    }
                };
                if let Err(error) = assert_expected_binding(
                    &current,
                    &record.config_sha256,
                    &record.route_set_sha256,
                ) {
                    return committed_failure_result(
                        home,
                        &record,
                        decision,
                        DecisionStatus::CommittedButBindingStale,
                        receipts,
                        known_commit,
                        error,
                    );
                }
                let exact_routes = record
                    .missing_routes
                    .iter()
                    .filter(|route| route.provider == provider)
                    .map(RouteBinding::to_route)
                    .collect::<Vec<_>>();
                let receipt = match crate::cli::consent::grant_exact_routes_with_config_at(
                    home,
                    provider,
                    &exact_routes,
                    &snapshot.config,
                    crate::cli::consent::ConsentMutationSource::Gui,
                )
                .await
                {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        return committed_failure_result(
                            home,
                            &record,
                            decision,
                            DecisionStatus::CommittedPartial,
                            receipts,
                            known_commit,
                            error,
                        );
                    }
                };
                known_commit |= receipt.changed;
                receipts.push(receipt_json(&receipt));
            }

            let final_binding = config_snapshot(&config_path).and_then(|current| {
                assert_expected_binding(&current, &record.config_sha256, &record.route_set_sha256)
            });
            if let Err(error) = final_binding {
                return committed_failure_result(
                    home,
                    &record,
                    decision,
                    DecisionStatus::CommittedButBindingStale,
                    receipts,
                    known_commit,
                    error,
                );
            }

            let readback = live_readback(home, &record.required_routes, &record.missing_routes);
            if !readback.all_required_granted {
                return committed_failure_result(
                    home,
                    &record,
                    decision,
                    DecisionStatus::CommittedPartial,
                    receipts,
                    known_commit,
                    anyhow::anyhow!(
                        "GUI allow-always readback found at least one required route ungranted"
                    ),
                );
            }
        }
    }

    let readback = live_readback(home, &record.required_routes, &record.missing_routes);
    Ok(DecisionResult {
        status: DecisionStatus::Decided,
        decision,
        config_sha256: record.config_sha256,
        route_set_sha256: record.route_set_sha256,
        receipts,
        readback: readback.rows,
        authority_persisted: readback.missing_authority_persisted,
        failure: None,
        one_time_token,
        token_expires_unix,
    })
}

pub(crate) async fn render_decide_chat(
    home: &Path,
    challenge_id: &str,
    decision: ChatConsentDecision,
    source: ConsentCommandSource,
    output: OutputFormat,
) -> Result<()> {
    source.require_gui()?;
    anyhow::ensure!(
        matches!(output, OutputFormat::Json | OutputFormat::Jsonl),
        "`consent decide-chat` requires `--output json`"
    );
    let secret = read_secret_from_stdin("GUI consent challenge token")?;
    let result = decide_at(
        home,
        challenge_id,
        &secret,
        decision,
        crate::time::now_unix_secs(),
    )
    .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": result.status.as_str(),
            "decision": result.decision.as_str(),
            "config_sha256": result.config_sha256,
            "route_set_sha256": result.route_set_sha256,
            "receipts": result.receipts,
            "readback": result.readback,
            "authority_persisted": result.authority_persisted,
            "failure": result.failure,
            "gui_consent_token": result.one_time_token.as_deref(),
            "token_expires_unix": result.token_expires_unix,
        }))?
    );
    Ok(())
}

fn split_one_time_token(token: &str) -> Result<(&str, &str)> {
    let (id, secret) = token
        .split_once('.')
        .context("GUI consent token has an invalid wire format")?;
    canonical_uuid(id)?;
    validate_digest(secret, "GUI consent token secret")?;
    Ok((id, secret))
}

fn parse_gui_chat_launch_envelope(input: &str) -> Result<GuiChatLaunch> {
    let envelope: GuiChatLaunchEnvelope =
        serde_json::from_str(input).context("parse private GUI chat launch envelope")?;
    anyhow::ensure!(
        envelope.version == 1,
        "unsupported private GUI chat launch envelope version"
    );
    anyhow::ensure!(
        envelope.launch == "commit",
        "private GUI chat launch envelope is not a commit"
    );

    // The deserialized wire values are independently zeroized by
    // `GuiChatLaunchEnvelope::drop`; clone them into the longer-lived
    // request-scoped containers before validating or returning them.
    let stream_control_token = Zeroizing::new(envelope.stream_control_token.clone());
    anyhow::ensure!(
        stream_control_token.len() == 32
            && stream_control_token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "private GUI chat stream control token must be exactly 32 ASCII hex characters"
    );

    let consent_token = envelope
        .consent_token
        .as_ref()
        .map(|token| Zeroizing::new(token.clone()));
    if let Some(token) = consent_token.as_deref() {
        split_one_time_token(token).context("invalid consent token in GUI chat launch envelope")?;
    }

    Ok(GuiChatLaunch {
        stream_control_token,
        consent_token,
    })
}

pub(crate) fn read_gui_chat_launch_from_stdin() -> Result<GuiChatLaunch> {
    let envelope = read_secret_from_stdin("private GUI chat launch envelope")?;
    parse_gui_chat_launch_envelope(&envelope)
}

fn consume_token_at(
    home: &Path,
    config_path: &Path,
    token: &str,
    now: u64,
) -> Result<ConsumedChatConsent> {
    let (token_id, secret) = split_one_time_token(token)?;
    let path = token_path(home, token_id)?;
    let _lock =
        crate::util::locked_file::lock_file_blocking(&lock_path(&path), "GUI one-time consent")?;
    let record: OneTimeTokenRecord = read_record(home, &path)?;
    anyhow::ensure!(
        record.version == RECORD_VERSION && record.token_id == token_id,
        "unsupported or mismatched GUI one-time consent record"
    );
    anyhow::ensure!(
        now <= record.expires_unix,
        "GUI one-time consent token expired; request consent again"
    );
    anyhow::ensure!(
        secrets_equal(secret, &record.secret_sha256),
        "GUI one-time consent token is invalid"
    );

    let snapshot = config_snapshot(config_path)?;
    anyhow::ensure!(
        snapshot.config_sha256 == record.config_sha256
            && snapshot.route_set_sha256 == record.route_set_sha256,
        "GUI one-time consent token rejected: config or provider routes changed"
    );
    anyhow::ensure!(
        record
            .routes
            .iter()
            .all(|route| snapshot.routes.contains(route)),
        "GUI one-time consent token contains a route outside the active config"
    );

    // Consume before constructing any provider. A failed provider build cannot
    // make the token replayable.
    consume_record(&path)?;
    drop(_lock);
    remove_consumed_lock(&path);
    let mut ephemeral = EphemeralConsent::default();
    for route in &record.routes {
        ephemeral.allow_route(&route.to_route())?;
    }
    Ok(ConsumedChatConsent {
        config: snapshot.config,
        ephemeral,
    })
}

pub(crate) fn consume_chat_token_value(
    home: &Path,
    config_path: &Path,
    token: &str,
) -> Result<ConsumedChatConsent> {
    consume_token_at(home, config_path, token, crate::time::now_unix_secs())
}

pub(crate) fn verify_gui_mutation_binding(
    home: &Path,
    expected_config_sha256: &str,
    expected_route_set_sha256: &str,
) -> Result<FreedomConfig> {
    let snapshot = config_snapshot(&home.join("freedom.yaml"))?;
    assert_expected_binding(&snapshot, expected_config_sha256, expected_route_set_sha256)?;
    Ok(snapshot.config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::inference::{InferenceProvider, TopologyMode};
    use tempfile::TempDir;

    fn write_config(home: &Path, config: &FreedomConfig) {
        std::fs::write(
            home.join("freedom.yaml"),
            serde_yaml::to_string(config).unwrap(),
        )
        .unwrap();
    }

    fn remote_ollama_config(endpoint: &str) -> FreedomConfig {
        FreedomConfig {
            provider_kind: Some(ProviderKind::LocalOllama),
            provider_endpoint: Some(endpoint.to_owned()),
            ..FreedomConfig::default()
        }
    }

    fn two_cloud_config() -> FreedomConfig {
        let mut config = FreedomConfig {
            provider_kind: Some(ProviderKind::AnthropicApi),
            ..FreedomConfig::default()
        };
        config.inference.mode = TopologyMode::Custom;
        config.inference.left.provider = Some(InferenceProvider::AnthropicApi);
        config.inference.right.provider = Some(InferenceProvider::OpenAi);
        config.inference.cerebellum.provider = Some(InferenceProvider::AnthropicApi);
        config
    }

    const TEST_STREAM_CONTROL_TOKEN: &str = "0123456789abcdef0123456789ABCDEF";
    const TEST_CONSENT_TOKEN: &str = concat!(
        "550e8400-e29b-41d4-a716-446655440000.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    #[test]
    fn gui_chat_launch_envelope_accepts_exact_commit_contract() {
        let encoded = serde_json::json!({
            "version": 1,
            "launch": "commit",
            "stream_control_token": TEST_STREAM_CONTROL_TOKEN,
            "consent_token": TEST_CONSENT_TOKEN,
        })
        .to_string();
        assert!(
            encoded.len() <= MAX_STDIN_SECRET_BYTES as usize,
            "the complete launch contract must fit the bounded stdin reader"
        );
        let launch = parse_gui_chat_launch_envelope(&encoded).unwrap();

        assert_eq!(
            launch.stream_control_token.as_str(),
            TEST_STREAM_CONTROL_TOKEN
        );
        assert_eq!(
            launch.consent_token.as_ref().map(|token| token.as_str()),
            Some(TEST_CONSENT_TOKEN)
        );

        let launch_without_consent = parse_gui_chat_launch_envelope(
            &serde_json::json!({
                "version": 1,
                "launch": "commit",
                "stream_control_token": TEST_STREAM_CONTROL_TOKEN,
                "consent_token": null,
            })
            .to_string(),
        )
        .unwrap();
        assert!(launch_without_consent.consent_token.is_none());
    }

    #[test]
    fn gui_chat_launch_envelope_rejects_unbound_or_malformed_values() {
        for (name, envelope) in [
            (
                "wrong version",
                serde_json::json!({
                    "version": 2,
                    "launch": "commit",
                    "stream_control_token": TEST_STREAM_CONTROL_TOKEN,
                    "consent_token": null,
                }),
            ),
            (
                "wrong launch decision",
                serde_json::json!({
                    "version": 1,
                    "launch": "cancel",
                    "stream_control_token": TEST_STREAM_CONTROL_TOKEN,
                    "consent_token": null,
                }),
            ),
            (
                "short stream token",
                serde_json::json!({
                    "version": 1,
                    "launch": "commit",
                    "stream_control_token": "abcd",
                    "consent_token": null,
                }),
            ),
            (
                "non-hex stream token",
                serde_json::json!({
                    "version": 1,
                    "launch": "commit",
                    "stream_control_token": "gggggggggggggggggggggggggggggggg",
                    "consent_token": null,
                }),
            ),
            (
                "malformed consent token",
                serde_json::json!({
                    "version": 1,
                    "launch": "commit",
                    "stream_control_token": TEST_STREAM_CONTROL_TOKEN,
                    "consent_token": "not-a-token",
                }),
            ),
            (
                "unknown field",
                serde_json::json!({
                    "version": 1,
                    "launch": "commit",
                    "stream_control_token": TEST_STREAM_CONTROL_TOKEN,
                    "consent_token": null,
                    "extra": true,
                }),
            ),
        ] {
            assert!(
                parse_gui_chat_launch_envelope(&envelope.to_string()).is_err(),
                "{name} unexpectedly passed validation"
            );
        }
    }

    #[tokio::test]
    async fn allow_once_token_is_exact_single_use_and_challenge_cannot_replay() {
        let home = TempDir::new().unwrap();
        let config = remote_ollama_config("http://ollama-a.example:11434/v1");
        write_config(home.path(), &config);
        let preflight = create_preflight_at(home.path(), 1_000).unwrap();
        let id = preflight.challenge_id.unwrap();
        let secret = preflight.challenge_secret.unwrap();

        let decision = decide_at(
            home.path(),
            &id,
            &secret,
            ChatConsentDecision::AllowOnce,
            1_001,
        )
        .await
        .unwrap();
        let token = decision.one_time_token.unwrap();
        let replay_error = match decide_at(
            home.path(),
            &id,
            &secret,
            ChatConsentDecision::AllowOnce,
            1_002,
        )
        .await
        {
            Ok(_) => panic!("consumed challenge replay unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(replay_error.to_string().contains("GUI consent record"));

        let consumed = consume_token_at(
            home.path(),
            &home.path().join("freedom.yaml"),
            &token,
            1_003,
        )
        .unwrap();
        assert!(
            !consumed
                .ephemeral
                .consume_route(&ConsentRoute::new(
                    ProviderKind::LocalOllama,
                    Some("http://ollama-b.example:11434"),
                ))
                .unwrap()
        );
        assert!(
            consumed
                .ephemeral
                .consume_route(&ConsentRoute::new(
                    ProviderKind::LocalOllama,
                    Some("http://ollama-a.example:11434/other"),
                ))
                .unwrap()
        );
        assert!(
            !consumed
                .ephemeral
                .consume_route(&ConsentRoute::new(
                    ProviderKind::LocalOllama,
                    Some("http://ollama-a.example:11434/again"),
                ))
                .unwrap()
        );
        assert!(
            consume_token_at(
                home.path(),
                &home.path().join("freedom.yaml"),
                &token,
                1_004
            )
            .unwrap_err()
            .to_string()
            .contains("GUI consent record")
        );
    }

    #[tokio::test]
    async fn preflight_prunes_expired_challenges_tokens_and_their_lock_files() {
        let home = TempDir::new().unwrap();
        let config = remote_ollama_config("http://ollama-a.example:11434");
        write_config(home.path(), &config);

        let abandoned = create_preflight_at(home.path(), 10).unwrap();
        let abandoned_path =
            challenge_path(home.path(), abandoned.challenge_id.as_deref().unwrap()).unwrap();
        assert!(abandoned_path.exists());
        drop(
            crate::util::locked_file::lock_file_blocking(
                &lock_path(&abandoned_path),
                "GUI consent cleanup test",
            )
            .unwrap(),
        );
        assert!(lock_path(&abandoned_path).exists());

        create_preflight_at(home.path(), 11).unwrap();
        assert!(abandoned_path.exists());
        assert!(
            lock_path(&abandoned_path).exists(),
            "a live record must retain its stable lock pathname"
        );

        let second_now = 10 + CHALLENGE_TTL_SECS + 1;
        let second = create_preflight_at(home.path(), second_now).unwrap();
        assert!(!abandoned_path.exists());
        assert!(!lock_path(&abandoned_path).exists());

        let decision = decide_at(
            home.path(),
            second.challenge_id.as_deref().unwrap(),
            second.challenge_secret.as_deref().unwrap(),
            ChatConsentDecision::AllowOnce,
            second_now + 1,
        )
        .await
        .unwrap();
        let token = decision.one_time_token.unwrap();
        let (token_id, _) = split_one_time_token(&token).unwrap();
        let abandoned_token_path = token_path(home.path(), token_id).unwrap();
        assert!(abandoned_token_path.exists());

        create_preflight_at(home.path(), second_now + TOKEN_TTL_SECS + 2).unwrap();
        assert!(!abandoned_token_path.exists());
        assert!(!lock_path(&abandoned_token_path).exists());
    }

    #[tokio::test]
    async fn challenge_and_token_reject_expiry_and_config_drift() {
        let home = TempDir::new().unwrap();
        let config_a = remote_ollama_config("http://ollama-a.example:11434");
        write_config(home.path(), &config_a);
        let expired = create_preflight_at(home.path(), 10).unwrap();
        let expired_error = match decide_at(
            home.path(),
            expired.challenge_id.as_deref().unwrap(),
            expired.challenge_secret.as_deref().unwrap(),
            ChatConsentDecision::Deny,
            10 + CHALLENGE_TTL_SECS + 1,
        )
        .await
        {
            Ok(_) => panic!("expired challenge unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(expired_error.to_string().contains("expired"));

        let drifted = create_preflight_at(home.path(), 1_000).unwrap();
        let config_b = remote_ollama_config("http://ollama-b.example:11434");
        write_config(home.path(), &config_b);
        let drift_error = match decide_at(
            home.path(),
            drifted.challenge_id.as_deref().unwrap(),
            drifted.challenge_secret.as_deref().unwrap(),
            ChatConsentDecision::AllowOnce,
            1_001,
        )
        .await
        {
            Ok(_) => panic!("drifted challenge unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(
            drift_error.to_string().contains("freedom.yaml changed"),
            "{drift_error:#}"
        );
    }

    #[tokio::test]
    async fn route_a_token_never_authorizes_route_b_even_with_same_provider() {
        let home = TempDir::new().unwrap();
        let config_a = remote_ollama_config("https://OLLAMA-A.example:443/api");
        write_config(home.path(), &config_a);
        let preflight = create_preflight_at(home.path(), 2_000).unwrap();
        let decision = decide_at(
            home.path(),
            preflight.challenge_id.as_deref().unwrap(),
            preflight.challenge_secret.as_deref().unwrap(),
            ChatConsentDecision::AllowOnce,
            2_001,
        )
        .await
        .unwrap();
        let token = decision.one_time_token.unwrap();
        let consumed = consume_token_at(
            home.path(),
            &home.path().join("freedom.yaml"),
            &token,
            2_002,
        )
        .unwrap();
        assert!(
            !consumed
                .ephemeral
                .consume_route(&ConsentRoute::new(
                    ProviderKind::LocalOllama,
                    Some("https://ollama-b.example:443"),
                ))
                .unwrap()
        );
        assert!(
            consumed
                .ephemeral
                .consume_route(&ConsentRoute::new(
                    ProviderKind::LocalOllama,
                    Some("https://ollama-a.example:443/different"),
                ))
                .unwrap()
        );
        assert!(
            !consumed
                .ephemeral
                .consume_route(&ConsentRoute::new(
                    ProviderKind::LocalOllama,
                    Some("https://ollama-a.example:443/again"),
                ))
                .unwrap()
        );
    }

    #[tokio::test]
    async fn token_rejects_route_drift_before_it_is_consumed() {
        let home = TempDir::new().unwrap();
        let config_a = remote_ollama_config("http://ollama-a.example:11434");
        write_config(home.path(), &config_a);
        let preflight = create_preflight_at(home.path(), 3_000).unwrap();
        let decision = decide_at(
            home.path(),
            preflight.challenge_id.as_deref().unwrap(),
            preflight.challenge_secret.as_deref().unwrap(),
            ChatConsentDecision::AllowOnce,
            3_001,
        )
        .await
        .unwrap();
        let token = decision.one_time_token.unwrap();

        let config_b = remote_ollama_config("http://ollama-b.example:11434");
        write_config(home.path(), &config_b);
        let error = consume_token_at(
            home.path(),
            &home.path().join("freedom.yaml"),
            &token,
            3_002,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("config or provider routes changed"),
            "{error:#}"
        );

        write_config(home.path(), &config_a);
        assert!(
            consume_token_at(
                home.path(),
                &home.path().join("freedom.yaml"),
                &token,
                3_003,
            )
            .is_ok(),
            "a drift rejection must not consume a still-valid token"
        );
    }

    #[tokio::test]
    async fn token_consumption_replaces_a_stale_same_route_preload_with_bound_config() {
        let home = TempDir::new().unwrap();
        let mut bound = remote_ollama_config("http://ollama-a.example:11434");
        bound.provider_model = Some("bound-model".to_owned());
        write_config(home.path(), &bound);
        let preflight = create_preflight_at(home.path(), 4_000).unwrap();
        let decision = decide_at(
            home.path(),
            preflight.challenge_id.as_deref().unwrap(),
            preflight.challenge_secret.as_deref().unwrap(),
            ChatConsentDecision::AllowOnce,
            4_001,
        )
        .await
        .unwrap();
        let token = decision.one_time_token.unwrap();

        let mut stale = bound.clone();
        stale.provider_model = Some("stale-model".to_owned());
        write_config(home.path(), &stale);
        let stale_preloaded =
            FreedomConfig::load_from_path(&home.path().join("freedom.yaml")).unwrap();
        write_config(home.path(), &bound);

        let consumed = consume_token_at(
            home.path(),
            &home.path().join("freedom.yaml"),
            &token,
            4_002,
        )
        .unwrap();
        assert_eq!(
            consumed.config.provider_model.as_deref(),
            Some("bound-model")
        );
        assert_eq!(
            stale_preloaded.provider_model.as_deref(),
            Some("stale-model")
        );
        assert!(
            consume_token_at(
                home.path(),
                &home.path().join("freedom.yaml"),
                &token,
                4_003,
            )
            .unwrap_err()
            .to_string()
            .contains("GUI consent record"),
            "the exact-config handoff must not weaken token single-use"
        );
    }

    #[tokio::test]
    async fn allow_always_second_provider_failure_returns_typed_partial_and_cannot_replay() {
        let home = TempDir::new().unwrap();
        let config = two_cloud_config();
        write_config(home.path(), &config);
        let preflight = create_preflight_at(home.path(), 5_000).unwrap();
        let marker = consent::marker_path(home.path(), ProviderKind::OpenaiApi);
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, b"malformed-openai-marker").unwrap();

        let result = decide_at(
            home.path(),
            preflight.challenge_id.as_deref().unwrap(),
            preflight.challenge_secret.as_deref().unwrap(),
            ChatConsentDecision::AllowAlways,
            5_001,
        )
        .await
        .unwrap();
        assert_eq!(result.status, DecisionStatus::CommittedPartial);
        assert!(result.authority_persisted);
        assert_eq!(result.receipts.len(), 1);
        assert!(result.failure.is_some());
        assert!(consent::is_route_granted(
            home.path(),
            &ConsentRoute::new(ProviderKind::AnthropicApi, None)
        ));
        assert!(!consent::is_route_granted(
            home.path(),
            &ConsentRoute::new(ProviderKind::OpenaiApi, None)
        ));

        let replay = decide_at(
            home.path(),
            preflight.challenge_id.as_deref().unwrap(),
            preflight.challenge_secret.as_deref().unwrap(),
            ChatConsentDecision::AllowAlways,
            5_002,
        )
        .await
        .unwrap_err();
        assert!(
            replay.to_string().contains("GUI consent record"),
            "{replay:#}"
        );
    }

    #[tokio::test]
    async fn challenge_detects_revocation_of_a_route_granted_at_preflight() {
        let home = TempDir::new().unwrap();
        let config = two_cloud_config();
        write_config(home.path(), &config);
        consent::grant(home.path(), ProviderKind::AnthropicApi).unwrap();
        let preflight = create_preflight_at(home.path(), 6_000).unwrap();
        assert_eq!(preflight.missing_routes.len(), 1);

        consent::revoke(home.path(), ProviderKind::AnthropicApi).unwrap();
        let drift = decide_at(
            home.path(),
            preflight.challenge_id.as_deref().unwrap(),
            preflight.challenge_secret.as_deref().unwrap(),
            ChatConsentDecision::Deny,
            6_001,
        )
        .await
        .unwrap_err();
        assert!(
            drift
                .to_string()
                .contains("consent markers changed after preflight"),
            "{drift:#}"
        );

        consent::grant(home.path(), ProviderKind::AnthropicApi).unwrap();
        let retry = decide_at(
            home.path(),
            preflight.challenge_id.as_deref().unwrap(),
            preflight.challenge_secret.as_deref().unwrap(),
            ChatConsentDecision::Deny,
            6_002,
        )
        .await
        .unwrap();
        assert_eq!(retry.status, DecisionStatus::Decided);
    }

    #[tokio::test]
    async fn optional_terminal_audit_for_unrelated_provider_does_not_block_preflight() {
        let home = TempDir::new().unwrap();
        let unrelated = ConsentRoute::new(ProviderKind::OpenaiApi, Some("https://api.openai.com"));
        let update =
            consent::prepare_grant_routes(home.path(), std::slice::from_ref(&unrelated)).unwrap();
        let mut transaction = crate::cli::consent_outbox::begin(
            home.path(),
            &update,
            crate::cli::consent_outbox::ConsentMutationAction::Grant,
            crate::cli::consent::ConsentMutationSource::Cli,
            Vec::new(),
            false,
        )
        .await
        .unwrap();
        assert!(!transaction.deliver_phase().await.unwrap().is_pending());
        assert!(update.commit().unwrap());
        transaction.mark_committed().unwrap();
        let _daemon_owner =
            crate::daemon::pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        assert!(transaction.deliver_phase().await.unwrap().is_pending());
        drop(transaction);

        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::AnthropicApi),
            ..FreedomConfig::default()
        };
        write_config(home.path(), &config);
        consent::grant(home.path(), ProviderKind::AnthropicApi).unwrap();

        recover_consent_outbox(home.path()).await.unwrap();
        let preflight = create_preflight_at(home.path(), 8_000).unwrap();
        assert!(preflight.challenge_id.is_none());
        assert!(preflight.missing_routes.is_empty());
    }

    #[test]
    fn oversized_private_record_is_rejected_before_durable_write() {
        let home = TempDir::new().unwrap();
        let path = home.path().join("oversized.json");
        let routes = (0..4_096)
            .map(|index| RouteBinding {
                provider: ProviderKind::OpenaiCompat,
                endpoint_origin: Some(format!("https://route-{index}.example")),
            })
            .collect::<Vec<_>>();
        let record = ChallengeRecord {
            version: RECORD_VERSION,
            challenge_id: uuid::Uuid::now_v7().to_string(),
            secret_sha256: "a".repeat(SECRET_HEX_LEN),
            config_sha256: "b".repeat(SECRET_HEX_LEN),
            route_set_sha256: "c".repeat(SECRET_HEX_LEN),
            required_routes: routes.clone(),
            missing_routes: routes,
            created_unix: 1,
            expires_unix: 2,
        };

        let error = write_record(&path, &record).unwrap_err();
        assert!(error.to_string().contains("safety ceiling"));
        assert!(!path.exists());
    }
}
