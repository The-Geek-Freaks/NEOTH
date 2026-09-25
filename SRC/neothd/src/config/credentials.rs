//! Separate credentials file — Codex audit item #7 follow-up.
//!
//! `~/.neoth/credentials.yaml` is the dedicated home for fields that hold
//! plaintext secrets (`provider_key`, `telegram_token`). Splitting them
//! out of `freedom.yaml` lets the operator:
//!   - share `freedom.yaml` (without secrets) for support / debugging
//!   - swap credentials independently of provider/role/autonomy config
//!   - run `ls ~/.neoth/` and see exactly which file holds secrets
//!
//! Backwards compatibility: `FreedomConfig::load_from_path` still accepts
//! the legacy form with embedded `provider_key` / `telegram_token`. When
//! both are present, the credentials.yaml values WIN — operators editing
//! the dedicated file expect their changes to take effect.
//!
//! The wizard writes both files atomically on first init. `mode 0600`
//! enforced via the same path as `freedom.yaml` (OpenOptions::mode pre-
//! open on unix; icacls grant:r owner on Windows).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use base64::Engine as _;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

use crate::secret::SecretString;

/// Cross-process-safe credential-store status classifier.
///
/// A single-read probe of `credentials.yaml` that callers use to decide
/// whether to display a warning, synthesise empty state, or bail — without
/// calling `load_or_default` and silently swallowing load failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStoreStatus {
    /// File does not exist — fresh install, treat as empty store.
    Missing,
    /// File exists and parses correctly.
    Ok,
    /// File exists but YAML or UTF-8 is corrupt.
    Invalid,
    /// File exists but an I/O error prevented reading it (permissions, etc.).
    Unreadable,
    /// File is AEAD-encrypted but the master key is unavailable.
    KeyUnavailable,
}

impl CredentialStoreStatus {
    /// Short lowercase label suitable for log messages and JSON fields.
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialStoreStatus::Missing => "missing",
            CredentialStoreStatus::Ok => "ok",
            CredentialStoreStatus::Invalid => "invalid",
            CredentialStoreStatus::Unreadable => "unreadable",
            CredentialStoreStatus::KeyUnavailable => "key_unavailable",
        }
    }
}

// ── Intra-process mutex (taken BEFORE the OS file lock, mutex-first ordering)
//
// Same pattern as `cluster::registry` — same-process writers serialise by
// parking on the mutex, so only the mutex-holder ever contends for the file
// lock. Poison-tolerant: a panic inside a critical section leaves the file
// consistent thanks to atomic rename, so recovering and proceeding is safe.
static CRED_LOCK: Mutex<()> = Mutex::new(());

// A dual-file transaction must exclude runtime readers for its complete
// PREPARED -> two renames -> journal removal window. This process mutex plus
// the sibling OS lock provides that boundary across threads and processes.
// The thread-local marker makes same-home nested loads re-entrant (for example
// a FreedomConfig mutation validating effective credentials) without relying
// on platform-specific advisory-lock re-entrancy.
static DUAL_FILE_TRANSACTION_LOCK: Mutex<()> = Mutex::new(());
thread_local! {
    static ACTIVE_DUAL_FILE_TRANSACTION_DIR: RefCell<Option<PathBuf>> = const {
        RefCell::new(None)
    };
    static ACTIVE_LEGACY_PAIR_LOCK_DIR: RefCell<Option<PathBuf>> = const {
        RefCell::new(None)
    };
    static ACTIVE_CONFIG_WRITER_DIR: RefCell<Option<PathBuf>> = const {
        RefCell::new(None)
    };
    static ACTIVE_RESTORE_PUBLICATION_DIR: RefCell<Option<PathBuf>> = const {
        RefCell::new(None)
    };
}

const DUAL_FILE_JOURNAL_NAME: &str = ".freedom-credentials.prepared.yaml";
const DUAL_FILE_LOCK_NAME: &str = ".freedom-credentials.transaction.lock";
const DUAL_FILE_JOURNAL_VERSION: u8 = 1;
const DUAL_FILE_JOURNAL_STATE: &str = "PREPARED";
const MAX_DUAL_FILE_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const RESTORE_IN_PROGRESS_NAME: &str = ".restore-in-progress.yaml";

fn lock_cred() -> MutexGuard<'static, ()> {
    CRED_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Bounded-blocking exclusive OS lock on `<path>.lock`.
/// Delegates to the shared `util::locked_file` primitive (same logic as
/// `cluster::registry::lock_registry_file`, without copy-pasting the unsafe
/// `flock`/`share_mode` code).
fn lock_cred_file(path: &Path) -> Result<std::fs::File> {
    let lock_path = path.with_extension("lock");
    crate::util::locked_file::lock_file_blocking(&lock_path, "credentials")
}

fn transaction_directory(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

pub(super) fn sibling_credentials_path(freedom_path: &Path) -> PathBuf {
    transaction_directory(freedom_path).join("credentials.yaml")
}

struct ActiveDualFileTransaction;

impl Drop for ActiveDualFileTransaction {
    fn drop(&mut self) {
        ACTIVE_DUAL_FILE_TRANSACTION_DIR.with(|active| {
            *active.borrow_mut() = None;
        });
    }
}

struct ActiveLegacyPairLocks;

impl ActiveLegacyPairLocks {
    fn enter(directory: &Path) -> Result<Self> {
        ACTIVE_LEGACY_PAIR_LOCK_DIR.with(|active| {
            let mut active = active.borrow_mut();
            anyhow::ensure!(
                active.is_none(),
                "legacy freedom/credentials pair locks are already marked active"
            );
            *active = Some(directory.to_path_buf());
            Ok(Self)
        })
    }
}

impl Drop for ActiveLegacyPairLocks {
    fn drop(&mut self) {
        ACTIVE_LEGACY_PAIR_LOCK_DIR.with(|active| {
            *active.borrow_mut() = None;
        });
    }
}

struct ActiveConfigWriter;

impl Drop for ActiveConfigWriter {
    fn drop(&mut self) {
        ACTIVE_CONFIG_WRITER_DIR.with(|active| {
            *active.borrow_mut() = None;
        });
    }
}

struct ActiveRestorePublication;

impl ActiveRestorePublication {
    fn enter(directory: &Path) -> Result<Self> {
        ACTIVE_RESTORE_PUBLICATION_DIR.with(|active| {
            let mut active = active.borrow_mut();
            anyhow::ensure!(active.is_none(), "restore publication is already active");
            *active = Some(directory.to_path_buf());
            Ok(Self)
        })
    }
}

impl Drop for ActiveRestorePublication {
    fn drop(&mut self) {
        ACTIVE_RESTORE_PUBLICATION_DIR.with(|active| {
            *active.borrow_mut() = None;
        });
    }
}

pub(super) fn with_config_writer_guard<T>(
    anchor: &Path,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let directory = transaction_directory(anchor);
    ACTIVE_CONFIG_WRITER_DIR.with(|active| {
        let mut active = active.borrow_mut();
        if let Some(active_directory) = active.as_ref() {
            anyhow::bail!(
                "refusing nested config writer ({} -> {}); compose both mutations in one transaction",
                active_directory.display(),
                directory.display()
            );
        }
        *active = Some(directory);
        Ok(())
    })?;
    let _active_writer = ActiveConfigWriter;
    action()
}

/// Hold every config/credential lock across an already-validated staged
/// restore. A private durable marker blocks all normal config loads if the
/// process dies after ancillary files become visible but before the pair commit
/// and cleanup. Re-running restore resumes under the explicit bypass and clears
/// the marker only after the whole publication succeeds.
pub(crate) fn with_restore_publication_at<T>(
    freedom_path: &Path,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let directory = transaction_directory(freedom_path);
    let _restore = ActiveRestorePublication::enter(&directory)?;
    with_coherent_pair_transaction_lock(freedom_path, || {
        let marker_path = directory.join(RESTORE_IN_PROGRESS_NAME);
        validate_exact_pair_target(&marker_path, "restore marker")?;
        crate::util::atomic_write::atomic_write_private(
            &marker_path,
            b"version: 1\nstate: RESTORE_PREPARED\n",
        )
        .with_context(|| format!("write private restore marker {}", marker_path.display()))?;
        sync_transaction_directory(&directory)?;

        let value = action().with_context(|| {
            format!(
                "restore publication interrupted; {} retained and runtime activation is blocked until restore is rerun",
                marker_path.display()
            )
        })?;
        crate::util::atomic_write::durable_remove_file(&marker_path)
            .with_context(|| format!("clear completed restore marker {}", marker_path.display()))?;
        Ok(value)
    })
}

fn with_legacy_pair_locks<T>(
    freedom_path: &Path,
    credentials_path: &Path,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let directory = transaction_directory(freedom_path);
    anyhow::ensure!(
        directory == transaction_directory(credentials_path),
        "freedom.yaml and credentials.yaml must be siblings for canonical pair locking"
    );
    let active_pair = ACTIVE_LEGACY_PAIR_LOCK_DIR.with(|active| active.borrow().clone());
    if let Some(active_directory) = active_pair {
        anyhow::ensure!(
            active_directory == directory,
            "refusing nested legacy pair locks across instance homes ({} -> {})",
            active_directory.display(),
            directory.display()
        );
        return action();
    }

    let _freedom_mutex = super::lock_freedom_update();
    let _credentials_mutex = lock_cred();
    let _freedom_file_lock = crate::util::locked_file::lock_file_blocking(
        &freedom_path.with_extension("lock"),
        "freedom config",
    )
    .with_context(|| format!("acquire freedom config lock for {}", freedom_path.display()))?;
    let _credentials_file_lock = lock_cred_file(credentials_path).with_context(|| {
        format!(
            "acquire credentials lock for {}",
            credentials_path.display()
        )
    })?;
    let _active_pair = ActiveLegacyPairLocks::enter(&directory)?;
    action()
}

/// Coherent two-file reader compatible with both journal-aware writers and a
/// still-running pre-journal NEOTH during rolling upgrades. The legacy writer
/// holds these four locks across both renames, so all four must be acquired
/// before the reader touches either file.
///
/// This is a synchronous scope only: callers must finish their local
/// configuration admission before returning and must never hold it across an
/// async wait or external effect. Same-instance nested coherent reads are
/// explicitly supported by the active-pair guard below.
pub(crate) fn with_coherent_pair_transaction_lock<T>(
    freedom_path: &Path,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let directory = transaction_directory(freedom_path);
    let active_transaction =
        ACTIVE_DUAL_FILE_TRANSACTION_DIR.with(|active| active.borrow().clone());
    if let Some(active_directory) = active_transaction {
        anyhow::ensure!(
            active_directory == directory,
            "refusing nested coherent config read across instance homes ({} -> {})",
            active_directory.display(),
            directory.display()
        );
        let pair_locks_held = ACTIVE_LEGACY_PAIR_LOCK_DIR.with(|active| {
            active
                .borrow()
                .as_ref()
                .is_some_and(|active_directory| active_directory == &directory)
        });
        anyhow::ensure!(
            pair_locks_held,
            "refusing a coherent config/credential read nested inside a single-file mutation"
        );
        return action();
    }

    with_dual_file_transaction_lock(freedom_path, || {
        let credentials_path = sibling_credentials_path(freedom_path);
        with_legacy_pair_locks(freedom_path, &credentials_path, action)
    })
}

/// Run a config/credential operation behind the crash-recovery boundary.
///
/// Dual-file writer lock order is: this transaction lock, then the existing
/// freedom/credential process and file locks. Single-file readers take this
/// boundary alone; coherent pair readers additionally take all four legacy
/// locks so they remain safe beside a pre-journal process during rolling
/// upgrades. Nested reads for the same instance are explicitly re-entrant;
/// nested writers are rejected by [`with_config_writer_guard`] before they can
/// reacquire a mutex or overwrite an inner generation. Cross-instance nesting
/// fails closed rather than acquiring two transaction locks in an order that
/// could deadlock another process.
pub(super) fn with_dual_file_transaction_lock<T>(
    anchor: &Path,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let directory = transaction_directory(anchor);
    let nested = ACTIVE_DUAL_FILE_TRANSACTION_DIR.with(|active| {
        let active = active.borrow();
        match active.as_ref() {
            Some(current) if current == &directory => Ok(true),
            Some(current) => anyhow::bail!(
                "refusing nested config transaction across instance homes ({} -> {})",
                current.display(),
                directory.display()
            ),
            None => Ok(false),
        }
    })?;
    if nested {
        return action();
    }

    let _process_guard = DUAL_FILE_TRANSACTION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _file_guard = crate::util::locked_file::lock_file_blocking(
        &directory.join(DUAL_FILE_LOCK_NAME),
        "freedom/credentials transaction",
    )?;
    recover_prepared_transaction_in(&directory)?;

    let restore_publication_active = ACTIVE_RESTORE_PUBLICATION_DIR.with(|active| {
        active
            .borrow()
            .as_ref()
            .is_some_and(|active_directory| active_directory == &directory)
    });
    if !restore_publication_active
        && read_private_journal(&directory.join(RESTORE_IN_PROGRESS_NAME))?.is_some()
    {
        anyhow::bail!(
            "incomplete backup restore in {}; runtime activation is blocked. Rerun the same `neoth restore <archive> --force` command to complete it",
            directory.display()
        );
    }

    ACTIVE_DUAL_FILE_TRANSACTION_DIR.with(|active| {
        *active.borrow_mut() = Some(directory);
    });
    let _active = ActiveDualFileTransaction;
    action()
}

/// Default file: `<neoth_home>/credentials.yaml`.
pub fn default_path() -> PathBuf {
    super::FreedomConfig::default_neoth_home().join("credentials.yaml")
}

/// GOLD-ADAPT-CRYPTO-04 #5 — magic prefix marking an AEAD-encrypted
/// credentials.yaml. Distinct from the WAL `ENC_MAGIC` so the two at-rest
/// formats can never be confused. Layout: `CONF_MAGIC ‖ nonce(12) ‖ ciphertext`.
const CONF_MAGIC: &[u8] = b"NEOTH_CONF_ENCv1\n";

pub(crate) fn credentials_blob_is_encrypted(raw: &[u8]) -> bool {
    raw.starts_with(CONF_MAGIC)
}

/// Encrypt a serialized credentials YAML string with the config subkey
/// (AES-256-GCM-SIV, the magic as AAD). Fresh random nonce per write.
fn encrypt_credentials_body(
    key: &crate::wal::crypto::WalSegmentKey,
    yaml: &str,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("credentials nonce RNG: {e}"))?;
    let ct = crate::wal::crypto::encrypt_blob(key, &nonce, CONF_MAGIC, yaml.as_bytes())
        .context("encrypt credentials body")?;
    let mut out = Vec::with_capacity(CONF_MAGIC.len() + nonce.len() + ct.len());
    out.extend_from_slice(CONF_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a `CONF_MAGIC`-framed credentials blob. `Err` on wrong key / tamper /
/// truncation / non-UTF-8 plaintext.
fn decrypt_credentials_body(key: &crate::wal::crypto::WalSegmentKey, raw: &[u8]) -> Result<String> {
    let after = raw
        .strip_prefix(CONF_MAGIC)
        .ok_or_else(|| anyhow::anyhow!("credentials blob is not CONF_MAGIC-framed"))?;
    if after.len() < 12 {
        anyhow::bail!("encrypted credentials truncated (no nonce)");
    }
    let nonce: [u8; 12] = after[..12].try_into().expect("checked len >= 12");
    let pt = crate::wal::crypto::decrypt_blob(key, &nonce, CONF_MAGIC, &after[12..])
        .context("decrypt credentials (wrong key or tampered)")?;
    String::from_utf8(pt).context("decrypted credentials are not UTF-8")
}

fn decode_credentials_yaml(path: &Path, raw: &[u8]) -> Result<zeroize::Zeroizing<String>> {
    let body = if raw.starts_with(CONF_MAGIC) {
        let home = transaction_directory(path);
        let key = crate::wal::master_key::config_subkey_at(&home).ok_or_else(|| {
            anyhow::anyhow!(
                "credentials at {} are encrypted but the master key is unavailable \
                 (restore it: neoth security restore-master-key)",
                path.display()
            )
        })?;
        decrypt_credentials_body(&key, raw)
            .with_context(|| format!("decrypt credentials at {}", path.display()))?
    } else {
        String::from_utf8(raw.to_vec())
            .with_context(|| format!("credentials at {} are not valid UTF-8", path.display()))?
    };
    Ok(zeroize::Zeroizing::new(body))
}

fn encode_credentials_yaml(path: &Path, body: &str) -> Result<FileSnapshot> {
    let home = transaction_directory(path);
    let persisted = if crate::wal::master_key::wal_encryption_enabled_at(&home)
        .context("resolve WAL/config at-rest encryption policy")?
    {
        match crate::wal::master_key::config_subkey_ensure_at(&home) {
            Some(key) => encrypt_credentials_body(&key, body)?,
            None => {
                anyhow::bail!(
                    "at-rest encryption enabled but master key unavailable — \
                     refusing to write plaintext credentials"
                );
            }
        }
    } else {
        body.as_bytes().to_vec()
    };
    Ok(FileSnapshot::Present(zeroize::Zeroizing::new(persisted)))
}

/// Shape of `credentials.yaml`. All fields optional so an operator who
/// hasn't configured a provider key (e.g. claude-cli OAuth only) doesn't
/// need to keep an empty key around.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TelegramAccountCredentials {
    pub token: Option<SecretString>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SlackAccountCredentials {
    pub bot_token: Option<SecretString>,
    pub app_token: Option<SecretString>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ChannelAccountCredentials {
    pub telegram: BTreeMap<crate::channels::registry::ChannelAccountId, TelegramAccountCredentials>,
    #[serde(
        default,
        deserialize_with = "deserialize_unique_slack_account_credentials"
    )]
    pub slack: BTreeMap<crate::channels::registry::ChannelAccountId, SlackAccountCredentials>,
}

fn deserialize_unique_slack_account_credentials<'de, D>(
    deserializer: D,
) -> std::result::Result<
    BTreeMap<crate::channels::registry::ChannelAccountId, SlackAccountCredentials>,
    D::Error,
>
where
    D: serde::Deserializer<'de>,
{
    struct SlackCredentialsVisitor;

    impl<'de> Visitor<'de> for SlackCredentialsVisitor {
        type Value = BTreeMap<crate::channels::registry::ChannelAccountId, SlackAccountCredentials>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a Slack credential object with unique account IDs")
        }

        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut accounts = BTreeMap::new();
            while let Some((account_id, credentials)) = map.next_entry::<
                crate::channels::registry::ChannelAccountId,
                SlackAccountCredentials,
            >()? {
                if accounts.insert(account_id.clone(), credentials).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate Slack credential account `{account_id}`"
                    )));
                }
            }
            Ok(accounts)
        }
    }

    deserializer.deserialize_map(SlackCredentialsVisitor)
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Credentials {
    /// API key for the separately configured adopted outbound n8n instance.
    /// Never serialize this value into `freedom.yaml` or job evidence.
    #[serde(default)]
    pub n8n_api_key: Option<SecretString>,
    /// LLM provider API key — OpenAI, Gemini, or compat endpoint.
    pub provider_key: Option<SecretString>,
    /// ElevenLabs TTS API key. Dedicated so speech access never silently reuses
    /// a general LLM credential.
    #[serde(default)]
    pub elevenlabs_tts_api_key: Option<SecretString>,
    /// Azure Speech/TTS subscription key. Region remains non-secret under
    /// `freedom.yaml::media.tts.azure_region`.
    #[serde(default)]
    pub azure_tts_api_key: Option<SecretString>,
    /// Telegram bot token from @BotFather.
    pub telegram_token: Option<SecretString>,
    /// Account-owned Telegram secrets. Empty preserves the legacy singleton.
    #[serde(default)]
    pub channel_accounts: ChannelAccountCredentials,
    /// OMI-MULTIMODAL-01 — OMI Developer API key (`omi_dev_*`) for importing
    /// conversations from the configured Developer API endpoint.
    #[serde(default)]
    pub omi_developer_api_key: Option<SecretString>,
    /// OMI-MULTIMODAL-01 — bearer token used to authenticate native OMI live
    /// PCM/media webhook requests. Kept out of `freedom.yaml` and required when
    /// native ingest is enabled, including loopback binds.
    #[serde(default)]
    pub omi_ingest_token: Option<SecretString>,
    /// GR-041 — per-hemisphere inference key overrides, companions to the
    /// `inference.{left,right,cerebellum,default_slot}.key` slots in
    /// `freedom.yaml`. Canonical public rendering strips those slot keys, so
    /// credentials.yaml is the only supported durable home; on load they are
    /// merged back onto the matching slot.
    #[serde(default)]
    pub inference_left_key: Option<SecretString>,
    #[serde(default)]
    pub inference_right_key: Option<SecretString>,
    #[serde(default)]
    pub inference_cerebellum_key: Option<SecretString>,
    #[serde(default)]
    pub inference_default_slot_key: Option<SecretString>,
    /// WhatsApp Business Cloud API access token. Issued from the Meta
    /// developer console. Used by the live Graph API sender, proactive
    /// delivery route, and authenticated webhook reply path.
    pub whatsapp_token: Option<SecretString>,
    /// WhatsApp Business phone-number id (the numeric id from the
    /// Meta console, not the phone number itself).
    pub whatsapp_phone_id: Option<String>,
    /// WhatsApp webhook verify-token — used by the Meta server when it
    /// confirms the operator's webhook endpoint.
    pub whatsapp_verify_token: Option<SecretString>,
    /// Meta app secret used to compute `X-Hub-Signature-256` for inbound
    /// WhatsApp webhooks. Required to start the Meta webhook listener;
    /// `send_text` still works without it.
    pub whatsapp_app_secret: Option<SecretString>,
    /// Exact WhatsApp Business sender allowed to drive inbound chat. Stored in
    /// canonical international digits (no leading `+`). Missing/blank keeps the
    /// signed Meta webhook listener fail-closed.
    pub whatsapp_allowed_sender: Option<String>,
    /// Operator-hosted repository Baileys sidecar URL. This is deliberately
    /// separate from the official Meta Cloud API fields above. Plain HTTP is
    /// accepted only for loopback; remote sidecars require HTTPS.
    pub whatsapp_baileys_url: Option<String>,
    /// Dedicated bearer token shared only with the Baileys sidecar (minimum 32
    /// characters). Never reuse the Meta token or a provider key.
    pub whatsapp_baileys_token: Option<SecretString>,
    /// Mandatory comma-separated inbound sender allowlist (E.164 or exact JID).
    /// An absent/empty list prevents the adapter from starting.
    pub whatsapp_baileys_allowed_senders: Option<String>,
    /// Optional comma-separated exact group JIDs (`…@g.us`). Groups are denied
    /// when absent; an allowed group still requires an allowed sender.
    pub whatsapp_baileys_allowed_groups: Option<String>,
    /// Slack bot user OAuth token (`xoxb-...`). Required by both
    /// socket-mode and webhook modes.
    pub slack_bot_token: Option<SecretString>,
    /// Slack app-level token (`xapp-...`) for socket mode. Operators
    /// who run NEOTH on a headless box without a public HTTPS endpoint
    /// pick socket mode; the app token lets the daemon open the
    /// WebSocket to Slack's edge directly.
    pub slack_app_token: Option<SecretString>,
    /// Exact immutable Slack member id (`U…`/`W…`) allowed to drive inbound
    /// Socket Mode messages. Missing/blank prevents the receive loop starting.
    pub slack_allowed_user_id: Option<String>,
    /// GOLD-PROG-16 — Discord bot token (sent as `Bot <token>`). When present
    /// alongside an exact allowed sender id and a provider, the daemon spawns
    /// the Discord gateway receive loop (`DiscordChannel::run`).
    pub discord_bot_token: Option<SecretString>,
    /// Exact immutable Discord user snowflake allowed to drive inbound chat.
    /// This is public authorization policy rather than a secret. A missing or
    /// blank value keeps the Discord receive loop fail-closed.
    pub discord_allowed_user_id: Option<String>,
    /// GOLD-FEAT-10 — base URL of the operator's local `signal-cli` HTTP
    /// daemon (e.g. `http://127.0.0.1:8080`). When present alongside
    /// `signal_phone_number`, the daemon spawns the Signal receive loop
    /// (`SignalChannel::run`). Not a secret (a loopback URL) but lives here
    /// with the other channel config.
    pub signal_cli_url: Option<String>,
    /// GOLD-FEAT-10 — our registered Signal number (`+E.164`). Used as the
    /// `number` on every signal-cli send + the `/v1/receive/{number}` path.
    pub signal_phone_number: Option<String>,
    /// Exact Signal sender number allowed to drive inbound chat (`+E.164`).
    /// Missing/blank prevents the receive poll loop starting.
    pub signal_allowed_sender: Option<String>,
    /// GOLD-FEAT-10 — Matrix homeserver URL (e.g. `https://matrix.org`). Not a
    /// secret; the entry point for the `matrix-channel` adapter.
    pub matrix_homeserver: Option<String>,
    /// GOLD-FEAT-10 — Matrix user id (`@bot:server`). Not a secret.
    pub matrix_user_id: Option<String>,
    /// GOLD-FEAT-10 — Matrix login password (alternative to a pre-issued
    /// access token). Secret.
    pub matrix_password: Option<SecretString>,
    /// GOLD-FEAT-10 — pre-issued Matrix access token (alternative to the
    /// password — restores a session without re-login). Secret.
    pub matrix_access_token: Option<SecretString>,
    /// GOLD-FEAT-10 — local state/crypto store dir for matrix-sdk (E2EE keys +
    /// sync state persist across restarts). Defaults to `~/.neoth/matrix_store/`
    /// when unset. Not a secret (a path).
    pub matrix_store_path: Option<String>,
    /// D2 — operator sender allowlist for Matrix (`@user:server`). `None` ⇒ open
    /// for messages in already-joined rooms, but invitations remain deny-all
    /// unless this or `matrix_allowed_room_ids` is configured. Set ⇒ only this
    /// sender/inviter is accepted; others are dropped + audited `0x3B`. Not a
    /// secret.
    pub matrix_allowed_user_id: Option<String>,
    /// Comma-separated Matrix room-id allowlist (`!id:server`). When set, only
    /// these rooms may be joined, receive messages, or receive proactive sends.
    /// Invitations require this room match and, when configured, the sender
    /// match above. Not a secret.
    pub matrix_allowed_room_ids: Option<String>,
    /// Matrix transport policy. `None`/`true` (default) requires every room to
    /// advertise `m.room.encryption` before inbound or outbound text is allowed.
    /// `Some(false)` is the explicit plaintext opt-out and is surfaced as such
    /// by channel probes/status. Not a secret.
    pub matrix_require_encryption: Option<bool>,
    /// GOLD-FEAT-10 — LINE long-lived channel access token (Messaging API tab in
    /// the LINE Developers console). Bearer token for the push send API. Secret.
    pub line_channel_access_token: Option<SecretString>,
    /// GOLD-FEAT-10 — LINE channel secret (Basic Settings tab). Verifies the
    /// inbound `X-Line-Signature` (base64 HMAC-SHA256 over the raw body). Secret.
    pub line_channel_secret: Option<SecretString>,
    /// GOLD-FEAT-10 — local bind port for the LINE webhook listener
    /// (`127.0.0.1:<port>`, default 8444). The operator fronts it with a public
    /// HTTPS reverse proxy. Not a secret; kept here with the other channel
    /// config (and out of the `config/mod.rs` hot zone). `None` ⇒ default port.
    pub line_webhook_port: Option<u16>,
    /// Exact LINE member user id allowed to drive inbound chat. Conversation
    /// membership alone is not authorization; missing/blank disables inbound.
    pub line_allowed_sender: Option<String>,
    /// GOLD-FEAT-10 — IRC server host (e.g. `irc.libera.chat`). NEOTH dials out,
    /// so no public URL is needed. Not a secret.
    pub irc_server: Option<String>,
    /// GOLD-FEAT-10 — IRC server port. `None` ⇒ 6697 (TLS). Not a secret.
    pub irc_port: Option<u16>,
    /// GOLD-FEAT-10 — IRC bot nick. Not a secret.
    pub irc_nick: Option<String>,
    /// GOLD-FEAT-10 — IRC server / NickServ / bouncer password. Secret.
    pub irc_password: Option<SecretString>,
    /// GOLD-FEAT-10 — comma-separated channels to join (e.g. `#neoth,#dev`).
    pub irc_channels: Option<String>,
    /// GOLD-FEAT-10 — use TLS for the IRC connection. `None` ⇒ true.
    pub irc_tls: Option<bool>,
    /// D2 — operator sender allowlist for IRC (a nick). `None` ⇒ open; set ⇒
    /// only this nick is accepted (others dropped + audited 0x3B). Best-effort:
    /// IRC nicks aren't authenticated without SASL. Not a secret.
    pub irc_allowed_nick: Option<String>,
    /// B9 spoof-hardening — require the IRCv3 `account-tag` on inbound IRC
    /// messages and only accept senders whose services account matches this
    /// value. Nick-only allowlists are trivially spoofable on public networks
    /// (`/nick` race); the account tag is asserted by the network's services
    /// (NickServ/SASL) and can't be forged by a nick change. Needs a network
    /// with IRCv3 `account-tag` support (Libera, OFTC, …). Compared EXACTLY
    /// (case-sensitive) against the tag the network emits — use the account
    /// name as the services registry stores it. `None` ⇒ nick-only gating.
    /// Not a secret.
    pub irc_allowed_account: Option<String>,
    /// GOLD-FEAT-10 — Mattermost server base URL (e.g. `https://mm.example.com`).
    /// NEOTH dials out to the WebSocket API, so no public URL is needed. Not a
    /// secret.
    pub mattermost_url: Option<String>,
    /// GOLD-FEAT-10 — Mattermost personal-access or bot token. Secret.
    pub mattermost_token: Option<SecretString>,
    /// D2 — operator sender allowlist for Mattermost (a user UUID). `None` ⇒
    /// open; set ⇒ only this user id is accepted (others dropped + audited 0x3B).
    /// Not a secret.
    pub mattermost_allowed_user_id: Option<String>,
    /// GOLD-FEAT-10 — Twitch bot username (the account NEOTH chats as).
    /// Lowercased at connect. Not a secret.
    pub twitch_username: Option<String>,
    /// GOLD-ADAPT-JV-PAPERLESS-01 — base URL of the operator's Paperless-NGX
    /// instance (e.g. `http://localhost:8010`). Documents are POSTed to
    /// `{paperless_url}/api/documents/post_document/`. Not a secret.
    pub paperless_url: Option<String>,
    /// GOLD-ADAPT-JV-PAPERLESS-01 — Paperless-NGX API token.  Generate via
    /// the Paperless web UI → Settings → API token.  Sent as
    /// `Authorization: Token <value>`. Secret (mlock+zeroize via SecretString).
    pub paperless_token: Option<SecretString>,
    /// GOLD-FEAT-10 — Twitch OAuth token (`chat:read` + `chat:edit` scopes).
    /// NEOTH prepends the required `oauth:` prefix. Secret.
    pub twitch_oauth_token: Option<SecretString>,
    /// GOLD-FEAT-10 — comma-separated Twitch channels to join (e.g. `#mychannel`).
    pub twitch_channels: Option<String>,
    /// GOLD-FEAT-10 — Nostr identity secret key (`nsec1…` bech32 or 64-char hex).
    /// NEOTH signs + decrypts NIP-17 DMs with it. Secret (mlock+zeroize).
    pub nostr_secret_key: Option<SecretString>,
    /// GOLD-FEAT-10 — comma-separated Nostr relay WSS URLs the adapter connects
    /// to (e.g. `wss://relay.damus.io,wss://nos.lol`). Not a secret.
    pub nostr_relays: Option<String>,
    /// D2 — operator sender allowlist for Nostr (a 64-char hex pubkey). `None` ⇒
    /// open; set ⇒ only this pubkey is accepted (others dropped + audited 0x3B).
    /// Not a secret.
    pub nostr_allowed_pubkey: Option<String>,
    /// GOLD-FEAT-10b — base URL of the operator's BlueBubbles server running on
    /// their Mac (e.g. `http://192.168.1.5:1234`). When present alongside
    /// `bluebubbles_password`, the daemon spawns the iMessage poll loop
    /// (`BlueBubblesChannel::run`). Not a secret (a LAN/Tailscale URL).
    pub bluebubbles_url: Option<String>,
    /// GOLD-FEAT-10b — BlueBubbles server password (Settings → Server → Password
    /// in the BB app). Appended as `?password=…` on every API request. Secret.
    pub bluebubbles_password: Option<SecretString>,
    /// GOLD-FEAT-10b — optional comma-separated BlueBubbles chat GUIDs to watch
    /// (e.g. `iMessage;-;+14155551234,iMessage;+;group-uuid`). `None` = accept
    /// all chats visible to the BB server. Not a secret.
    pub bluebubbles_chat_guid: Option<String>,
    /// GOLD-FEAT-10b — optional single iMessage handle (phone or Apple-ID email)
    /// that may reach the pipeline. `None` = open (any sender in a watched chat).
    /// Checked via `sender_blocked_by_allowlist` (D2 gate). Not a secret.
    pub imessage_allowed_sender: Option<String>,
    /// B9 — path to the GCP service-account JSON key for Google Chat (the key
    /// FILE is the secret; this stores only its path). When present alongside
    /// `gchat_subscription` (and the build carries the `gchat-channel`
    /// feature), the daemon spawns the Pub/Sub pull loop. Not a secret.
    pub gchat_service_account_json: Option<String>,
    /// B9 — Pub/Sub pull subscription carrying the Chat app's events
    /// (`projects/<p>/subscriptions/<s>`). Not a secret.
    pub gchat_subscription: Option<String>,
    /// D2 — operator sender allowlist for Google Chat (`users/<id>`). `None` ⇒
    /// open; set ⇒ only this Google-asserted user id is accepted (others
    /// dropped + audited 0x3B). Not a secret.
    pub gchat_allowed_sender: Option<String>,
    /// Local repository-owned Keet companion origin. Loopback HTTP(S) only;
    /// validated again by the runtime before any request. Not a secret.
    pub keet_bridge_url: Option<String>,
    /// Keet topic capability handled by the companion. Possession grants room
    /// access, so it is a secret: keep it out of Debug/log/audit surfaces and
    /// migrate it through the configured secret backend like any bearer token.
    pub keet_topic: Option<SecretString>,
    /// Exact comma-separated companion sender IDs accepted from the topic.
    /// Mandatory for inbound; all other senders are dropped + audited.
    pub keet_allowed_senders: Option<String>,
    /// Legacy seed written by the removed speculative native transport. It is
    /// retained for migration cleanup but is never used as Keet authentication.
    pub keet_seed_phrase: Option<SecretString>,
    /// Mandatory bearer secret for the repository-owned Keet companion.
    /// `pears_bearer_token` is accepted on read for existing installations;
    /// all new writes use the transport-specific canonical name.
    #[serde(alias = "pears_bearer_token")]
    pub keet_bridge_bearer_token: Option<SecretString>,
    /// TD-01 (Session 30) — Todoist REST v2 API token (Settings →
    /// Integrations → Developer in the Todoist app). Used by
    /// `neoth todo {list,add,close}` via `tools::todoist`. Wrapped in
    /// SecretString for the same mlock+zeroize protections as the other
    /// keys. Optional override paths: `--token` flag, `NEOTH_TODOIST_TOKEN`.
    pub todoist_token: Option<SecretString>,
    /// TD-02 (Session 32) — Google OAuth installed-app client id (the
    /// `*.apps.googleusercontent.com` value from the Google Cloud console).
    /// Shared across the Google integrations (Tasks today, Gmail/Calendar
    /// next). Not a secret on its own, but kept beside the others so one
    /// file holds the whole Google identity.
    pub google_oauth_client_id: Option<String>,
    /// TD-02 — Google OAuth client secret that pairs with the client id.
    /// Installed-app secrets are not truly confidential, but it rides in
    /// `SecretString` for the same mlock+zeroize handling as the rest.
    pub google_oauth_client_secret: Option<SecretString>,
    /// TD-02 — long-lived Google OAuth refresh token (scope
    /// `https://www.googleapis.com/auth/tasks`). Exchanged for a
    /// short-lived access token on each `neoth todo --provider google` run
    /// via `tools::google_tasks::refresh_access_token`. The only durable
    /// Google secret; access tokens are never persisted. Override:
    /// `NEOTH_GOOGLE_REFRESH_TOKEN`.
    pub google_oauth_refresh_token: Option<SecretString>,
    /// TD-02 CalDAV — base URL of the operator's task calendar collection
    /// (e.g. `https://cloud.example.com/remote.php/dav/calendars/<user>/tasks/`).
    /// `neoth todo --provider caldav list`. Override: `NEOTH_CALDAV_URL`.
    pub caldav_url: Option<String>,
    /// TD-02 CalDAV — Basic-auth username. Override: `NEOTH_CALDAV_USERNAME`.
    pub caldav_username: Option<String>,
    /// TD-02 CalDAV — Basic-auth password / app-password (SecretString for the
    /// same mlock+zeroize handling). Override: `NEOTH_CALDAV_PASSWORD`.
    pub caldav_password: Option<SecretString>,
    /// TD-02 Microsoft To Do — Azure AD tenant (`common` for personal accounts,
    /// or a tenant GUID). Override: `NEOTH_MS_TODO_TENANT_ID`.
    pub ms_todo_tenant_id: Option<String>,
    /// TD-02 Microsoft To Do — Azure app registration client id. Override:
    /// `NEOTH_MS_TODO_CLIENT_ID`.
    pub ms_todo_client_id: Option<String>,
    /// TD-02 Microsoft To Do — client secret. Override: `NEOTH_MS_TODO_CLIENT_SECRET`.
    pub ms_todo_client_secret: Option<SecretString>,
    /// TD-02 Microsoft To Do — long-lived OAuth refresh token (scope
    /// `Tasks.ReadWrite offline_access`). Override: `NEOTH_MS_TODO_REFRESH_TOKEN`.
    pub ms_todo_refresh_token: Option<SecretString>,
    /// SL-00 (Session 32) — the cluster shared-secret passphrase. ALL nodes
    /// in one cluster share this phrase; it derives the `cluster_key` that
    /// HMAC-authenticates every announce, gossip, and delegated-task frame, so a
    /// peer without the phrase can never join or impersonate. A secret →
    /// lives here in `SecretString` (mlock+zeroize), NOT in freedom.yaml.
    /// The PUBLIC cluster rendezvous name lives in `freedom.yaml::cluster.name`.
    pub cluster_passphrase: Option<SecretString>,
    /// GOLD-ADAPT-TUDU-01 — tududi self-hosted task manager API token.
    /// Set by the wizard when the operator registers their local tududi
    /// instance. The daemon populates `TUDUDI_API_TOKEN` in the NEOTH
    /// process env at startup so `mcp_servers.yaml`'s `from_env` sentinel
    /// resolves at MCP spawn time. Secret (mlock+zeroize).
    #[serde(default)]
    pub tududi_api_token: Option<SecretString>,
    /// TERMIX-SSH-SECRETS-01 — complete SSH tunnel authority. The bundle lives
    /// in the private credential store because every endpoint may carry a
    /// password or private-key passphrase. `None` means no dedicated authority
    /// has been established yet (so a legacy inline freedom.yaml block may be
    /// migrated); `Some([])` explicitly disables every tunnel.
    #[serde(default)]
    pub ssh_tunnels: Option<Vec<crate::transport::ssh_config::SshTunnelConfig>>,
}

/// Opaque credential-layer candidate for one named Telegram account.  This
/// intentionally has no `Debug` implementation because it retains both the
/// candidate token and the dynamic keychain preimage until commit or drop.
pub(crate) struct PreparedTelegramAccountUpsert {
    freedom_path: PathBuf,
    credentials_path: PathBuf,
    account_id: crate::channels::registry::ChannelAccountId,
    keychain_mode: bool,
    token: SecretString,
    candidate: crate::config::RuntimeConfigPair,
    freedom_before: FileSnapshot,
    credentials_before: FileSnapshot,
    freedom_after: FileSnapshot,
    credentials_after: FileSnapshot,
    /// Dynamic account keys plus the forbidden legacy singleton key.  Every
    /// entry is compared at commit so a probe cannot validate a mixed account
    /// generation.
    dynamic_before: BTreeMap<String, Option<SecretString>>,
}

/// Opaque exact-account retirement candidate.  It owns every public/private
/// preimage used by the CAS commit, including each currently configured
/// dynamic account key.  No caller can change the account selection between
/// preparation and publication.
pub(crate) struct PreparedTelegramAccountRemoval {
    freedom_path: PathBuf,
    credentials_path: PathBuf,
    account_id: crate::channels::registry::ChannelAccountId,
    keychain_mode: bool,
    freedom_before: FileSnapshot,
    credentials_before: FileSnapshot,
    freedom_after: FileSnapshot,
    credentials_after: FileSnapshot,
    dynamic_before: BTreeMap<String, Option<SecretString>>,
}

/// Opaque, file-backed candidate for one named Slack account. Slack account
/// keychain custody is deliberately unsupported until both bot and app tokens
/// have a complete dynamic-key lifecycle; preparation rejects that backend
/// before producing any candidate or writing either file.
pub(crate) struct PreparedSlackAccountUpsert {
    freedom_path: PathBuf,
    credentials_path: PathBuf,
    account_id: crate::channels::registry::ChannelAccountId,
    candidate: crate::config::RuntimeConfigPair,
    freedom_before: FileSnapshot,
    credentials_before: FileSnapshot,
    credentials_after: FileSnapshot,
}

/// Opaque exact-account Slack retirement candidate. It retains both raw file
/// preimages so commit can reject any drift after the caller's review.
pub(crate) struct PreparedSlackAccountRemoval {
    freedom_path: PathBuf,
    credentials_path: PathBuf,
    account_id: crate::channels::registry::ChannelAccountId,
    freedom_before: FileSnapshot,
    credentials_before: FileSnapshot,
    freedom_after: FileSnapshot,
    credentials_after: FileSnapshot,
}

impl PreparedTelegramAccountRemoval {
    pub(crate) fn account_id(&self) -> &crate::channels::registry::ChannelAccountId {
        &self.account_id
    }
}

impl PreparedTelegramAccountUpsert {
    /// The exact coherent generation that an external Telegram `getMe` probe
    /// may inspect.  It is borrowed, never reconstructed by a facade.
    pub(crate) fn candidate_pair(&self) -> &crate::config::RuntimeConfigPair {
        &self.candidate
    }

    /// The only named account which this candidate may create or replace.
    pub(crate) fn account_id(&self) -> &crate::channels::registry::ChannelAccountId {
        &self.account_id
    }
}

impl PreparedSlackAccountUpsert {
    /// The exact coherent file-backed generation that a read-only Slack
    /// `auth.test` probe may inspect before publication.
    pub(crate) fn candidate_pair(&self) -> &crate::config::RuntimeConfigPair {
        &self.candidate
    }

    pub(crate) fn account_id(&self) -> &crate::channels::registry::ChannelAccountId {
        &self.account_id
    }
}

impl PreparedSlackAccountRemoval {
    pub(crate) fn account_id(&self) -> &crate::channels::registry::ChannelAccountId {
        &self.account_id
    }
}

fn same_secret_snapshot(left: Option<&SecretString>, right: Option<&SecretString>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.expose() == right.expose(),
        _ => false,
    }
}

/// Durable, opaque compensation handle for one n8n adoption.  It intentionally
/// has no `Debug`: both file snapshots and the keychain preimage can contain
/// credentials.  The custody sidecar is private-permissioned and survives a
/// crash between publication and the job service's Ready transition.
pub(crate) struct PreparedN8nAdoptionUpdate {
    freedom_path: PathBuf,
    credentials_path: PathBuf,
    custody_path: PathBuf,
    keychain_mode: bool,
    keychain_before_present: bool,
    keychain_backup_key: Option<String>,
    keychain_candidate_key: Option<String>,
    freedom_before: FileSnapshot,
    credentials_before: FileSnapshot,
    freedom_after: FileSnapshot,
    credentials_after: FileSnapshot,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum N8nAdoptionPhase {
    PreparingKeychain,
    Prepared,
    CanonicalUpdatedPairPending,
    Published,
    PairRestoredKeychainPending,
    CleanupPending,
    ReadyFinalizationPending,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct N8nAdoptionCustody {
    job_id: String,
    phase: N8nAdoptionPhase,
    keychain_mode: bool,
    freedom_before: JournalFileSnapshot,
    credentials_before: JournalFileSnapshot,
    freedom_after: JournalFileSnapshot,
    credentials_after: JournalFileSnapshot,
    keychain_before_present: bool,
    keychain_backup_key: Option<String>,
    keychain_candidate_key: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum N8nOwnedCleanupOutcome {
    Cleared,
    AlreadyAbsent,
    PreservedUnproven,
    PreservedChanged,
}

impl N8nOwnedCleanupOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Cleared => "cleared",
            Self::AlreadyAbsent => "already_absent",
            Self::PreservedUnproven => "preserved_unproven",
            Self::PreservedChanged => "preserved_changed",
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct N8nOwnedBindingReceipt {
    job_id: String,
    endpoint_origin: String,
    #[serde(default)]
    api_version: Option<String>,
    api_key_commitment: String,
    keychain_mode: bool,
}

/// State observed from a durable n8n custody sidecar.  The adapter must bind
/// this to its authoritative job state: `Published` is never equivalent to
/// Ready, and `Prepared` has not changed the config/credential generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum N8nAdoptionCustodyState {
    Prepared,
    CanonicalUpdatedPairPending,
    Published,
    PairRestoredKeychainPending,
    RollbackCleanupPending,
    ReadyFinalizationPending,
}

fn n8n_adoption_custody_path(freedom_path: &Path, job_id: &str) -> Result<PathBuf> {
    let parsed = uuid::Uuid::parse_str(job_id).context("n8n adoption job id must be a UUID")?;
    anyhow::ensure!(
        parsed.hyphenated().to_string() == job_id,
        "n8n adoption job id must be canonical lowercase hyphenated UUID"
    );
    Ok(transaction_directory(freedom_path).join(format!(".n8n-adoption-{job_id}.custody.yaml")))
}

fn n8n_adoption_keychain_key(job_id: &str, kind: &str) -> String {
    format!("n8n_api_key.{kind}.{job_id}")
}

fn n8n_owned_binding_receipt_path(freedom_path: &Path, job_id: &str) -> Result<PathBuf> {
    n8n_adoption_custody_path(freedom_path, job_id).map(|_| {
        transaction_directory(freedom_path).join(format!(".n8n-owned-{job_id}.receipt.yaml"))
    })
}

fn n8n_key_commitment(value: &SecretString) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth.n8n-owned-binding.v1\0");
    digest.update(value.expose().as_bytes());
    hex::encode(digest.finalize())
}

fn persist_n8n_owned_binding_receipt(path: &Path, receipt: &N8nOwnedBindingReceipt) -> Result<()> {
    let body = serde_yaml::to_string(receipt).context("serialize n8n ownership receipt")?;
    crate::util::atomic_write::atomic_write_private(path, body.as_bytes())
        .context("persist n8n ownership receipt")
}

fn load_n8n_owned_binding_receipt(path: &Path) -> Result<Option<N8nOwnedBindingReceipt>> {
    let Some(body) = read_private_journal(path)? else {
        return Ok(None);
    };
    serde_yaml::from_slice(&body)
        .context("parse n8n ownership receipt")
        .map(Some)
}

fn persist_n8n_adoption_custody(path: &Path, custody: &N8nAdoptionCustody) -> Result<()> {
    let body = zeroize::Zeroizing::new(
        serde_yaml::to_string(custody).context("serialize private n8n adoption custody")?,
    );
    crate::util::atomic_write::atomic_write_private(path, body.as_bytes())
        .with_context(|| format!("persist private n8n adoption custody {}", path.display()))
}

fn load_n8n_adoption_custody(path: &Path) -> Result<N8nAdoptionCustody> {
    let body = read_private_journal(path)?
        .with_context(|| format!("n8n adoption custody {} is missing", path.display()))?;
    serde_yaml::from_slice(&body)
        .with_context(|| format!("parse n8n adoption custody {}", path.display()))
}

impl N8nAdoptionCustody {
    fn from_prepared(job_id: String, prepared: &PreparedN8nAdoptionUpdate) -> Self {
        Self {
            job_id,
            phase: N8nAdoptionPhase::PreparingKeychain,
            keychain_mode: prepared.keychain_mode,
            freedom_before: JournalFileSnapshot::from_file_snapshot(&prepared.freedom_before),
            credentials_before: JournalFileSnapshot::from_file_snapshot(
                &prepared.credentials_before,
            ),
            freedom_after: JournalFileSnapshot::from_file_snapshot(&prepared.freedom_after),
            credentials_after: JournalFileSnapshot::from_file_snapshot(&prepared.credentials_after),
            keychain_before_present: prepared.keychain_before_present,
            keychain_backup_key: prepared.keychain_backup_key.clone(),
            keychain_candidate_key: prepared.keychain_candidate_key.clone(),
        }
    }

    fn snapshots(&self) -> Result<(FileSnapshot, FileSnapshot, FileSnapshot, FileSnapshot)> {
        Ok((
            self.freedom_before.decode("n8n freedom_before")?,
            self.credentials_before.decode("n8n credentials_before")?,
            self.freedom_after.decode("n8n freedom_after")?,
            self.credentials_after.decode("n8n credentials_after")?,
        ))
    }
}

fn classify_n8n_adoption_custody(
    phase: N8nAdoptionPhase,
    files_before: bool,
    files_after: bool,
    key_before: bool,
    key_after: bool,
) -> Result<N8nAdoptionCustodyState> {
    if matches!(phase, N8nAdoptionPhase::ReadyFinalizationPending) && files_after {
        Ok(N8nAdoptionCustodyState::ReadyFinalizationPending)
    } else if matches!(phase, N8nAdoptionPhase::CleanupPending) && files_before && key_before {
        Ok(N8nAdoptionCustodyState::RollbackCleanupPending)
    } else if files_after && key_after {
        Ok(N8nAdoptionCustodyState::Published)
    } else if matches!(phase, N8nAdoptionPhase::CanonicalUpdatedPairPending)
        && files_before
        && key_after
    {
        Ok(N8nAdoptionCustodyState::CanonicalUpdatedPairPending)
    } else if files_before && key_after {
        Ok(N8nAdoptionCustodyState::PairRestoredKeychainPending)
    } else if files_before && key_before {
        Ok(N8nAdoptionCustodyState::Prepared)
    } else {
        anyhow::bail!(
            "n8n adoption custody does not match either exact source or target generation; manual repair required"
        )
    }
}

/// The only keychain cleanup primitive used by finalization and rollback.
/// Keeping the store as a private parameter makes partial-delete retry paths
/// testable without serializing key material into the custody sidecar.
fn cleanup_n8n_keychain_custody(
    store: &dyn crate::config::keychain::SecretStore,
    custody: &N8nAdoptionCustody,
) -> Result<()> {
    store.delete(
        custody
            .keychain_backup_key
            .as_deref()
            .context("missing n8n keychain backup reference")?,
    )?;
    store.delete(
        custody
            .keychain_candidate_key
            .as_deref()
            .context("missing n8n keychain candidate reference")?,
    )?;
    Ok(())
}

impl Credentials {
    /// Presence-only map guard for outbound rollout. It has no side effect on
    /// legacy Telegram fields or keychain material.
    pub fn telegram_account_map_active(&self) -> bool {
        !self.channel_accounts.telegram.is_empty()
    }

    /// Presence-only map guard. Slack named accounts are persisted in the
    /// normal credentials file until a dedicated account-keychain lifecycle is
    /// introduced; they must never disappear through an empty-store shortcut.
    pub fn slack_account_map_active(&self) -> bool {
        !self.channel_accounts.slack.is_empty()
    }

    /// Prepare an outbound n8n endpoint/key binding. Preparation captures the
    /// exact raw pair and the one keychain entry, then persists a private
    /// custody sidecar before any network probe or config publication. The
    /// caller may safely probe `api_key` in memory before calling commit.
    pub(crate) fn prepare_n8n_adoption_at(
        freedom_path: &Path,
        credentials_path: &Path,
        job_id: &str,
        instance: crate::config::N8nInstanceConfig,
        api_key: SecretString,
    ) -> Result<PreparedN8nAdoptionUpdate> {
        anyhow::ensure!(
            !api_key.expose().trim().is_empty(),
            "n8n API key must be non-blank"
        );
        instance.validate().map_err(anyhow::Error::msg)?;
        let custody_path = n8n_adoption_custody_path(freedom_path, job_id)?;
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for n8n adoption"
        );
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    anyhow::ensure!(
                        !custody_path.exists(),
                        "n8n adoption custody already exists for job; recover it before retrying"
                    );
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    let mut config =
                        crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)
                            .with_context(|| {
                                format!(
                                    "load {} for n8n adoption preparation",
                                    freedom_path.display()
                                )
                            })?;
                    let mut credentials = Self::load_or_default_unlocked(credentials_path)
                        .with_context(|| {
                            format!(
                                "load {} for n8n adoption preparation",
                                credentials_path.display()
                            )
                        })?;
                    let keychain_mode =
                        config.secrets_backend == crate::config::SecretsBackend::Keychain;
                    let opened_store = if keychain_mode {
                        Some(
                            crate::config::keychain::open_store()
                                .context("open OS keychain for n8n adoption preparation")?,
                        )
                    } else {
                        None
                    };
                    let keychain_before = if let Some(store) = opened_store.as_deref() {
                        store
                            .get("n8n_api_key")
                            .context("snapshot n8n API key from keychain")?
                    } else {
                        None
                    };
                    let keychain_backup_key =
                        keychain_mode.then(|| n8n_adoption_keychain_key(job_id, "backup"));
                    let keychain_candidate_key =
                        keychain_mode.then(|| n8n_adoption_keychain_key(job_id, "candidate"));
                    config.n8n_instance = Some(instance);
                    credentials.n8n_api_key = (!keychain_mode).then(|| api_key.clone());
                    let freedom_body = render_freedom_preserving_unknown_yaml(
                        &config,
                        &freedom_before,
                        InlineTelegramTokenPolicy::Preserve,
                    )?;
                    let freedom_after = FileSnapshot::Present(zeroize::Zeroizing::new(
                        freedom_body.as_bytes().to_vec(),
                    ));
                    let credentials_after = credentials.rendered_file_snapshot_preserving_unknown(
                        credentials_path,
                        &credentials_before,
                    )?;
                    let prepared = PreparedN8nAdoptionUpdate {
                        freedom_path: freedom_path.to_path_buf(),
                        credentials_path: credentials_path.to_path_buf(),
                        custody_path,
                        keychain_mode,
                        keychain_before_present: keychain_before.is_some(),
                        keychain_backup_key,
                        keychain_candidate_key,
                        freedom_before,
                        credentials_before,
                        freedom_after,
                        credentials_after,
                    };
                    persist_n8n_adoption_custody(
                        &prepared.custody_path,
                        &N8nAdoptionCustody::from_prepared(job_id.to_owned(), &prepared),
                    )?;
                    if let Some(store) = opened_store.as_deref() {
                        let backup = prepared
                            .keychain_backup_key
                            .as_deref()
                            .expect("keychain backup key");
                        let candidate = prepared
                            .keychain_candidate_key
                            .as_deref()
                            .expect("keychain candidate key");
                        anyhow::ensure!(
                            store.get(backup)?.is_none() && store.get(candidate)?.is_none(),
                            "n8n adoption keychain custody keys already exist; recover the job before retrying"
                        );
                        if let Some(previous) = keychain_before.as_ref() {
                            store
                                .set(backup, previous)
                                .context("persist n8n API key backup in keychain")?;
                        }
                        if let Err(error) = store.set(candidate, &api_key) {
                            let _ = store.delete(backup);
                            return Err(error).context("persist n8n API key candidate in keychain");
                        }
                    }
                    let mut custody = load_n8n_adoption_custody(&prepared.custody_path)?;
                    custody.phase = N8nAdoptionPhase::Prepared;
                    persist_n8n_adoption_custody(&prepared.custody_path, &custody)?;
                    Ok(prepared)
                })
            })
        })
    }

    /// Publish precisely the generation captured by preparation. Both raw
    /// files and the configured keychain entry are CAS-checked first. A
    /// recoverable early pair failure restores the keychain; a crossed
    /// publication retains custody for deterministic recovery/rollback.
    pub(crate) fn commit_prepared_n8n_adoption_at(
        prepared: PreparedN8nAdoptionUpdate,
    ) -> Result<()> {
        let freedom_dir = transaction_directory(&prepared.freedom_path);
        with_dual_file_transaction_lock(&prepared.freedom_path, || {
            with_config_writer_guard(&prepared.freedom_path, || {
                with_legacy_pair_locks(&prepared.freedom_path, &prepared.credentials_path, || {
                    anyhow::ensure!(
                        FileSnapshot::capture(&prepared.freedom_path)?
                            .same_as(&prepared.freedom_before)
                            && FileSnapshot::capture(&prepared.credentials_path)?
                                .same_as(&prepared.credentials_before),
                        "n8n adoption source configuration changed after preparation; retry the command"
                    );
                    let opened_store = prepared
                        .keychain_mode
                        .then(crate::config::keychain::open_store)
                        .transpose()
                        .context("open OS keychain for n8n adoption commit")?;
                    let store = opened_store.as_deref();
                    if let Some(store) = store {
                        let backup = prepared
                            .keychain_backup_key
                            .as_deref()
                            .context("missing n8n keychain backup reference")?;
                        let candidate = prepared
                            .keychain_candidate_key
                            .as_deref()
                            .context("missing n8n keychain candidate reference")?;
                        let before = store.get(backup)?;
                        anyhow::ensure!(
                            before.is_some() == prepared.keychain_before_present,
                            "n8n keychain backup presence changed after preparation; retry the command"
                        );
                        anyhow::ensure!(
                            same_secret_snapshot(
                                store.get("n8n_api_key")?.as_ref(),
                                before.as_ref()
                            ),
                            "n8n API key changed after preparation; retry the command"
                        );
                        let candidate_value = store
                            .get(candidate)?
                            .context("n8n keychain candidate is missing")?;
                        let mut custody = load_n8n_adoption_custody(&prepared.custody_path)?;
                        custody.phase = N8nAdoptionPhase::CanonicalUpdatedPairPending;
                        persist_n8n_adoption_custody(&prepared.custody_path, &custody)?;
                        store
                            .set("n8n_api_key", &candidate_value)
                            .context("write n8n API key before adoption publication")?;
                    }
                    let publication = publish_prepared_file_pair(
                        &prepared.freedom_path,
                        &prepared.credentials_path,
                        &freedom_dir,
                        &prepared.freedom_before,
                        &prepared.freedom_after,
                        &prepared.credentials_before,
                        &prepared.credentials_after,
                        (),
                        Some(|path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }),
                        |_| Ok(()),
                    );
                    if let Err(error) = publication {
                        if let Some(store) =
                            store.filter(|_| !dual_file_target_publication_crossed(&error))
                        {
                            let backup = prepared
                                .keychain_backup_key
                                .as_deref()
                                .context("missing n8n keychain backup reference")?;
                            match store.get(backup)? {
                                Some(value) => store.set("n8n_api_key", &value),
                                None => store.delete("n8n_api_key"),
                            }
                            .context("restore n8n API key after uncommitted adoption failure")?;
                            let mut custody = load_n8n_adoption_custody(&prepared.custody_path)?;
                            custody.phase = N8nAdoptionPhase::Prepared;
                            persist_n8n_adoption_custody(&prepared.custody_path, &custody)?;
                        }
                        return Err(error);
                    }
                    let mut custody = load_n8n_adoption_custody(&prepared.custody_path)?;
                    custody.phase = N8nAdoptionPhase::Published;
                    persist_n8n_adoption_custody(&prepared.custody_path, &custody)?;
                    Ok(())
                })
            })
        })
    }

    /// Returns the exact durable publication state. If a crash occurred after
    /// the pair committed but before the sidecar phase flip, target equality
    /// still reports `Published`; mixed generations fail closed.
    #[cfg(test)]
    pub(crate) fn inspect_n8n_adoption_custody_at(
        freedom_path: &Path,
        credentials_path: &Path,
        job_id: &str,
    ) -> Result<N8nAdoptionCustodyState> {
        let custody_path = n8n_adoption_custody_path(freedom_path, job_id)?;
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let custody = load_n8n_adoption_custody(&custody_path)?;
                    let (fb, cb, fa, ca) = custody.snapshots()?;
                    let files_before = FileSnapshot::capture(freedom_path)?.same_as(&fb)
                        && FileSnapshot::capture(credentials_path)?.same_as(&cb);
                    let files_after = FileSnapshot::capture(freedom_path)?.same_as(&fa)
                        && FileSnapshot::capture(credentials_path)?.same_as(&ca);
                    let mut opened_store = None;
                    let key_state = if custody.keychain_mode {
                        opened_store = Some(
                            crate::config::keychain::open_store()
                                .context("open OS keychain for n8n adoption recovery")?,
                        );
                        opened_store
                            .as_deref()
                            .expect("opened keychain store")
                            .get("n8n_api_key")?
                    } else {
                        None
                    };
                    let store = opened_store.as_deref();
                    let backup = store
                        .map(|store| {
                            custody
                                .keychain_backup_key
                                .as_deref()
                                .context("missing n8n keychain backup reference")
                                .and_then(|key| store.get(key))
                        })
                        .transpose()?;
                    let candidate = store
                        .map(|store| {
                            custody
                                .keychain_candidate_key
                                .as_deref()
                                .context("missing n8n keychain candidate reference")
                                .and_then(|key| store.get(key))
                        })
                        .transpose()?;
                    let backup_value = backup.as_ref().and_then(Option::as_ref);
                    let candidate_value = candidate.as_ref().and_then(Option::as_ref);
                    let key_before = !custody.keychain_mode
                        || (backup_value.is_some() == custody.keychain_before_present
                            && same_secret_snapshot(key_state.as_ref(), backup_value));
                    let key_after = !custody.keychain_mode
                        || same_secret_snapshot(key_state.as_ref(), candidate_value);
                    classify_n8n_adoption_custody(
                        custody.phase,
                        files_before,
                        files_after,
                        key_before,
                        key_after,
                    )
                })
            })
        })
    }

    fn ensure_n8n_status_snapshot_is_safe(freedom_path: &Path) -> Result<()> {
        let directory = transaction_directory(freedom_path);
        let has_n8n_custody = match std::fs::read_dir(&directory) {
            Ok(entries) => {
                let mut found = false;
                for entry in entries {
                    let entry = entry.with_context(|| {
                        format!(
                            "read n8n adoption custody directory {}",
                            directory.display()
                        )
                    })?;
                    found |= entry.file_name().to_str().is_some_and(|name| {
                        name.starts_with(".n8n-adoption-") && name.ends_with(".custody.yaml")
                    });
                }
                found
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect n8n adoption custody directory {}",
                        directory.display()
                    )
                });
            }
        };
        anyhow::ensure!(
            read_private_journal(&directory.join(DUAL_FILE_JOURNAL_NAME))?.is_none()
                && read_private_journal(&directory.join(RESTORE_IN_PROGRESS_NAME))?.is_none()
                && !has_n8n_custody,
            "n8n adoption status is unavailable while a configuration transaction is pending"
        );
        Ok(())
    }

    /// Coherently re-read the adopted endpoint and effective secret after
    /// publication. It is crate-private because returning `SecretString` is
    /// only needed by the integration adapter's post-commit probe.
    pub(crate) fn read_n8n_adoption_binding_at(
        freedom_path: &Path,
        credentials_path: &Path,
    ) -> Result<(crate::config::N8nInstanceConfig, SecretString)> {
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let config =
                        crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)?;
                    let instance = config
                        .n8n_instance
                        .clone()
                        .context("adopted n8n endpoint is not configured")?;
                    let credentials =
                        Self::load_effective_unlocked(credentials_path, config.secrets_backend)?;
                    let api_key = credentials
                        .n8n_api_key
                        .context("adopted n8n API key is not configured")?;
                    Ok((instance, api_key))
                })
            })
        })
    }

    /// Read-only status view: it intentionally performs no migration,
    /// transaction recovery, or publication. The keychain path reports only
    /// presence and never loads a plaintext fallback for this binding.
    pub(crate) fn read_n8n_adoption_status_at(
        freedom_path: &Path,
        credentials_path: &Path,
    ) -> Result<(Option<crate::config::LoopbackHttpEndpoint>, bool)> {
        // Status must never acquire the recovery lock: doing so can publish or
        // roll back another process's journal. Snapshot twice and fail closed
        // if a writer changed either source or left a journal behind.
        Self::ensure_n8n_status_snapshot_is_safe(freedom_path)?;
        let freedom_before = FileSnapshot::capture(freedom_path)?;
        let credentials_before = FileSnapshot::capture(credentials_path)?;
        if matches!(
            (&freedom_before, &credentials_before),
            (FileSnapshot::Missing, FileSnapshot::Missing)
        ) {
            // A fresh home is an unconfigured, read-only state. Recheck both
            // the journal boundary and snapshots so a concurrent partial
            // writer is never mistaken for an empty configuration.
            Self::ensure_n8n_status_snapshot_is_safe(freedom_path)?;
            anyhow::ensure!(
                FileSnapshot::capture(freedom_path)?.same_as(&freedom_before)
                    && FileSnapshot::capture(credentials_path)?.same_as(&credentials_before),
                "n8n adoption status changed while it was being read; retry"
            );
            return Ok((None, false));
        }
        let result = (|| {
            let config =
                crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)?;
            let endpoint = config.n8n_instance.map(|instance| instance.endpoint);
            let raw = Self::load_or_default_unlocked(credentials_path)?;
            let present = if config.secrets_backend == crate::config::SecretsBackend::Keychain {
                anyhow::ensure!(
                    raw.n8n_api_key.is_none(),
                    "adopted n8n API key must reside in the configured keychain backend"
                );
                crate::config::keychain::open_store()
                    .context("open OS keychain for n8n status")?
                    .get("n8n_api_key")?
                    .is_some()
            } else {
                raw.n8n_api_key.is_some()
            };
            Ok((endpoint, present))
        })();
        Self::ensure_n8n_status_snapshot_is_safe(freedom_path)?;
        anyhow::ensure!(
            FileSnapshot::capture(freedom_path)?.same_as(&freedom_before)
                && FileSnapshot::capture(credentials_path)?.same_as(&credentials_before),
            "n8n adoption status changed while it was being read; retry"
        );
        result
    }

    /// Remove a published adoption only when the current public+private state
    /// still equals its target. This CAS guard prevents a stale failed job from
    /// deleting a later successful adoption.
    pub(crate) fn rollback_n8n_adoption_at(
        freedom_path: &Path,
        credentials_path: &Path,
        job_id: &str,
    ) -> Result<()> {
        let custody_path = n8n_adoption_custody_path(freedom_path, job_id)?;
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let custody = load_n8n_adoption_custody(&custody_path)?;
                    let (fb, cb, fa, ca) = custody.snapshots()?;
                    let opened_store = custody
                        .keychain_mode
                        .then(crate::config::keychain::open_store)
                        .transpose()
                        .context("open OS keychain for n8n adoption rollback")?;
                    let store = opened_store.as_deref();
                    let files_before = FileSnapshot::capture(freedom_path)?.same_as(&fb)
                        && FileSnapshot::capture(credentials_path)?.same_as(&cb);
                    let files_after = FileSnapshot::capture(freedom_path)?.same_as(&fa)
                        && FileSnapshot::capture(credentials_path)?.same_as(&ca);
                    let (key_before, key_after) = if let Some(store) = store {
                        let backup = custody
                            .keychain_backup_key
                            .as_deref()
                            .context("missing n8n keychain backup reference")?;
                        let candidate = custody
                            .keychain_candidate_key
                            .as_deref()
                            .context("missing n8n keychain candidate reference")?;
                        let current = store.get("n8n_api_key")?;
                        let before = store.get(backup)?;
                        let candidate = store.get(candidate)?;
                        (
                            before.is_some() == custody.keychain_before_present
                                && same_secret_snapshot(current.as_ref(), before.as_ref()),
                            same_secret_snapshot(current.as_ref(), candidate.as_ref()),
                        )
                    } else {
                        (true, true)
                    };
                    let state = classify_n8n_adoption_custody(
                        custody.phase,
                        files_before,
                        files_after,
                        key_before,
                        key_after,
                    )?;
                    anyhow::ensure!(
                        state != N8nAdoptionCustodyState::ReadyFinalizationPending,
                        "n8n adoption finalization has begun; Ready custody must not be rolled back"
                    );
                    if state == N8nAdoptionCustodyState::RollbackCleanupPending {
                        if let Some(store) = store {
                            cleanup_n8n_keychain_custody(store, &custody)?;
                        }
                        return crate::util::atomic_write::durable_remove_file(&custody_path)
                            .with_context(|| {
                                format!(
                                    "remove completed n8n rollback custody {}",
                                    custody_path.display()
                                )
                            });
                    }
                    if state == N8nAdoptionCustodyState::Prepared {
                        if let Some(store) = store {
                            cleanup_n8n_keychain_custody(store, &custody)?;
                        }
                        return crate::util::atomic_write::durable_remove_file(&custody_path)
                            .with_context(|| {
                                format!(
                                    "remove uncommitted n8n adoption custody {}",
                                    custody_path.display()
                                )
                            });
                    }
                    if matches!(
                        state,
                        N8nAdoptionCustodyState::CanonicalUpdatedPairPending
                            | N8nAdoptionCustodyState::PairRestoredKeychainPending
                    ) {
                        if let Some(store) = store {
                            let backup = custody
                                .keychain_backup_key
                                .as_deref()
                                .context("missing n8n keychain backup reference")?;
                            match store.get(backup)? {
                                Some(value) => store.set("n8n_api_key", &value),
                                None => store.delete("n8n_api_key"),
                            }?;
                            cleanup_n8n_keychain_custody(store, &custody)?;
                        }
                        return crate::util::atomic_write::durable_remove_file(&custody_path)
                            .with_context(|| {
                                format!(
                                    "remove repaired n8n adoption custody {}",
                                    custody_path.display()
                                )
                            });
                    }
                    anyhow::ensure!(
                        state == N8nAdoptionCustodyState::Published,
                        "n8n adoption custody is not recoverable"
                    );
                    let freedom_dir = transaction_directory(freedom_path);
                    publish_prepared_file_pair(
                        freedom_path,
                        credentials_path,
                        &freedom_dir,
                        &fa,
                        &fb,
                        &ca,
                        &cb,
                        (),
                        Some(|path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }),
                        |_| Ok(()),
                    )?;
                    let mut custody = load_n8n_adoption_custody(&custody_path)?;
                    custody.phase = N8nAdoptionPhase::PairRestoredKeychainPending;
                    persist_n8n_adoption_custody(&custody_path, &custody)?;
                    if let Some(store) = store {
                        let backup = custody
                            .keychain_backup_key
                            .as_deref()
                            .context("missing n8n keychain backup reference")?;
                        match store.get(backup)? {
                            Some(value) => store.set("n8n_api_key", &value),
                            None => store.delete("n8n_api_key"),
                        }
                        .context("restore n8n API key after adoption rollback")?;
                        custody.phase = N8nAdoptionPhase::CleanupPending;
                        persist_n8n_adoption_custody(&custody_path, &custody)?;
                        store
                            .delete(backup)
                            .context("remove n8n API key backup custody")?;
                        store
                            .delete(
                                custody
                                    .keychain_candidate_key
                                    .as_deref()
                                    .context("missing n8n keychain candidate reference")?,
                            )
                            .context("remove n8n API key candidate custody")?;
                    }
                    crate::util::atomic_write::durable_remove_file(&custody_path).with_context(
                        || {
                            format!(
                                "remove rolled-back n8n adoption custody {}",
                                custody_path.display()
                            )
                        },
                    )
                })
            })
        })
    }

    /// A Ready job calls this only after its durable Ready evidence has landed.
    /// It verifies the exact target before deleting compensation custody, so a
    /// crash after Ready leaves no recovery path that can undo success.
    pub(crate) fn finish_n8n_adoption_at(
        freedom_path: &Path,
        credentials_path: &Path,
        job_id: &str,
    ) -> Result<()> {
        let custody_path = n8n_adoption_custody_path(freedom_path, job_id)?;
        let receipt_path = n8n_owned_binding_receipt_path(freedom_path, job_id)?;
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let mut custody = load_n8n_adoption_custody(&custody_path)?;
                    let (_, _, freedom_after, credentials_after) = custody.snapshots()?;
                    anyhow::ensure!(
                        FileSnapshot::capture(freedom_path)?.same_as(&freedom_after)
                            && FileSnapshot::capture(credentials_path)?.same_as(&credentials_after),
                        "n8n adoption target changed before finalization; refusing to remove custody"
                    );
                    let opened_store = custody
                        .keychain_mode
                        .then(crate::config::keychain::open_store)
                        .transpose()
                        .context("open OS keychain for completed n8n custody cleanup")?;
                    let store = opened_store.as_deref();
                    let existing_receipt = load_n8n_owned_binding_receipt(&receipt_path)?;

                    if custody.phase != N8nAdoptionPhase::ReadyFinalizationPending {
                        let config = crate::config::FreedomConfig::load_public_from_path_unlocked(
                            freedom_path,
                        )?;
                        anyhow::ensure!(
                            (config.secrets_backend == crate::config::SecretsBackend::Keychain)
                                == custody.keychain_mode,
                            "n8n secrets backend changed before finalization; refusing to remove custody"
                        );
                        let instance = config
                            .n8n_instance
                            .as_ref()
                            .context("n8n endpoint missing before ownership receipt")?;
                        let current_key = if let Some(store) = store {
                            let candidate = custody
                                .keychain_candidate_key
                                .as_deref()
                                .context("missing n8n keychain candidate reference")?;
                            let current = store
                                .get("n8n_api_key")?
                                .context("n8n API key missing before ownership receipt")?;
                            anyhow::ensure!(
                                same_secret_snapshot(
                                    Some(&current),
                                    store.get(candidate)?.as_ref()
                                ),
                                "n8n API key changed before finalization; refusing to remove custody"
                            );
                            current
                        } else {
                            // The exact file snapshot above proves this is the prepared
                            // after-generation, so this key is the file candidate that
                            // the adoption published rather than a later edit.
                            Self::load_or_default_unlocked(credentials_path)?
                                .n8n_api_key
                                .context("n8n API key missing before ownership receipt")?
                        };
                        let receipt = N8nOwnedBindingReceipt {
                            job_id: job_id.to_owned(),
                            endpoint_origin: instance.endpoint.origin().to_owned(),
                            api_version: instance.api_version.clone(),
                            api_key_commitment: n8n_key_commitment(&current_key),
                            keychain_mode: custody.keychain_mode,
                        };
                        match existing_receipt.as_ref() {
                            Some(existing) => anyhow::ensure!(
                                *existing == receipt,
                                "n8n ownership receipt conflicts with completed adoption"
                            ),
                            None => persist_n8n_owned_binding_receipt(&receipt_path, &receipt)?,
                        }
                        custody.phase = N8nAdoptionPhase::ReadyFinalizationPending;
                        persist_n8n_adoption_custody(&custody_path, &custody)?;
                    } else if let Some(existing) = existing_receipt {
                        let config = crate::config::FreedomConfig::load_public_from_path_unlocked(
                            freedom_path,
                        )?;
                        anyhow::ensure!(
                            (config.secrets_backend == crate::config::SecretsBackend::Keychain)
                                == existing.keychain_mode,
                            "n8n secrets backend changed after ownership receipt; refusing to remove custody"
                        );
                        let instance = config
                            .n8n_instance
                            .as_ref()
                            .context("n8n endpoint missing after ownership receipt")?;
                        let current_key = if let Some(store) = store {
                            store.get("n8n_api_key")?
                        } else {
                            Self::load_or_default_unlocked(credentials_path)?.n8n_api_key
                        }
                        .context("n8n API key missing after ownership receipt")?;
                        anyhow::ensure!(
                            existing.job_id == job_id
                                && existing.endpoint_origin == instance.endpoint.origin()
                                && existing.api_version == instance.api_version
                                && existing.api_key_commitment == n8n_key_commitment(&current_key)
                                && existing.keychain_mode == custody.keychain_mode,
                            "n8n ownership receipt no longer matches completed adoption"
                        );
                    }
                    // A legacy ReadyFinalizationPending custody can predate receipts.
                    // Never create ownership proof from its current values on retry.
                    if let Some(store) = store {
                        cleanup_n8n_keychain_custody(store, &custody)?;
                    }
                    crate::util::atomic_write::durable_remove_file(&custody_path).with_context(
                        || {
                            format!(
                                "remove completed n8n adoption custody {}",
                                custody_path.display()
                            )
                        },
                    )
                })
            })
        })
    }
    /// Clear only a retained, file-backed n8n binding. Historical Ready jobs
    /// without a receipt, keychain-backed bindings, and any changed endpoint
    /// or key remain untouched and return an explicit conservative outcome.
    pub(crate) fn clear_owned_n8n_binding_at(
        freedom_path: &Path,
        credentials_path: &Path,
        source_job_id: &str,
        expected_endpoint: &crate::config::LoopbackHttpEndpoint,
    ) -> Result<N8nOwnedCleanupOutcome> {
        let receipt_path = n8n_owned_binding_receipt_path(freedom_path, source_job_id)?;
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let Some(receipt) = load_n8n_owned_binding_receipt(&receipt_path)? else {
                        return Ok(N8nOwnedCleanupOutcome::PreservedUnproven);
                    };
                    anyhow::ensure!(
                        receipt.job_id == source_job_id,
                        "n8n ownership receipt job mismatch"
                    );
                    if receipt.endpoint_origin != expected_endpoint.origin()
                        || receipt.keychain_mode
                    {
                        return Ok(N8nOwnedCleanupOutcome::PreservedUnproven);
                    }
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    let mut config =
                        crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)?;
                    if config.secrets_backend != crate::config::SecretsBackend::File {
                        return Ok(N8nOwnedCleanupOutcome::PreservedChanged);
                    }
                    let mut credentials = Self::load_or_default_unlocked(credentials_path)?;
                    let instance = config.n8n_instance.as_ref();
                    let endpoint = instance.map(|instance| instance.endpoint.origin().to_owned());
                    let key = credentials.n8n_api_key.as_ref();
                    if endpoint.is_none() && key.is_none() {
                        return Ok(N8nOwnedCleanupOutcome::AlreadyAbsent);
                    }
                    if endpoint.as_deref() != Some(receipt.endpoint_origin.as_str())
                        || !instance
                            .is_some_and(|instance| instance.api_version == receipt.api_version)
                        || key.map(n8n_key_commitment).as_deref()
                            != Some(receipt.api_key_commitment.as_str())
                    {
                        return Ok(N8nOwnedCleanupOutcome::PreservedChanged);
                    }
                    config.n8n_instance = None;
                    credentials.n8n_api_key = None;
                    let freedom_after = FileSnapshot::Present(zeroize::Zeroizing::new(
                        render_freedom_preserving_unknown_yaml(
                            &config,
                            &freedom_before,
                            InlineTelegramTokenPolicy::Preserve,
                        )?
                        .as_bytes()
                        .to_vec(),
                    ));
                    let credentials_after = credentials.rendered_file_snapshot_preserving_unknown(
                        credentials_path,
                        &credentials_before,
                    )?;
                    let freedom_dir = transaction_directory(freedom_path);
                    publish_prepared_file_pair(
                        freedom_path,
                        credentials_path,
                        &freedom_dir,
                        &freedom_before,
                        &freedom_after,
                        &credentials_before,
                        &credentials_after,
                        N8nOwnedCleanupOutcome::Cleared,
                        Some(|path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .map_err(anyhow::Error::from)
                        }),
                        |_| Ok(()),
                    )
                })
            })
        })
    }

    /// Commit the only permitted legacy-to-account Telegram binding. Both
    /// public admission policy and the effective legacy token move through the
    /// existing PREPARED pair transaction; no historical runtime state is read.
    pub(crate) fn migrate_legacy_telegram_to_account_at(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
    ) -> Result<()> {
        Self::migrate_legacy_telegram_to_account_at_using_fault_and_store(
            freedom_path,
            credentials_path,
            account_id,
            None,
            |_| Ok(()),
        )
    }

    /// Stage one explicit Telegram account upsert for an external, read-only
    /// candidate probe.  The returned value is deliberately opaque: it owns
    /// the exact raw pair and keychain observations that `commit` must compare
    /// after the probe, so callers cannot reconstruct a snapshot under a
    /// different lock boundary.
    pub(crate) fn prepare_telegram_account_upsert_at(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
        allowed_user_id: u64,
        token: SecretString,
    ) -> Result<PreparedTelegramAccountUpsert> {
        Self::prepare_telegram_account_upsert_at_using_store(
            freedom_path,
            credentials_path,
            account_id,
            allowed_user_id,
            token,
            None,
        )
    }

    /// Commit exactly the generation previously returned by
    /// [`Self::prepare_telegram_account_upsert_at`].  A changed raw file or
    /// any relevant dynamic keychain entry is a retry error before mutation.
    pub(crate) fn commit_prepared_telegram_account_upsert_at(
        prepared: PreparedTelegramAccountUpsert,
    ) -> Result<()> {
        Self::commit_prepared_telegram_account_upsert_at_using_fault_and_store(
            prepared,
            None,
            |_| Ok(()),
        )
    }

    fn prepare_telegram_account_upsert_at_using_store(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
        allowed_user_id: u64,
        token: SecretString,
        injected_store: Option<&dyn crate::config::keychain::SecretStore>,
    ) -> Result<PreparedTelegramAccountUpsert> {
        anyhow::ensure!(
            allowed_user_id != 0,
            "Telegram account allowed_user_id must be nonzero"
        );
        anyhow::ensure!(
            !token.expose().trim().is_empty(),
            "Telegram account token must be non-blank"
        );
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a durable transaction"
        );

        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    let mut config =
                        crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)
                            .with_context(|| {
                                format!(
                                    "load {} for Telegram account upsert preparation",
                                    freedom_path.display()
                                )
                            })?;
                    let mut raw_credentials = Self::load_or_default_unlocked(credentials_path)
                        .with_context(|| {
                            format!(
                                "load {} for Telegram account upsert preparation",
                                credentials_path.display()
                            )
                        })?;
                    anyhow::ensure!(
                        config.telegram_token.is_none()
                            && config.telegram_user_id.is_none()
                            && raw_credentials.telegram_token.is_none(),
                        "legacy Telegram scalar fields cannot coexist with a Telegram account upsert"
                    );
                    anyhow::ensure!(
                        config
                            .channel_accounts
                            .telegram
                            .keys()
                            .eq(raw_credentials.channel_accounts.telegram.keys()),
                        "Telegram account policy and raw credential keys must match exactly before upsert"
                    );
                    for (mapped_account, policy) in &config.channel_accounts.telegram {
                        anyhow::ensure!(
                            policy.allowed_user_id != 0,
                            "telegram account `{mapped_account}` has an invalid allowed_user_id"
                        );
                    }

                    let keychain_mode =
                        config.secrets_backend == crate::config::SecretsBackend::Keychain;
                    let opened_store =
                        if keychain_mode && injected_store.is_none() {
                            Some(crate::config::keychain::open_store().context(
                                "open OS keychain for Telegram account upsert preparation",
                            )?)
                        } else {
                            None
                        };
                    // File mode must not even inspect an injected store.
                    let store = if keychain_mode {
                        injected_store.or(opened_store.as_deref())
                    } else {
                        None
                    };
                    let mut dynamic_before = BTreeMap::new();
                    if let Some(store) = store {
                        // The legacy key is forbidden and is also part of the
                        // commit CAS, preventing a concurrent scalar fallback.
                        let legacy = store.get("telegram_token").context(
                            "read legacy Telegram key during account upsert preparation",
                        )?;
                        anyhow::ensure!(
                            legacy.is_none(),
                            "legacy Telegram keychain token cannot coexist with a Telegram account upsert"
                        );
                        dynamic_before.insert("telegram_token".to_owned(), legacy);
                        for mapped_account in config
                            .channel_accounts
                            .telegram
                            .keys()
                            .chain(std::iter::once(&account_id))
                        {
                            let key =
                                crate::config::keychain::telegram_account_token_key(mapped_account);
                            if dynamic_before.contains_key(&key) {
                                continue;
                            }
                            let value = store.get(&key).with_context(|| {
                                format!(
                                    "read dynamic Telegram account token for `{mapped_account}` during upsert preparation"
                                )
                            })?;
                            dynamic_before.insert(key, value);
                        }
                    }

                    let existing_dm_pairing = config
                        .channel_accounts
                        .telegram
                        .get(&account_id)
                        .and_then(|existing| existing.dm_pairing.clone());
                    let existing_incarnation = config
                        .channel_accounts
                        .telegram
                        .get(&account_id)
                        .and_then(|existing| existing.incarnation.clone());
                    config.channel_accounts.telegram.insert(
                        account_id.clone(),
                        crate::config::TelegramAccountConfig {
                            allowed_user_id,
                            incarnation: Some(
                                existing_incarnation
                                    .unwrap_or_else(crate::config::AccountIncarnation::new_random),
                            ),
                            dm_pairing: existing_dm_pairing,
                        },
                    );
                    raw_credentials.channel_accounts.telegram.insert(
                        account_id.clone(),
                        TelegramAccountCredentials {
                            token: (!keychain_mode).then(|| token.clone()),
                        },
                    );

                    let mut effective_credentials = raw_credentials.clone();
                    if let Some(store) = store {
                        crate::config::keychain::supplement_telegram_account_tokens(
                            &mut effective_credentials,
                            store,
                        )?;
                        effective_credentials
                            .channel_accounts
                            .telegram
                            .get_mut(&account_id)
                            .context("prepared Telegram account credential is missing")?
                            .token = Some(token.clone());
                    }
                    let candidate = crate::config::RuntimeConfigPair {
                        config: config.clone(),
                        raw_credentials: raw_credentials.clone(),
                        credentials: effective_credentials,
                    };
                    let accounts = candidate.authenticated_telegram_accounts()?;
                    anyhow::ensure!(
                        accounts
                            .iter()
                            .any(|account| account.channel_ref().account_id == account_id),
                        "prepared Telegram account is not authenticated"
                    );

                    let freedom_body = render_freedom_preserving_unknown_yaml(
                        &config,
                        &freedom_before,
                        InlineTelegramTokenPolicy::Preserve,
                    )?;
                    let freedom_after = FileSnapshot::Present(zeroize::Zeroizing::new(
                        freedom_body.as_bytes().to_vec(),
                    ));
                    let credentials_after = raw_credentials
                        .rendered_file_snapshot_preserving_unknown(
                            credentials_path,
                            &credentials_before,
                        )?;
                    Ok(PreparedTelegramAccountUpsert {
                        freedom_path: freedom_path.to_path_buf(),
                        credentials_path: credentials_path.to_path_buf(),
                        account_id,
                        keychain_mode,
                        token,
                        candidate,
                        freedom_before,
                        credentials_before,
                        freedom_after,
                        credentials_after,
                        dynamic_before,
                    })
                })
            })
        })
    }

    fn commit_prepared_telegram_account_upsert_at_using_fault_and_store<H>(
        prepared: PreparedTelegramAccountUpsert,
        injected_store: Option<&dyn crate::config::keychain::SecretStore>,
        fault: H,
    ) -> Result<()>
    where
        H: FnMut(DualFileFaultPoint) -> Result<()>,
    {
        let freedom_dir = transaction_directory(&prepared.freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(&prepared.credentials_path),
            "prepared Telegram account paths are not sibling files"
        );
        with_dual_file_transaction_lock(&prepared.freedom_path, || {
            with_config_writer_guard(&prepared.freedom_path, || {
                with_legacy_pair_locks(&prepared.freedom_path, &prepared.credentials_path, || {
                    let current_freedom = FileSnapshot::capture(&prepared.freedom_path)?;
                    let current_credentials = FileSnapshot::capture(&prepared.credentials_path)?;
                    anyhow::ensure!(
                        current_freedom.same_as(&prepared.freedom_before)
                            && current_credentials.same_as(&prepared.credentials_before),
                        "Telegram account configuration changed after its reviewed candidate; retry the command"
                    );
                    let opened_store = if prepared.keychain_mode && injected_store.is_none() {
                        Some(
                            crate::config::keychain::open_store()
                                .context("open OS keychain for Telegram account upsert commit")?,
                        )
                    } else {
                        None
                    };
                    let store = if prepared.keychain_mode {
                        injected_store.or(opened_store.as_deref())
                    } else {
                        None
                    };
                    if prepared.keychain_mode {
                        let store = store.context("keychain account upsert has no secret store")?;
                        for (key, expected) in &prepared.dynamic_before {
                            let actual = store.get(key).with_context(|| {
                                format!(
                                    "read dynamic Telegram key `{key}` before account upsert commit"
                                )
                            })?;
                            anyhow::ensure!(
                                same_secret_snapshot(actual.as_ref(), expected.as_ref()),
                                "Telegram account dynamic credential changed after its reviewed candidate; retry the command"
                            );
                        }
                        let selected_key = crate::config::keychain::telegram_account_token_key(
                            &prepared.account_id,
                        );
                        store.set(&selected_key, &prepared.token).context(
                            "write dynamic Telegram account token before PREPARED pair publication",
                        )?;
                    }
                    let publication = publish_prepared_file_pair(
                        &prepared.freedom_path,
                        &prepared.credentials_path,
                        &freedom_dir,
                        &prepared.freedom_before,
                        &prepared.freedom_after,
                        &prepared.credentials_before,
                        &prepared.credentials_after,
                        (),
                        Some(|path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }),
                        fault,
                    );
                    if let Err(error) = publication {
                        if prepared.keychain_mode && !dual_file_target_publication_crossed(&error) {
                            let store =
                                store.context("keychain account upsert has no secret store")?;
                            let selected_key = crate::config::keychain::telegram_account_token_key(
                                &prepared.account_id,
                            );
                            let previous = prepared
                                .dynamic_before
                                .get(&selected_key)
                                .context("prepared dynamic Telegram token snapshot is missing")?;
                            let restored = match previous {
                                Some(value) => store.set(&selected_key, value),
                                None => store.delete(&selected_key),
                            };
                            if let Err(restore_error) = restored {
                                return Err(error.context(format!(
                                    "restore dynamic Telegram account token after recoverable pair failure: {restore_error:#}"
                                )));
                            }
                        }
                        return Err(error);
                    }
                    Ok(())
                })
            })
        })
    }

    /// Prepare retirement of one exact named Telegram account.  An empty map
    /// is a safe disabled state only because all scalar Telegram authority and
    /// the forbidden legacy dynamic key are required absent before staging.
    pub(crate) fn prepare_telegram_account_removal_at(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
    ) -> Result<PreparedTelegramAccountRemoval> {
        Self::prepare_telegram_account_removal_at_using_store(
            freedom_path,
            credentials_path,
            account_id,
            None,
        )
    }

    fn prepare_telegram_account_removal_at_using_store(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
        injected_store: Option<&dyn crate::config::keychain::SecretStore>,
    ) -> Result<PreparedTelegramAccountRemoval> {
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a durable transaction"
        );
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    let mut config =
                        crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)
                            .with_context(|| {
                                format!(
                                    "load {} for Telegram account retirement",
                                    freedom_path.display()
                                )
                            })?;
                    let mut credentials = Self::load_or_default_unlocked(credentials_path)
                        .with_context(|| {
                            format!(
                                "load {} for Telegram account retirement",
                                credentials_path.display()
                            )
                        })?;
                    anyhow::ensure!(
                        config.telegram_token.is_none()
                            && config.telegram_user_id.is_none()
                            && credentials.telegram_token.is_none(),
                        "legacy Telegram scalar fields cannot coexist with named account retirement"
                    );
                    anyhow::ensure!(
                        config
                            .channel_accounts
                            .telegram
                            .keys()
                            .eq(credentials.channel_accounts.telegram.keys()),
                        "Telegram account policy and raw credential keys must match exactly before retirement"
                    );
                    let policy = config
                        .channel_accounts
                        .telegram
                        .get(&account_id)
                        .context("selected Telegram account is not configured")?;
                    anyhow::ensure!(
                        policy.allowed_user_id != 0,
                        "selected Telegram account has no pinned operator"
                    );
                    let keychain_mode =
                        config.secrets_backend == crate::config::SecretsBackend::Keychain;
                    if !keychain_mode {
                        let credential = credentials
                            .channel_accounts
                            .telegram
                            .get(&account_id)
                            .and_then(|entry| entry.token.as_ref())
                            .context(
                                "selected Telegram account has no effective file credential",
                            )?;
                        anyhow::ensure!(
                            !credential.expose().trim().is_empty(),
                            "selected Telegram account has an empty credential"
                        );
                    }
                    let opened_store = if keychain_mode && injected_store.is_none() {
                        Some(
                            crate::config::keychain::open_store()
                                .context("open OS keychain for Telegram account retirement")?,
                        )
                    } else {
                        None
                    };
                    let store = if keychain_mode {
                        injected_store.or(opened_store.as_deref())
                    } else {
                        None
                    };
                    let mut dynamic_before = BTreeMap::new();
                    if let Some(store) = store {
                        for mapped in config.channel_accounts.telegram.keys() {
                            let key = crate::config::keychain::telegram_account_token_key(mapped);
                            dynamic_before.insert(key.clone(), store.get(&key)?);
                        }
                        let legacy = "telegram_token".to_owned();
                        let legacy_value = store.get(&legacy)?;
                        anyhow::ensure!(
                            legacy_value.is_none(),
                            "legacy Telegram keychain token cannot coexist with named account retirement"
                        );
                        dynamic_before.insert(legacy, legacy_value);
                        let selected_key =
                            crate::config::keychain::telegram_account_token_key(&account_id);
                        anyhow::ensure!(
                            dynamic_before
                                .get(&selected_key)
                                .and_then(Option::as_ref)
                                .is_some_and(|token| !token.expose().trim().is_empty()),
                            "selected Telegram account has no effective dynamic credential"
                        );
                    }

                    config.channel_accounts.telegram.remove(&account_id);
                    credentials.channel_accounts.telegram.remove(&account_id);
                    let freedom_after = FileSnapshot::Present(zeroize::Zeroizing::new(
                        render_freedom_preserving_unknown_yaml(
                            &config,
                            &freedom_before,
                            InlineTelegramTokenPolicy::Preserve,
                        )?
                        .as_bytes()
                        .to_vec(),
                    ));
                    let credentials_after = credentials.rendered_file_snapshot_preserving_unknown(
                        credentials_path,
                        &credentials_before,
                    )?;
                    Ok(PreparedTelegramAccountRemoval {
                        freedom_path: freedom_path.to_path_buf(),
                        credentials_path: credentials_path.to_path_buf(),
                        account_id,
                        keychain_mode,
                        freedom_before,
                        credentials_before,
                        freedom_after,
                        credentials_after,
                        dynamic_before,
                    })
                })
            })
        })
    }

    /// Commit a previously prepared exact-account retirement.  Dynamic-key
    /// deletion precedes PREPARED publication; a pre-target failure restores
    /// its preimage, while a crossed target is left for journal recovery.
    pub(crate) fn commit_prepared_telegram_account_removal_at(
        prepared: PreparedTelegramAccountRemoval,
    ) -> Result<()> {
        Self::commit_prepared_telegram_account_removal_at_using_fault_and_store(
            prepared,
            None,
            |_| Ok(()),
        )
    }

    fn commit_prepared_telegram_account_removal_at_using_fault_and_store<H>(
        prepared: PreparedTelegramAccountRemoval,
        injected_store: Option<&dyn crate::config::keychain::SecretStore>,
        fault: H,
    ) -> Result<()>
    where
        H: FnMut(DualFileFaultPoint) -> Result<()>,
    {
        let freedom_dir = transaction_directory(&prepared.freedom_path);
        with_dual_file_transaction_lock(&prepared.freedom_path, || {
            with_config_writer_guard(&prepared.freedom_path, || {
                with_legacy_pair_locks(&prepared.freedom_path, &prepared.credentials_path, || {
                    anyhow::ensure!(
                        FileSnapshot::capture(&prepared.freedom_path)?
                            .same_as(&prepared.freedom_before)
                            && FileSnapshot::capture(&prepared.credentials_path)?
                                .same_as(&prepared.credentials_before),
                        "Telegram account configuration changed after reviewed retirement; retry the command"
                    );
                    let opened_store =
                        if prepared.keychain_mode && injected_store.is_none() {
                            Some(crate::config::keychain::open_store().context(
                                "open OS keychain for Telegram account retirement commit",
                            )?)
                        } else {
                            None
                        };
                    let store = if prepared.keychain_mode {
                        injected_store.or(opened_store.as_deref())
                    } else {
                        None
                    };
                    if let Some(store) = store {
                        for (key, expected) in &prepared.dynamic_before {
                            anyhow::ensure!(
                                same_secret_snapshot(store.get(key)?.as_ref(), expected.as_ref()),
                                "Telegram account dynamic credential changed after reviewed retirement; retry the command"
                            );
                        }
                        store.delete(&crate::config::keychain::telegram_account_token_key(&prepared.account_id))
                            .context("delete selected dynamic Telegram token before PREPARED pair publication")?;
                    }
                    let published = publish_prepared_file_pair(
                        &prepared.freedom_path,
                        &prepared.credentials_path,
                        &freedom_dir,
                        &prepared.freedom_before,
                        &prepared.freedom_after,
                        &prepared.credentials_before,
                        &prepared.credentials_after,
                        (),
                        Some(|path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }),
                        fault,
                    );
                    if let Err(error) = published {
                        if prepared.keychain_mode && !dual_file_target_publication_crossed(&error) {
                            let store =
                                store.context("keychain account retirement has no secret store")?;
                            let key = crate::config::keychain::telegram_account_token_key(
                                &prepared.account_id,
                            );
                            match prepared.dynamic_before.get(&key).context("prepared dynamic Telegram token snapshot is missing")? {
                                Some(token) => store.set(&key, token), None => store.delete(&key),
                            }.context("restore selected dynamic Telegram token after recoverable pair failure")?;
                        }
                        return Err(error);
                    }
                    Ok(())
                })
            })
        })
    }

    /// Move a legacy singleton into exactly one named Telegram account.
    ///
    /// The OS store is necessarily external to the durable pair journal.  We
    /// therefore snapshot its dynamic account key before staging the exact
    /// file images, write the dynamic value before the journal can become
    /// visible, and restore that snapshot only while recovery is guaranteed
    /// to choose the old pair.  Once the target publication boundary has been
    /// crossed, recovery may commit the new pair, so the dynamic value must
    /// remain the new one.
    fn migrate_legacy_telegram_to_account_at_using_fault_and_store<H>(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
        injected_store: Option<&dyn crate::config::keychain::SecretStore>,
        fault: H,
    ) -> Result<()>
    where
        H: FnMut(DualFileFaultPoint) -> Result<()>,
    {
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a durable transaction"
        );

        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    // Do not use the effective loader here: migration precedence is
                    // intentionally the raw inline value, then credentials.yaml,
                    // then the matching legacy OS-store key.
                    let mut config =
                        crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)
                            .with_context(|| {
                                format!(
                                    "load {} for legacy Telegram account migration",
                                    freedom_path.display()
                                )
                            })?;
                    let mut credentials = Self::load_or_default_unlocked(credentials_path)
                        .with_context(|| {
                            format!(
                                "load {} for legacy Telegram account migration",
                                credentials_path.display()
                            )
                        })?;
                    let keychain_mode =
                        config.secrets_backend == crate::config::SecretsBackend::Keychain;
                    let opened_store =
                        if keychain_mode && injected_store.is_none() {
                            Some(crate::config::keychain::open_store().context(
                                "open OS keychain for legacy Telegram account migration",
                            )?)
                        } else {
                            None
                        };
                    // File mode must never touch an OS store, including when a
                    // test injects one to prove that boundary.
                    let store = if keychain_mode {
                        injected_store.or(opened_store.as_deref())
                    } else {
                        None
                    };
                    let dynamic_key =
                        crate::config::keychain::telegram_account_token_key(&account_id);
                    let committed_target = keychain_mode
                        && config.telegram_token.is_none()
                        && config.telegram_user_id.is_none()
                        && config.channel_accounts.telegram.len() == 1
                        && config
                            .channel_accounts
                            .telegram
                            .get(&account_id)
                            .is_some_and(|policy| policy.allowed_user_id != 0)
                        && credentials.telegram_token.is_none()
                        && credentials.channel_accounts.telegram.len() == 1
                        && credentials
                            .channel_accounts
                            .telegram
                            .get(&account_id)
                            .is_some_and(|account| account.token.is_none());
                    if !config.channel_accounts.telegram.is_empty()
                        || !credentials.channel_accounts.telegram.is_empty()
                    {
                        if committed_target {
                            // A prior call can fail only after the pair has
                            // committed but before the legacy singleton key is
                            // removed.  Do not rewrite the durable pair on a
                            // retry: its account map is already authoritative.
                            let store = store.expect("keychain committed target opens a store");
                            let dynamic_token = store.get(&dynamic_key).context(
                                "read committed Telegram account token before retrying legacy key cleanup",
                            )?;
                            anyhow::ensure!(
                                dynamic_token
                                    .as_ref()
                                    .is_some_and(|token| !token.expose().trim().is_empty()),
                                "refusing legacy Telegram key cleanup: committed account `{}` has no non-blank dynamic token",
                                account_id
                            );
                            store.delete("telegram_token").context(
                                "Telegram account migration already committed, but legacy key cleanup failed; rerun the same migration to retry cleanup without rewriting the committed pair",
                            )?;
                            return Ok(());
                        }
                        anyhow::bail!(
                            "Telegram account map or account credentials already configured"
                        );
                    }
                    let dynamic_before = store
                        .map(|store| store.get(&dynamic_key))
                        .transpose()?
                        .flatten();
                    let legacy_before = store
                        .map(|store| store.get("telegram_token"))
                        .transpose()?
                        .flatten();

                    let allowed_user_id = config
                        .telegram_user_id
                        .take()
                        .context("legacy telegram_user_id is missing")?;
                    anyhow::ensure!(allowed_user_id != 0, "legacy telegram_user_id is invalid");
                    let token = config
                        .telegram_token
                        .take()
                        .or_else(|| credentials.telegram_token.take())
                        .or(legacy_before.clone())
                        .context("legacy Telegram token is missing")?;
                    // A higher-precedence inline token still retires a lower
                    // legacy credentials.yaml singleton; account maps never
                    // fall back to either scalar form.
                    credentials.telegram_token = None;
                    config.channel_accounts.telegram.insert(
                        account_id.clone(),
                        crate::config::TelegramAccountConfig {
                            allowed_user_id,
                            incarnation: Some(crate::config::AccountIncarnation::new_random()),
                            ..Default::default()
                        },
                    );
                    credentials.channel_accounts.telegram.insert(
                        account_id,
                        TelegramAccountCredentials {
                            token: (!keychain_mode).then(|| token.clone()),
                        },
                    );

                    let freedom_body = render_freedom_preserving_unknown_yaml(
                        &config,
                        &freedom_before,
                        InlineTelegramTokenPolicy::Remove,
                    )?;
                    let freedom_after = FileSnapshot::Present(zeroize::Zeroizing::new(
                        freedom_body.as_bytes().to_vec(),
                    ));
                    let credentials_after = credentials.rendered_file_snapshot_preserving_unknown(
                        credentials_path,
                        &credentials_before,
                    )?;

                    if let Some(store) = store {
                        store.set(&dynamic_key, &token).context(
                            "write dynamic Telegram account token before PREPARED pair publication",
                        )?;
                    }
                    let publication = publish_prepared_file_pair(
                        freedom_path,
                        credentials_path,
                        &freedom_dir,
                        &freedom_before,
                        &freedom_after,
                        &credentials_before,
                        &credentials_after,
                        (),
                        Some(|path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }),
                        fault,
                    );
                    if let Err(error) = publication {
                        if let Some(store) = store
                            && !dual_file_target_publication_crossed(&error)
                        {
                            let restored = match dynamic_before {
                                Some(value) => store.set(&dynamic_key, &value),
                                None => store.delete(&dynamic_key),
                            };
                            if let Err(restore_error) = restored {
                                return Err(error.context(format!(
                                    "restore dynamic Telegram account token after recoverable pair failure: {restore_error:#}"
                                )));
                            }
                        }
                        return Err(error);
                    }
                    if let Some(store) = store {
                        store.delete("telegram_token").context(
                            "Telegram account migration already committed its config/credential pair, but legacy key cleanup failed; rerun the same migration to retry cleanup without rewriting the committed pair",
                        )?;
                    }
                    Ok(())
                })
            })
        })
    }
    /// Stage one explicit file-backed Slack account upsert. The returned
    /// candidate owns the exact source snapshots that commit must compare after
    /// an external read-only `auth.test` probe.
    pub(crate) fn prepare_slack_account_upsert_at(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
        allowed_user_id: String,
        bot_token: SecretString,
        app_token: SecretString,
    ) -> Result<PreparedSlackAccountUpsert> {
        Self::prepare_slack_account_write_at(
            freedom_path,
            credentials_path,
            account_id,
            Some(allowed_user_id),
            bot_token,
            app_token,
        )
    }

    /// Rotate credentials while selecting the existing policy under the same
    /// transaction lock and snapshots as the prepared candidate.
    pub(crate) fn prepare_slack_account_rotation_at(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
        bot_token: SecretString,
        app_token: SecretString,
    ) -> Result<PreparedSlackAccountUpsert> {
        Self::prepare_slack_account_write_at(
            freedom_path,
            credentials_path,
            account_id,
            None,
            bot_token,
            app_token,
        )
    }

    fn prepare_slack_account_write_at(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
        allowed_user_id: Option<String>,
        bot_token: SecretString,
        app_token: SecretString,
    ) -> Result<PreparedSlackAccountUpsert> {
        let allowed_user_id = allowed_user_id
            .map(|id| crate::channels::slack::normalize_allowed_user_id(&id))
            .transpose()
            .context("Slack account allowed_user_id is invalid")?;
        anyhow::ensure!(
            !bot_token.expose().trim().is_empty(),
            "Slack account bot token must be non-blank"
        );
        anyhow::ensure!(
            !app_token.expose().trim().is_empty(),
            "Slack account app token must be non-blank"
        );
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a durable transaction"
        );
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    let mut config =
                        crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)
                            .with_context(|| {
                                format!(
                                    "load {} for Slack account upsert preparation",
                                    freedom_path.display()
                                )
                            })?;
                    anyhow::ensure!(
                        config.secrets_backend != crate::config::SecretsBackend::Keychain,
                        "mapped Slack accounts require the file secrets backend until complete bot/app keychain custody exists"
                    );
                    let mut credentials = Self::load_or_default_unlocked(credentials_path)
                        .with_context(|| {
                            format!(
                                "load {} for Slack account upsert preparation",
                                credentials_path.display()
                            )
                        })?;
                    anyhow::ensure!(
                        credentials.slack_bot_token.is_none()
                            && credentials.slack_app_token.is_none()
                            && credentials.slack_allowed_user_id.is_none(),
                        "legacy Slack scalar fields cannot coexist with a Slack account upsert"
                    );
                    anyhow::ensure!(
                        config
                            .channel_accounts
                            .slack
                            .keys()
                            .eq(credentials.channel_accounts.slack.keys()),
                        "Slack account policy and raw credential keys must match exactly before upsert"
                    );
                    for (mapped_account, policy) in &config.channel_accounts.slack {
                        crate::channels::slack::normalize_allowed_user_id(&policy.allowed_user_id)
                            .with_context(|| format!("slack account `{mapped_account}` has an invalid allowed_user_id"))?;
                        let secrets = credentials
                            .channel_accounts
                            .slack
                            .get(mapped_account)
                            .expect("matched Slack account key");
                        anyhow::ensure!(
                            secrets
                                .bot_token
                                .as_ref()
                                .is_some_and(|token| !token.expose().trim().is_empty())
                                && secrets
                                    .app_token
                                    .as_ref()
                                    .is_some_and(|token| !token.expose().trim().is_empty()),
                            "slack account `{mapped_account}` has incomplete file credentials"
                        );
                    }
                    let allowed_user_id = match allowed_user_id {
                        Some(id) => id,
                        None => config
                            .channel_accounts
                            .slack
                            .get(&account_id)
                            .context(
                                "credential rotation requires an existing named Slack account",
                            )?
                            .allowed_user_id
                            .clone(),
                    };
                    let existing_team_id = config
                        .channel_accounts
                        .slack
                        .get(&account_id)
                        .and_then(|existing| existing.team_id.clone());
                    config.channel_accounts.slack.insert(
                        account_id.clone(),
                        crate::config::SlackAccountConfig {
                            allowed_user_id,
                            // The external `auth.test` result is not known
                            // until after this candidate has been probed.
                            // Commit replaces this provisional authority under
                            // the retained raw-pair CAS boundary.
                            team_id: existing_team_id,
                            incarnation: Some(crate::config::AccountIncarnation::new_random()),
                        },
                    );
                    credentials.channel_accounts.slack.insert(
                        account_id.clone(),
                        SlackAccountCredentials {
                            bot_token: Some(bot_token),
                            app_token: Some(app_token),
                        },
                    );
                    let candidate = crate::config::RuntimeConfigPair {
                        config: config.clone(),
                        raw_credentials: credentials.clone(),
                        credentials: credentials.clone(),
                    };
                    let accounts = candidate.authenticated_slack_accounts()?;
                    anyhow::ensure!(
                        accounts
                            .iter()
                            .any(|account| account.channel_ref().account_id == account_id),
                        "prepared Slack account is not authenticated"
                    );
                    let credentials_after = credentials.rendered_file_snapshot_preserving_unknown(
                        credentials_path,
                        &credentials_before,
                    )?;
                    Ok(PreparedSlackAccountUpsert {
                        freedom_path: freedom_path.to_path_buf(),
                        credentials_path: credentials_path.to_path_buf(),
                        account_id,
                        candidate,
                        freedom_before,
                        credentials_before,
                        credentials_after,
                    })
                })
            })
        })
    }

    /// Publish the exact reviewed Slack candidate, only while both original
    /// raw file snapshots still match.
    pub(crate) fn commit_prepared_slack_account_upsert_at(
        prepared: PreparedSlackAccountUpsert,
        verified_team_id: &str,
    ) -> Result<()> {
        let verified_team_id = crate::config::normalize_slack_team_id(verified_team_id)
            .context("verified Slack team_id is invalid")?;
        let freedom_dir = transaction_directory(&prepared.freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(&prepared.credentials_path),
            "prepared Slack account paths are not sibling files"
        );
        with_dual_file_transaction_lock(&prepared.freedom_path, || {
            with_config_writer_guard(&prepared.freedom_path, || {
                with_legacy_pair_locks(&prepared.freedom_path, &prepared.credentials_path, || {
                    anyhow::ensure!(
                        FileSnapshot::capture(&prepared.freedom_path)?
                            .same_as(&prepared.freedom_before)
                            && FileSnapshot::capture(&prepared.credentials_path)?
                                .same_as(&prepared.credentials_before),
                        "Slack account configuration changed after its reviewed candidate; retry the command"
                    );
                    let mut config = crate::config::FreedomConfig::load_public_from_path_unlocked(
                        &prepared.freedom_path,
                    )
                    .with_context(|| {
                        format!(
                            "load {} for reviewed Slack workspace binding",
                            prepared.freedom_path.display()
                        )
                    })?;
                    let candidate_policy = prepared
                        .candidate
                        .config
                        .channel_accounts
                        .slack
                        .get(&prepared.account_id)
                        .context("prepared Slack account policy is missing")?;
                    let prior = config.channel_accounts.slack.get(&prepared.account_id);
                    let prior_team_id = prior
                        .and_then(|policy| policy.team_id.as_deref())
                        .map(crate::config::normalize_slack_team_id)
                        .transpose()
                        .context("stored Slack team_id is invalid")?;
                    let incarnation = match prior_team_id.as_deref() {
                        Some(existing) if existing == verified_team_id.as_str() => prior
                            .and_then(|policy| policy.incarnation.clone())
                            .or_else(|| Some(crate::config::AccountIncarnation::new_random())),
                        _ => Some(crate::config::AccountIncarnation::new_random()),
                    };
                    config.channel_accounts.slack.insert(
                        prepared.account_id.clone(),
                        crate::config::SlackAccountConfig {
                            allowed_user_id: candidate_policy.allowed_user_id.clone(),
                            team_id: Some(verified_team_id),
                            incarnation,
                        },
                    );
                    let freedom_after = FileSnapshot::Present(zeroize::Zeroizing::new(
                        render_freedom_preserving_unknown_yaml(
                            &config,
                            &prepared.freedom_before,
                            InlineTelegramTokenPolicy::Preserve,
                        )?
                        .as_bytes()
                        .to_vec(),
                    ));
                    publish_prepared_file_pair(
                        &prepared.freedom_path,
                        &prepared.credentials_path,
                        &freedom_dir,
                        &prepared.freedom_before,
                        &freedom_after,
                        &prepared.credentials_before,
                        &prepared.credentials_after,
                        (),
                        Some(|path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }),
                        |_| Ok(()),
                    )
                })
            })
        })
    }

    /// Prepare retirement of one exact, complete file-backed Slack account.
    pub(crate) fn prepare_slack_account_removal_at(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
    ) -> Result<PreparedSlackAccountRemoval> {
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a durable transaction"
        );
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    let mut config =
                        crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)
                            .with_context(|| {
                                format!(
                                    "load {} for Slack account retirement",
                                    freedom_path.display()
                                )
                            })?;
                    anyhow::ensure!(
                        config.secrets_backend != crate::config::SecretsBackend::Keychain,
                        "mapped Slack accounts require the file secrets backend until complete bot/app keychain custody exists"
                    );
                    let mut credentials = Self::load_or_default_unlocked(credentials_path)
                        .with_context(|| {
                            format!(
                                "load {} for Slack account retirement",
                                credentials_path.display()
                            )
                        })?;
                    anyhow::ensure!(
                        credentials.slack_bot_token.is_none()
                            && credentials.slack_app_token.is_none()
                            && credentials.slack_allowed_user_id.is_none(),
                        "legacy Slack scalar fields cannot coexist with named account retirement"
                    );
                    anyhow::ensure!(
                        config
                            .channel_accounts
                            .slack
                            .keys()
                            .eq(credentials.channel_accounts.slack.keys()),
                        "Slack account policy and raw credential keys must match exactly before retirement"
                    );
                    let policy = config
                        .channel_accounts
                        .slack
                        .get(&account_id)
                        .context("selected Slack account is not configured")?;
                    crate::channels::slack::normalize_allowed_user_id(&policy.allowed_user_id)
                        .context("selected Slack account has an invalid allowed_user_id")?;
                    let selected = credentials
                        .channel_accounts
                        .slack
                        .get(&account_id)
                        .context("selected Slack account has no file credentials")?;
                    anyhow::ensure!(
                        selected
                            .bot_token
                            .as_ref()
                            .is_some_and(|token| !token.expose().trim().is_empty())
                            && selected
                                .app_token
                                .as_ref()
                                .is_some_and(|token| !token.expose().trim().is_empty()),
                        "selected Slack account has incomplete file credentials"
                    );
                    config.channel_accounts.slack.remove(&account_id);
                    credentials.channel_accounts.slack.remove(&account_id);
                    let freedom_after = FileSnapshot::Present(zeroize::Zeroizing::new(
                        render_freedom_preserving_unknown_yaml(
                            &config,
                            &freedom_before,
                            InlineTelegramTokenPolicy::Preserve,
                        )?
                        .as_bytes()
                        .to_vec(),
                    ));
                    let credentials_after = credentials.rendered_file_snapshot_preserving_unknown(
                        credentials_path,
                        &credentials_before,
                    )?;
                    Ok(PreparedSlackAccountRemoval {
                        freedom_path: freedom_path.to_path_buf(),
                        credentials_path: credentials_path.to_path_buf(),
                        account_id,
                        freedom_before,
                        credentials_before,
                        freedom_after,
                        credentials_after,
                    })
                })
            })
        })
    }

    pub(crate) fn commit_prepared_slack_account_removal_at(
        prepared: PreparedSlackAccountRemoval,
    ) -> Result<()> {
        let freedom_dir = transaction_directory(&prepared.freedom_path);
        with_dual_file_transaction_lock(&prepared.freedom_path, || {
            with_config_writer_guard(&prepared.freedom_path, || {
                with_legacy_pair_locks(&prepared.freedom_path, &prepared.credentials_path, || {
                    anyhow::ensure!(
                        FileSnapshot::capture(&prepared.freedom_path)?
                            .same_as(&prepared.freedom_before)
                            && FileSnapshot::capture(&prepared.credentials_path)?
                                .same_as(&prepared.credentials_before),
                        "Slack account configuration changed after reviewed retirement; retry the command"
                    );
                    publish_prepared_file_pair(
                        &prepared.freedom_path,
                        &prepared.credentials_path,
                        &freedom_dir,
                        &prepared.freedom_before,
                        &prepared.freedom_after,
                        &prepared.credentials_before,
                        &prepared.credentials_after,
                        (),
                        Some(|path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }),
                        |_| Ok(()),
                    )
                })
            })
        })
    }

    /// Atomically move the complete legacy Slack scalar triple into one named,
    /// file-backed account. Partial, mixed, invalid, or keychain-backed state
    /// is rejected while both source files remain untouched.
    pub(crate) fn migrate_legacy_slack_to_account_at(
        freedom_path: &Path,
        credentials_path: &Path,
        account_id: crate::channels::registry::ChannelAccountId,
    ) -> Result<()> {
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a durable transaction"
        );
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    let mut config =
                        crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)
                            .with_context(|| {
                                format!(
                                    "load {} for legacy Slack account migration",
                                    freedom_path.display()
                                )
                            })?;
                    anyhow::ensure!(
                        config.secrets_backend != crate::config::SecretsBackend::Keychain,
                        "mapped Slack accounts require the file secrets backend until complete bot/app keychain custody exists"
                    );
                    let mut credentials = Self::load_or_default_unlocked(credentials_path)
                        .with_context(|| {
                            format!(
                                "load {} for legacy Slack account migration",
                                credentials_path.display()
                            )
                        })?;
                    anyhow::ensure!(
                        config.channel_accounts.slack.is_empty()
                            && credentials.channel_accounts.slack.is_empty(),
                        "Slack account map or account credentials already configured"
                    );
                    let bot_token = credentials
                        .slack_bot_token
                        .take()
                        .context("legacy Slack bot token is missing")?;
                    let app_token = credentials
                        .slack_app_token
                        .take()
                        .context("legacy Slack app token is missing")?;
                    anyhow::ensure!(
                        !bot_token.expose().trim().is_empty()
                            && !app_token.expose().trim().is_empty(),
                        "legacy Slack tokens must be non-blank"
                    );
                    let allowed_user_id = credentials
                        .slack_allowed_user_id
                        .take()
                        .context("legacy Slack allowed_user_id is missing")?;
                    let allowed_user_id =
                        crate::channels::slack::normalize_allowed_user_id(&allowed_user_id)
                            .context("legacy Slack allowed_user_id is invalid")?;
                    config.channel_accounts.slack.insert(
                        account_id.clone(),
                        crate::config::SlackAccountConfig {
                            allowed_user_id,
                            team_id: None,
                            incarnation: Some(crate::config::AccountIncarnation::new_random()),
                        },
                    );
                    credentials.channel_accounts.slack.insert(
                        account_id,
                        SlackAccountCredentials {
                            bot_token: Some(bot_token),
                            app_token: Some(app_token),
                        },
                    );
                    let freedom_after = FileSnapshot::Present(zeroize::Zeroizing::new(
                        render_freedom_preserving_unknown_yaml(
                            &config,
                            &freedom_before,
                            InlineTelegramTokenPolicy::Preserve,
                        )?
                        .as_bytes()
                        .to_vec(),
                    ));
                    let credentials_after = credentials.rendered_file_snapshot_preserving_unknown(
                        credentials_path,
                        &credentials_before,
                    )?;
                    publish_prepared_file_pair(
                        freedom_path,
                        credentials_path,
                        &freedom_dir,
                        &freedom_before,
                        &freedom_after,
                        &credentials_before,
                        &credentials_after,
                        (),
                        Some(|path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }),
                        |_| Ok(()),
                    )
                })
            })
        })
    }

    /// Secure default for existing credentials files that predate the field.
    pub fn matrix_requires_encryption(&self) -> bool {
        self.matrix_require_encryption.unwrap_or(true)
    }

    /// Read from `path`. Missing file returns `Credentials::default()`
    /// (a clean install has no secrets yet). Bad YAML is a hard error —
    /// silent fallback would mask a typo that disables an operator's
    /// configured provider.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        with_dual_file_transaction_lock(path, || Self::load_or_default_unlocked(path))
    }

    /// Strict credential load for callers that already hold the dual-file
    /// transaction boundary. Keeping this private to config code prevents a
    /// runtime caller from observing a PREPARED mixed state.
    pub(super) fn load_or_default_unlocked(path: &Path) -> Result<Self> {
        // B17 TOCTOU fix: single syscall, no TOCTOU window between exists() and
        // read(). Only ErrorKind::NotFound returns the default empty store; every
        // other error (permissions, I/O, keychain, corrupt YAML) propagates with
        // full path context so the caller can fail-closed.
        let raw = zeroize::Zeroizing::new(match std::fs::read(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(e).with_context(|| format!("read credentials at {}", path.display()));
            }
        });
        // CRYPTO-04 #5 — decrypt when at-rest-encrypted; else legacy plaintext.
        // The transient plaintext buffer is zeroized on every return path.
        let body = decode_credentials_yaml(path, &raw)?;
        let c: Self = serde_yaml::from_str(&body)
            .with_context(|| format!("parse credentials YAML at {}", path.display()))?;
        Ok(c)
    }

    /// Load the effective credential set for the configured secrets backend.
    /// File values win; a keychain backend only fills fields that remain empty.
    /// Failure to open the store preserves the documented emergency-file
    /// fallback. A malformed compound SSH authority fails closed when no file
    /// override exists; scalar lookup failures keep their per-field fallback.
    pub fn load_effective(path: &Path, backend: crate::config::SecretsBackend) -> Result<Self> {
        with_dual_file_transaction_lock(path, || Self::load_effective_unlocked(path, backend))
    }

    pub(super) fn load_effective_unlocked(
        path: &Path,
        backend: crate::config::SecretsBackend,
    ) -> Result<Self> {
        let credentials = Self::load_or_default_unlocked(path)?;
        Self::supplement_effective_unlocked(credentials, backend)
    }

    pub(super) fn supplement_effective_unlocked(
        mut credentials: Self,
        backend: crate::config::SecretsBackend,
    ) -> Result<Self> {
        if backend == crate::config::SecretsBackend::Keychain {
            anyhow::ensure!(
                credentials.n8n_api_key.is_none(),
                "adopted n8n API key must reside in the configured keychain backend"
            );
            match crate::config::keychain::open_store() {
                Ok(store) => {
                    crate::config::keychain::supplement_from_store(
                        &mut credentials,
                        store.as_ref(),
                    )
                    .context("supplement credentials from OS keychain")?;
                    crate::config::keychain::supplement_telegram_account_tokens(
                        &mut credentials,
                        store.as_ref(),
                    )
                    .context("supplement Telegram account credentials from OS keychain")?;
                }
                Err(error) => tracing::warn!(
                    %error,
                    "could not open OS keychain; using credentials.yaml emergency values"
                ),
            }
        }
        Ok(credentials)
    }

    /// Convenience: read from the default `~/.neoth/credentials.yaml`.
    pub fn load() -> Result<Self> {
        Self::load_or_default(&default_path())
    }

    /// Write atomically mode 0600 (Unix) or process-token-private (Windows).
    /// Skips entirely when both fields are `None` so a credentials-free
    /// install doesn't leave an empty placeholder file behind.
    pub fn write(&self, path: &Path) -> Result<()> {
        with_dual_file_transaction_lock(path, || {
            with_config_writer_guard(path, || {
                let _mutex = lock_cred();
                let _file_lock = lock_cred_file(path)
                    .with_context(|| format!("acquire credentials lock for {}", path.display()))?;
                self.write_unlocked(path)
            })
        })
    }

    fn write_unlocked(&self, path: &Path) -> Result<()> {
        let before = FileSnapshot::capture(path).map_err(|error| {
            if self.is_empty() {
                error.context(format!("remove empty credential store {}", path.display()))
            } else {
                error
            }
        })?;
        self.rendered_file_snapshot_preserving_unknown(path, &before)?
            .restore(path)
    }

    /// Render the exact bytes that a later atomic publication must install.
    /// The transaction journal and the actual rename use this same snapshot,
    /// including the one-time AEAD nonce, so recovery can distinguish an exact
    /// committed image from an unexpected/tampered file.
    fn rendered_file_snapshot(&self, path: &Path) -> Result<FileSnapshot> {
        if self.is_empty() {
            return Ok(FileSnapshot::Missing);
        }
        // YAML round-trip is intentional (we DO want the plaintext in
        // the file on disk — that's the whole point of credentials.yaml).
        // What's at risk is the in-memory `String` until we return:
        // it's a plain `String`, not a `SecretString`, so it isn't
        // zeroized automatically. Wipe it before drop so a memory
        // disclosure bug elsewhere can't pull recently-written secrets
        // off the heap.
        let body =
            zeroize::Zeroizing::new(serde_yaml::to_string(self).context("serialise credentials")?);
        encode_credentials_yaml(path, &body)
    }

    /// Render an RMW target without deleting fields introduced by a newer
    /// NEOTH version. Known fields come from the typed mutation; unknown YAML
    /// values remain byte-secret but structurally intact. Encrypted sources are
    /// decrypted only in zeroizing memory and re-encrypted with the active
    /// config subkey before the PREPARED journal is written.
    fn rendered_file_snapshot_preserving_unknown(
        &self,
        path: &Path,
        before: &FileSnapshot,
    ) -> Result<FileSnapshot> {
        let FileSnapshot::Present(raw) = before else {
            return self.rendered_file_snapshot(path);
        };
        let original_body = decode_credentials_yaml(path, raw)?;
        let mut merged = SensitiveYamlValue(
            serde_yaml::from_str(&original_body)
                .with_context(|| format!("parse credentials YAML at {}", path.display()))?,
        );
        // `pears_bearer_token` is a read-only legacy alias for the canonical
        // `keet_bridge_bearer_token` field. Keeping both keys after the known
        // field overlay would make Serde reject the target as a duplicate
        // field and strand upgraded installations on every later RMW.
        if let serde_yaml::Value::Mapping(existing) = &mut merged.0 {
            let legacy_key = serde_yaml::Value::String("pears_bearer_token".to_string());
            if let Some(mut legacy_value) = existing.remove(&legacy_key) {
                zeroize_yaml_value(&mut legacy_value);
            }
        }
        let schema = serde_yaml::to_value(Self::default())
            .context("serialize credential schema for lossless update")?;
        let has_unknown = match (&merged.0, &schema) {
            (serde_yaml::Value::Mapping(existing), serde_yaml::Value::Mapping(known)) => {
                existing.keys().any(|key| !known.contains_key(key))
            }
            _ => false,
        };
        if self.is_empty() && !has_unknown {
            return Ok(FileSnapshot::Missing);
        }

        let known = serde_yaml::to_value(self)
            .context("serialize known credentials for lossless update")?;
        remove_retired_channel_account_yaml(
            &mut merged.0,
            "telegram",
            &self.channel_accounts.telegram,
        );
        remove_retired_channel_account_yaml(&mut merged.0, "slack", &self.channel_accounts.slack);
        overlay_known_yaml(&mut merged.0, known);
        let body = zeroize::Zeroizing::new(
            serde_yaml::to_string(&merged.0)
                .context("serialize credentials while preserving unknown fields")?,
        );
        let _: Self = serde_yaml::from_str(&body)
            .context("validate merged credentials after lossless update")?;
        encode_credentials_yaml(path, &body)
    }

    /// Sorted names of every explicitly configured credential field. The
    /// temporary serde tree is recursively zeroized on every return path so
    /// compound SSH passwords/passphrases never linger in ordinary heap
    /// strings after a names-only inspection.
    pub(crate) fn configured_field_names(&self) -> Result<Vec<String>> {
        let value = SensitiveYamlValue(
            serde_yaml::to_value(self).context("inspect configured credential field names")?,
        );
        let mut names = Vec::new();
        if let Some(mapping) = value.0.as_mapping() {
            for (key, value) in mapping {
                if !value.is_null()
                    && let Some(name) = key.as_str()
                {
                    names.push(name.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    /// Return requested migration fields that are not durably represented in
    /// this typed image. Scalar secrets must be non-empty strings; the
    /// compound `ssh_tunnels` field is present whenever it is non-null,
    /// including the authoritative `Some([])` disabled state.
    pub(crate) fn missing_migration_fields(&self, fields: &[String]) -> Result<Vec<String>> {
        let value = SensitiveYamlValue(
            serde_yaml::to_value(self).context("verify persisted credential migration fields")?,
        );
        let mapping = value
            .0
            .as_mapping()
            .context("credentials serialized to a non-mapping during migration verification")?;
        Ok(fields
            .iter()
            .filter(|field| {
                let key = serde_yaml::Value::String((*field).clone());
                match mapping.get(&key) {
                    Some(value) if field.as_str() == "ssh_tunnels" => value.is_null(),
                    Some(value) => value.as_str().is_none_or(str::is_empty),
                    None => true,
                }
            })
            .cloned()
            .collect())
    }

    /// Overlay every non-null field from `incoming` onto this credential set.
    /// Both serde trees and the intermediate YAML are zeroizing; replaced
    /// values are wiped immediately. The returned names contain field names
    /// only, never values.
    pub(crate) fn merge_present_fields(&self, incoming: &Self) -> Result<(Self, Vec<String>)> {
        let mut base = SensitiveYamlValue(
            serde_yaml::to_value(self).context("serialize existing credentials for merge")?,
        );
        let mut overlay = SensitiveYamlValue(
            serde_yaml::to_value(incoming).context("serialize incoming credentials for merge")?,
        );
        let base_mapping = base
            .0
            .as_mapping_mut()
            .context("existing credentials serialized to a non-mapping")?;
        let overlay_mapping = overlay
            .0
            .as_mapping_mut()
            .context("incoming credentials serialized to a non-mapping")?;
        let mut imported = Vec::new();
        for (key, value) in std::mem::take(overlay_mapping) {
            if value.is_null() {
                let _discarded = SensitiveYamlValue(value);
                continue;
            }
            if let Some(name) = key.as_str() {
                imported.push(name.to_string());
            }
            if let Some(previous) = base_mapping.insert(key, value) {
                let _replaced = SensitiveYamlValue(previous);
            }
        }
        let merged_yaml = zeroize::Zeroizing::new(
            serde_yaml::to_string(&base.0)
                .context("serialize merged credentials from zeroizing tree")?,
        );
        let merged = serde_yaml::from_str(&merged_yaml).context("rebuild merged credentials")?;
        imported.sort();
        Ok((merged, imported))
    }

    /// Read-only view used by `credential migrate --dry-run`. It overlays a
    /// historical public SSH bundle into the returned typed credentials but
    /// never publishes either file.
    pub(crate) fn load_with_legacy_ssh_preview_at(
        freedom_path: &Path,
        credentials_path: &Path,
        store: &dyn super::keychain::SecretStore,
    ) -> Result<(Self, bool, super::SecretsBackend)> {
        anyhow::ensure!(
            transaction_directory(freedom_path) == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a coherent migration preview"
        );
        with_coherent_pair_transaction_lock(freedom_path, || {
            let mut credentials = Self::load_or_default_unlocked(credentials_path)?;
            let Some((candidate, legacy_present)) =
                Self::preview_runtime_config_with_legacy_ssh_unlocked(
                    freedom_path,
                    &mut credentials,
                    Some(store),
                )?
            else {
                return Ok((credentials, false, super::SecretsBackend::File));
            };
            Ok((credentials, legacy_present, candidate.secrets_backend))
        })
    }

    /// Parse a runtime config and overlay the historical public SSH authority
    /// without mutating either file. Dedicated file/keychain authorities win,
    /// including `Some([])`; malformed legacy content is parsed only when it
    /// would be the effective authority.
    pub(super) fn preview_runtime_config_with_legacy_ssh_unlocked(
        freedom_path: &Path,
        credentials: &mut Self,
        store: Option<&dyn super::keychain::SecretStore>,
    ) -> Result<Option<(super::FreedomConfig, bool)>> {
        let freedom_source = zeroize::Zeroizing::new(match std::fs::read(freedom_path) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", freedom_path.display()));
            }
        });
        let mut public =
            SensitiveYamlValue(serde_yaml::from_slice(&freedom_source).with_context(|| {
                format!(
                    "parse {} for legacy SSH migration preview",
                    freedom_path.display()
                )
            })?);
        let root = public.0.as_mapping_mut().with_context(|| {
            format!(
                "{} must contain a YAML mapping for legacy SSH migration preview",
                freedom_path.display()
            )
        })?;
        let key = serde_yaml::Value::String("ssh_tunnels".to_string());
        let legacy_value = root.remove(&key).map(SensitiveYamlValue);
        let legacy_present = legacy_value.is_some();

        // Match the real migration's validation without writing anything.
        let public_body = zeroize::Zeroizing::new(
            serde_yaml::to_string(&public.0)
                .context("serialize freedom.yaml legacy SSH preview target")?,
        );
        let candidate: super::FreedomConfig = serde_yaml::from_str(&public_body)
            .context("validate freedom.yaml legacy SSH preview target")?;
        let _ = candidate.public_yaml()?;

        if legacy_present
            && credentials.ssh_tunnels.is_none()
            && candidate.secrets_backend == super::SecretsBackend::Keychain
            && let Some(store) = store
        {
            let mut effective = credentials.clone();
            super::keychain::supplement_from_store(&mut effective, store)
                .context("resolve dedicated keychain SSH authority for migration preview")?;
            if effective.ssh_tunnels.is_some() {
                credentials.ssh_tunnels = effective.ssh_tunnels;
            }
        }
        if credentials.ssh_tunnels.is_none()
            && let Some(legacy_value) = legacy_value.as_ref()
        {
            let legacy_yaml = zeroize::Zeroizing::new(
                serde_yaml::to_string(&legacy_value.0)
                    .context("serialize legacy freedom.yaml::ssh_tunnels preview")?,
            );
            credentials.ssh_tunnels = Some(
                serde_yaml::from_str(&legacy_yaml)
                    .context("parse legacy freedom.yaml::ssh_tunnels preview")?,
            );
        }
        Ok(Some((candidate, legacy_present)))
    }

    /// Remove the historical root `ssh_tunnels` key from a public config image
    /// while preserving every other YAML value. The removed subtree and parse
    /// tree are recursively zeroized.
    pub(crate) fn public_freedom_without_legacy_ssh(source: &str) -> Result<String> {
        let mut public = SensitiveYamlValue(
            serde_yaml::from_str(source)
                .context("parse freedom.yaml before removing legacy SSH")?,
        );
        let root = public
            .0
            .as_mapping_mut()
            .context("freedom.yaml must contain a YAML mapping before removing legacy SSH")?;
        let key = serde_yaml::Value::String("ssh_tunnels".to_string());
        let Some(legacy) = root.remove(&key) else {
            return Ok(source.to_string());
        };
        let _legacy = SensitiveYamlValue(legacy);
        let body = zeroize::Zeroizing::new(
            serde_yaml::to_string(&public.0)
                .context("serialize freedom.yaml without legacy SSH authority")?,
        );
        let candidate: super::FreedomConfig = serde_yaml::from_str(&body)
            .context("validate freedom.yaml without legacy SSH authority")?;
        let rendered = zeroize::Zeroizing::new(candidate.public_yaml()?);
        let rendered_value: serde_yaml::Value = serde_yaml::from_str(&rendered)
            .context("parse public FreedomConfig SSH-boundary validation image")?;
        let rendered_root = rendered_value
            .as_mapping()
            .context("public FreedomConfig SSH-boundary validation image must be a mapping")?;
        anyhow::ensure!(
            !rendered_root.contains_key(&key),
            "public FreedomConfig rendering retained private SSH tunnel authority"
        );
        Ok(body.as_str().to_string())
    }

    /// True when there are no secrets to persist.
    ///
    /// Destructured intentionally so adding a new field to `Credentials`
    /// without updating this method is a compile error rather than a
    /// silent wrong answer.
    pub fn is_empty(&self) -> bool {
        let Self {
            n8n_api_key,
            provider_key,
            elevenlabs_tts_api_key,
            azure_tts_api_key,
            telegram_token,
            channel_accounts,
            omi_developer_api_key,
            omi_ingest_token,
            inference_left_key,
            inference_right_key,
            inference_cerebellum_key,
            inference_default_slot_key,
            whatsapp_token,
            whatsapp_phone_id,
            whatsapp_verify_token,
            whatsapp_app_secret,
            whatsapp_allowed_sender,
            whatsapp_baileys_url,
            whatsapp_baileys_token,
            whatsapp_baileys_allowed_senders,
            whatsapp_baileys_allowed_groups,
            slack_bot_token,
            slack_app_token,
            slack_allowed_user_id,
            discord_bot_token,
            discord_allowed_user_id,
            signal_cli_url,
            signal_phone_number,
            signal_allowed_sender,
            matrix_homeserver,
            matrix_user_id,
            matrix_password,
            matrix_access_token,
            matrix_store_path,
            matrix_allowed_user_id,
            matrix_allowed_room_ids,
            matrix_require_encryption,
            line_channel_access_token,
            line_channel_secret,
            line_webhook_port,
            line_allowed_sender,
            irc_server,
            irc_port,
            irc_nick,
            irc_password,
            irc_channels,
            irc_tls,
            irc_allowed_nick,
            irc_allowed_account,
            mattermost_url,
            mattermost_token,
            mattermost_allowed_user_id,
            twitch_username,
            twitch_oauth_token,
            twitch_channels,
            nostr_secret_key,
            nostr_relays,
            nostr_allowed_pubkey,
            bluebubbles_url,
            bluebubbles_password,
            bluebubbles_chat_guid,
            imessage_allowed_sender,
            gchat_service_account_json,
            gchat_subscription,
            gchat_allowed_sender,
            keet_bridge_url,
            keet_topic,
            keet_allowed_senders,
            keet_seed_phrase,
            keet_bridge_bearer_token,
            todoist_token,
            google_oauth_client_id,
            google_oauth_client_secret,
            google_oauth_refresh_token,
            caldav_url,
            caldav_username,
            caldav_password,
            ms_todo_tenant_id,
            ms_todo_client_id,
            ms_todo_client_secret,
            ms_todo_refresh_token,
            cluster_passphrase,
            tududi_api_token,
            ssh_tunnels,
            paperless_url,
            paperless_token,
        } = self;
        n8n_api_key.is_none()
            && provider_key.is_none()
            && elevenlabs_tts_api_key.is_none()
            && azure_tts_api_key.is_none()
            && telegram_token.is_none()
            && channel_accounts.telegram.is_empty()
            && channel_accounts.slack.is_empty()
            && omi_developer_api_key.is_none()
            && omi_ingest_token.is_none()
            && inference_left_key.is_none()
            && inference_right_key.is_none()
            && inference_cerebellum_key.is_none()
            && inference_default_slot_key.is_none()
            && whatsapp_token.is_none()
            && whatsapp_phone_id.is_none()
            && whatsapp_verify_token.is_none()
            && whatsapp_app_secret.is_none()
            && whatsapp_allowed_sender.is_none()
            && whatsapp_baileys_url.is_none()
            && whatsapp_baileys_token.is_none()
            && whatsapp_baileys_allowed_senders.is_none()
            && whatsapp_baileys_allowed_groups.is_none()
            && slack_bot_token.is_none()
            && slack_app_token.is_none()
            && slack_allowed_user_id.is_none()
            && discord_bot_token.is_none()
            && discord_allowed_user_id.is_none()
            && signal_cli_url.is_none()
            && signal_phone_number.is_none()
            && signal_allowed_sender.is_none()
            && matrix_homeserver.is_none()
            && matrix_user_id.is_none()
            && matrix_password.is_none()
            && matrix_access_token.is_none()
            && matrix_store_path.is_none()
            && matrix_allowed_user_id.is_none()
            && matrix_allowed_room_ids.is_none()
            && matrix_require_encryption.is_none()
            && line_channel_access_token.is_none()
            && line_channel_secret.is_none()
            && line_webhook_port.is_none()
            && line_allowed_sender.is_none()
            && irc_server.is_none()
            && irc_port.is_none()
            && irc_nick.is_none()
            && irc_password.is_none()
            && irc_channels.is_none()
            && irc_tls.is_none()
            && irc_allowed_nick.is_none()
            && irc_allowed_account.is_none()
            && mattermost_url.is_none()
            && mattermost_token.is_none()
            && mattermost_allowed_user_id.is_none()
            && twitch_username.is_none()
            && twitch_oauth_token.is_none()
            && twitch_channels.is_none()
            && nostr_secret_key.is_none()
            && nostr_relays.is_none()
            && nostr_allowed_pubkey.is_none()
            && bluebubbles_url.is_none()
            && bluebubbles_password.is_none()
            && bluebubbles_chat_guid.is_none()
            && imessage_allowed_sender.is_none()
            && gchat_service_account_json.is_none()
            && gchat_subscription.is_none()
            && gchat_allowed_sender.is_none()
            && keet_bridge_url.is_none()
            && keet_topic.is_none()
            && keet_allowed_senders.is_none()
            && keet_seed_phrase.is_none()
            && keet_bridge_bearer_token.is_none()
            && todoist_token.is_none()
            && google_oauth_client_id.is_none()
            && google_oauth_client_secret.is_none()
            && google_oauth_refresh_token.is_none()
            && caldav_url.is_none()
            && caldav_username.is_none()
            && caldav_password.is_none()
            && ms_todo_tenant_id.is_none()
            && ms_todo_client_id.is_none()
            && ms_todo_client_secret.is_none()
            && ms_todo_refresh_token.is_none()
            && cluster_passphrase.is_none()
            && tududi_api_token.is_none()
            && ssh_tunnels.is_none()
            && paperless_url.is_none()
            && paperless_token.is_none()
    }

    /// True if either field is set. Mirror of `!is_empty()` for call-site
    /// readability.
    pub fn has_any(&self) -> bool {
        !self.is_empty()
    }

    /// B17 — single-read classifier that does NOT silently fall back to a
    /// default. Callers that previously used `load_or_default(..).unwrap_or_default()`
    /// switch to this + a conditional load so they can distinguish a bad file
    /// from a genuinely missing one.
    pub fn credential_store_status(path: &Path) -> CredentialStoreStatus {
        with_dual_file_transaction_lock(path, || Ok(Self::credential_store_status_unlocked(path)))
            .unwrap_or(CredentialStoreStatus::Unreadable)
    }

    pub(super) fn credential_store_status_unlocked(path: &Path) -> CredentialStoreStatus {
        let raw = match std::fs::read(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return CredentialStoreStatus::Missing;
            }
            Err(_) => return CredentialStoreStatus::Unreadable,
        };
        if raw.starts_with(CONF_MAGIC) {
            let home = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let Some(key) = crate::wal::master_key::config_subkey_at(home) else {
                return CredentialStoreStatus::KeyUnavailable;
            };
            if decrypt_credentials_body(&key, &raw).is_err() {
                return CredentialStoreStatus::Invalid;
            }
        } else {
            // Plaintext path — validate UTF-8 then YAML.
            let Ok(body) = std::str::from_utf8(&raw) else {
                return CredentialStoreStatus::Invalid;
            };
            if serde_yaml::from_str::<Self>(body).is_err() {
                return CredentialStoreStatus::Invalid;
            }
        }
        CredentialStoreStatus::Ok
    }

    /// B17 — cross-process-safe read-modify-write on `credentials.yaml`.
    ///
    /// Acquires the shared recovery boundary first, then the intra-process
    /// `CRED_LOCK` and OS advisory lock on `<path>.lock`, reloads strictly
    /// under those locks, calls `mutation`, and atomically writes the result.
    /// Returns the mutation's return value.
    ///
    /// STOP invariants:
    /// - If `load_or_default` returns `Err`, returns immediately WITHOUT
    ///   calling the mutation or writing — the bad file bytes are preserved
    ///   intact for operator recovery.
    /// - If the mutation returns `Err`, writes nothing.
    /// - Never auto-repairs, truncates, or re-encrypts a corrupt file.
    pub fn update_at<F, R>(path: &Path, mutation: F) -> Result<R>
    where
        F: FnOnce(&mut Self) -> Result<R>,
    {
        with_dual_file_transaction_lock(path, || {
            with_config_writer_guard(path, || {
                let _mutex = lock_cred();
                let _file_lock = lock_cred_file(path)
                    .with_context(|| format!("acquire credentials lock for {}", path.display()))?;
                // Load strictly under both locks. Only NotFound returns Ok(default);
                // any other error propagates — NEVER writes into a failed-load.
                let before = FileSnapshot::capture(path)?;
                let mut creds = Self::load_or_default_unlocked(path).with_context(|| {
                    format!("load credentials at {} for update", path.display())
                })?;
                let result = mutation(&mut creds)?;
                creds
                    .rendered_file_snapshot_preserving_unknown(path, &before)?
                    .restore(path)
                    .with_context(|| {
                        format!("write credentials at {} after update", path.display())
                    })?;
                Ok(result)
            })
        })
    }

    /// Cross-process-safe two-file mutation for configuration that spans
    /// `freedom.yaml` and `credentials.yaml` (for example Telegram's public
    /// sender allowlist plus its secret bot token).
    ///
    /// Both files are loaded strictly while their canonical process + OS locks
    /// are held. Before either rename, a private durable PREPARED journal binds
    /// the exact before/after bytes. Every later runtime load recovers that
    /// journal first, so a process or machine crash can never activate a mixed
    /// public-policy/secret pair.
    #[cfg(any(feature = "cluster", test))]
    pub(crate) fn update_with_freedom_at<F, R>(
        freedom_path: &Path,
        credentials_path: &Path,
        mutation: F,
    ) -> Result<R>
    where
        F: FnOnce(&mut super::FreedomConfig, &mut Self) -> Result<R>,
    {
        Self::update_with_freedom_at_using(
            freedom_path,
            credentials_path,
            mutation,
            Some(|path: &Path, body: &[u8]| {
                crate::util::atomic_write::atomic_write_private(path, body)
                    .with_context(|| format!("atomically write {}", path.display()))
            }),
            InlineTelegramTokenPolicy::Preserve,
            None,
        )
    }

    /// Reviewed dual-file mutation bound to the exact freedom.yaml generation
    /// previously snapshotted for audit/rollback. Credentials are still
    /// reloaded under the commit locks; any intervening public config edit is
    /// a loud retry instead of being overwritten by stale approved intent.
    pub(crate) fn update_with_freedom_at_if_source<F, R>(
        freedom_path: &Path,
        credentials_path: &Path,
        expected_freedom_source: &[u8],
        mutation: F,
    ) -> Result<R>
    where
        F: FnOnce(&mut super::FreedomConfig, &mut Self) -> Result<R>,
    {
        Self::update_with_freedom_at_using(
            freedom_path,
            credentials_path,
            mutation,
            Some(|path: &Path, body: &[u8]| {
                crate::util::atomic_write::atomic_write_private(path, body)
                    .with_context(|| format!("atomically write {}", path.display()))
            }),
            InlineTelegramTokenPolicy::Preserve,
            Some(expected_freedom_source),
        )
    }

    /// Telegram-specific dual-file mutation. Unlike the generic primitive,
    /// this deliberately removes a legacy inline Telegram token after the
    /// replacement token is durably staged in credentials.yaml.
    pub(crate) fn update_telegram_with_freedom_at<F, R>(
        freedom_path: &Path,
        credentials_path: &Path,
        mutation: F,
    ) -> Result<R>
    where
        F: FnOnce(&mut super::FreedomConfig, &mut Self) -> Result<R>,
    {
        Self::update_with_freedom_at_using(
            freedom_path,
            credentials_path,
            mutation,
            Some(|path: &Path, body: &[u8]| {
                crate::util::atomic_write::atomic_write_private(path, body)
                    .with_context(|| format!("atomically write {}", path.display()))
            }),
            InlineTelegramTokenPolicy::Remove,
            None,
        )
    }

    /// Lossless raw-freedom counterpart for first-run/reconfigure workflows
    /// whose public schema is broader than [`super::FreedomConfig`]. The
    /// closure sees the exact optional UTF-8 source and the typed file-backed
    /// credentials, then returns an optional complete freedom target. `None`
    /// target preserves the current freedom bytes while still allowing a
    /// credential-only mutation. Both targets use the same PREPARED journal.
    pub(crate) fn update_raw_freedom_with_credentials_at<F, R>(
        freedom_path: &Path,
        credentials_path: &Path,
        mutation: F,
    ) -> Result<R>
    where
        F: FnOnce(Option<&str>, &mut Self) -> Result<(Option<String>, R)>,
    {
        Self::update_raw_freedom_with_credentials_at_using_fault(
            freedom_path,
            credentials_path,
            mutation,
            |_| Ok(()),
        )
    }

    #[cfg(test)]
    pub(crate) fn test_update_raw_freedom_with_credentials_at_using_fault<F, R>(
        freedom_path: &Path,
        credentials_path: &Path,
        mutation: F,
        injected: DualFileTestFaultPoint,
    ) -> Result<R>
    where
        F: FnOnce(Option<&str>, &mut Self) -> Result<(Option<String>, R)>,
    {
        Self::update_raw_freedom_with_credentials_at_using_fault(
            freedom_path,
            credentials_path,
            mutation,
            |actual| {
                let matches = matches!(
                    (injected, actual),
                    (
                        DualFileTestFaultPoint::JournalPrepared,
                        DualFileFaultPoint::JournalPrepared
                    ) | (
                        DualFileTestFaultPoint::FreedomPublished,
                        DualFileFaultPoint::FreedomPublished
                    ) | (
                        DualFileTestFaultPoint::DirectorySynced,
                        DualFileFaultPoint::DirectorySynced
                    )
                );
                anyhow::ensure!(!matches, "injected dual-file fault at {actual:?}");
                Ok(())
            },
        )
    }

    /// One-time, zero-interaction migration for the historical
    /// `freedom.yaml::ssh_tunnels` shape.
    ///
    /// The complete tunnel bundle is security-bearing because endpoint and
    /// jump-host auth may contain passwords/private-key passphrases. It is
    /// therefore moved into the private credential store and removed from the
    /// public file as one PREPARED-journal transaction. A dedicated
    /// `credentials.yaml::ssh_tunnels` value always wins, including `Some([])`;
    /// the legacy block is still removed so it cannot later resurrect.
    ///
    /// Any parse/render/publication failure leaves the original coherent pair
    /// (or its recoverable journal) intact.
    pub(super) fn migrate_legacy_ssh_tunnels_at(
        freedom_path: &Path,
        credentials_path: &Path,
    ) -> Result<()> {
        Self::migrate_legacy_ssh_tunnels_at_using_fault(
            freedom_path,
            credentials_path,
            |_| Ok(()),
        )?;
        Ok(())
    }

    fn migrate_legacy_ssh_tunnels_at_using_fault<H>(
        freedom_path: &Path,
        credentials_path: &Path,
        fault: H,
    ) -> Result<LegacySshMigrationOutcome>
    where
        H: FnMut(DualFileFaultPoint) -> Result<()>,
    {
        Self::migrate_legacy_ssh_tunnels_at_using_fault_and_store(
            freedom_path,
            credentials_path,
            None,
            fault,
        )
    }

    fn migrate_legacy_ssh_tunnels_at_using_fault_and_store<H>(
        freedom_path: &Path,
        credentials_path: &Path,
        injected_store: Option<&dyn super::keychain::SecretStore>,
        fault: H,
    ) -> Result<LegacySshMigrationOutcome>
    where
        H: FnMut(DualFileFaultPoint) -> Result<()>,
    {
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a durable transaction"
        );

        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let FileSnapshot::Present(freedom_source) = &freedom_before else {
                        return Ok(LegacySshMigrationOutcome::Unchanged);
                    };
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    let mut public = SensitiveYamlValue(
                        serde_yaml::from_slice(freedom_source).with_context(|| {
                            format!(
                                "parse YAML at {} before legacy SSH credential migration",
                                freedom_path.display()
                            )
                        })?,
                    );
                    let root = public.0.as_mapping_mut().with_context(|| {
                        format!(
                            "{} must contain a YAML mapping before legacy SSH credential migration",
                            freedom_path.display()
                        )
                    })?;
                    let key = serde_yaml::Value::String("ssh_tunnels".to_string());
                    let Some(legacy_value) = root.remove(&key) else {
                        return Ok(LegacySshMigrationOutcome::Unchanged);
                    };
                    // Keep stale plaintext auth zeroizing even when a
                    // dedicated authority means it must not be parsed or used.
                    let legacy_value = SensitiveYamlValue(legacy_value);

                    let mut credentials = Self::load_or_default_unlocked(credentials_path)
                        .with_context(|| {
                            format!(
                                "load {} for legacy SSH credential migration",
                                credentials_path.display()
                            )
                        })?;
                    let freedom_body = zeroize::Zeroizing::new(
                        serde_yaml::to_string(&public.0)
                            .context("serialize freedom.yaml without legacy SSH credentials")?,
                    );
                    let candidate: super::FreedomConfig = serde_yaml::from_str(&freedom_body)
                        .with_context(|| {
                            format!(
                                "validate {} after legacy SSH credential migration",
                                freedom_path.display()
                            )
                        })?;
                    let public_yaml = zeroize::Zeroizing::new(candidate.public_yaml()?);
                    let rendered_public: serde_yaml::Value = serde_yaml::from_str(&public_yaml)
                        .context("parse public FreedomConfig migration validation image")?;
                    let rendered_root = rendered_public.as_mapping().context(
                        "public FreedomConfig migration validation image must be a YAML mapping",
                    )?;
                    anyhow::ensure!(
                        !rendered_root.contains_key(&key),
                        "public FreedomConfig rendering retained private SSH tunnel authority"
                    );

                    let mut dedicated_keychain_ssh_present = false;
                    if credentials.ssh_tunnels.is_none()
                        && candidate.secrets_backend == super::SecretsBackend::Keychain
                    {
                        if let Some(store) = injected_store {
                            let mut effective = credentials.clone();
                            super::keychain::supplement_from_store(&mut effective, store)
                                .context("resolve dedicated keychain SSH migration authority")?;
                            dedicated_keychain_ssh_present = effective.ssh_tunnels.is_some();
                        } else {
                            let store = super::keychain::open_store().context(
                                "open OS keychain while resolving dedicated SSH migration authority",
                            )?;
                            let mut effective = credentials.clone();
                            super::keychain::supplement_from_store(&mut effective, store.as_ref())
                                .context("resolve dedicated keychain SSH migration authority")?;
                            dedicated_keychain_ssh_present = effective.ssh_tunnels.is_some();
                        }
                    }
                    if credentials.ssh_tunnels.is_none() && !dedicated_keychain_ssh_present {
                        let legacy_yaml = zeroize::Zeroizing::new(
                            serde_yaml::to_string(&legacy_value.0)
                                .context("serialize legacy freedom.yaml::ssh_tunnels")?,
                        );
                        let legacy_tunnels: Vec<crate::transport::ssh_config::SshTunnelConfig> =
                            serde_yaml::from_str(&legacy_yaml)
                                .context("parse legacy freedom.yaml::ssh_tunnels")?;
                        credentials.ssh_tunnels = Some(legacy_tunnels);
                    }

                    let freedom_after = FileSnapshot::Present(zeroize::Zeroizing::new(
                        freedom_body.as_bytes().to_vec(),
                    ));
                    let credentials_after = credentials.rendered_file_snapshot_preserving_unknown(
                        credentials_path,
                        &credentials_before,
                    )?;

                    publish_prepared_file_pair(
                        freedom_path,
                        credentials_path,
                        &freedom_dir,
                        &freedom_before,
                        &freedom_after,
                        &credentials_before,
                        &credentials_after,
                        LegacySshMigrationOutcome::Migrated,
                        Some(|path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }),
                        fault,
                    )
                })
            })
        })
    }

    /// Publish exact already-staged backup bytes as one crash-recoverable pair.
    /// `None` preserves that member's current exact bytes; encrypted credential
    /// frames are never decrypted, reserialized, or re-encrypted. Both target
    /// paths must be regular files or absent, never symlinks/directories.
    pub(crate) fn publish_exact_raw_pair_at(
        freedom_path: &Path,
        credentials_path: &Path,
        freedom_target: Option<&[u8]>,
        credentials_target: Option<&[u8]>,
    ) -> Result<()> {
        Self::publish_exact_raw_pair_at_using_fault(
            freedom_path,
            credentials_path,
            freedom_target,
            credentials_target,
            |_| Ok(()),
        )
    }

    pub(crate) fn validate_exact_raw_pair(
        freedom_path: &Path,
        credentials_path: &Path,
        freedom_target: Option<&[u8]>,
        credentials_target: Option<&[u8]>,
    ) -> Result<()> {
        validate_raw_freedom_target(freedom_path, freedom_target)?;
        validate_raw_credentials_target(credentials_path, credentials_target)
    }

    fn publish_exact_raw_pair_at_using_fault<H>(
        freedom_path: &Path,
        credentials_path: &Path,
        freedom_target: Option<&[u8]>,
        credentials_target: Option<&[u8]>,
        fault: H,
    ) -> Result<()>
    where
        H: FnMut(DualFileFaultPoint) -> Result<()>,
    {
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a durable transaction"
        );
        validate_exact_pair_target(freedom_path, "freedom config")?;
        validate_exact_pair_target(credentials_path, "credentials")?;
        Self::validate_exact_raw_pair(
            freedom_path,
            credentials_path,
            freedom_target,
            credentials_target,
        )?;

        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    // Recheck after acquiring every lock so a path swap cannot
                    // turn validation into a symlink overwrite.
                    validate_exact_pair_target(freedom_path, "freedom config")?;
                    validate_exact_pair_target(credentials_path, "credentials")?;
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    let freedom_after = freedom_target.map_or_else(
                        || freedom_before.duplicate(),
                        |target| FileSnapshot::Present(zeroize::Zeroizing::new(target.to_vec())),
                    );
                    let credentials_after = credentials_target.map_or_else(
                        || credentials_before.duplicate(),
                        |target| FileSnapshot::Present(zeroize::Zeroizing::new(target.to_vec())),
                    );
                    let write_freedom = freedom_target.map(|_| {
                        |path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }
                    });
                    publish_prepared_file_pair(
                        freedom_path,
                        credentials_path,
                        &freedom_dir,
                        &freedom_before,
                        &freedom_after,
                        &credentials_before,
                        &credentials_after,
                        (),
                        write_freedom,
                        fault,
                    )
                })
            })
        })
    }

    fn update_raw_freedom_with_credentials_at_using_fault<F, R, H>(
        freedom_path: &Path,
        credentials_path: &Path,
        mutation: F,
        fault: H,
    ) -> Result<R>
    where
        F: FnOnce(Option<&str>, &mut Self) -> Result<(Option<String>, R)>,
        H: FnMut(DualFileFaultPoint) -> Result<()>,
    {
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a durable transaction"
        );

        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    let source = freedom_before
                        .present_bytes()
                        .map(std::str::from_utf8)
                        .transpose()
                        .with_context(|| {
                            format!("{} is not valid UTF-8", freedom_path.display())
                        })?;
                    let mut credentials = Self::load_or_default_unlocked(credentials_path)
                        .with_context(|| {
                            format!("load {} for raw update", credentials_path.display())
                        })?;
                    let (freedom_target, value) = mutation(source, &mut credentials)?;
                    let freedom_target = freedom_target.map(zeroize::Zeroizing::new);
                    if let Some(target) = freedom_target.as_ref() {
                        let candidate: super::FreedomConfig = serde_yaml::from_str(target)
                            .with_context(|| {
                                format!("validate raw target for {}", freedom_path.display())
                            })?;
                        let _ = candidate.public_yaml()?;
                    }
                    let freedom_after = match freedom_target.as_ref() {
                        Some(target) => FileSnapshot::Present(zeroize::Zeroizing::new(
                            target.as_bytes().to_vec(),
                        )),
                        None => freedom_before.duplicate(),
                    };
                    let credentials_after = credentials.rendered_file_snapshot_preserving_unknown(
                        credentials_path,
                        &credentials_before,
                    )?;
                    let write_freedom = freedom_target.as_ref().map(|_| {
                        |path: &Path, body: &[u8]| {
                            crate::util::atomic_write::atomic_write_private(path, body)
                                .with_context(|| format!("atomically write {}", path.display()))
                        }
                    });
                    publish_prepared_file_pair(
                        freedom_path,
                        credentials_path,
                        &freedom_dir,
                        &freedom_before,
                        &freedom_after,
                        &credentials_before,
                        &credentials_after,
                        value,
                        write_freedom,
                        fault,
                    )
                })
            })
        })
    }

    /// Lock and strictly load both stores, but commit only credentials.yaml.
    /// Channel mutations use this when freedom.yaml is read-only input (most
    /// adapters), avoiding a lossy public-config rewrite while retaining the
    /// same lock order as Telegram's dual-file transaction.
    pub(crate) fn update_with_freedom_read_at<F, R>(
        freedom_path: &Path,
        credentials_path: &Path,
        mutation: F,
    ) -> Result<R>
    where
        F: FnOnce(&super::FreedomConfig, &mut Self) -> Result<R>,
    {
        Self::update_with_freedom_at_using(
            freedom_path,
            credentials_path,
            |freedom, credentials| mutation(freedom, credentials),
            None::<fn(&Path, &[u8]) -> Result<()>>,
            InlineTelegramTokenPolicy::Preserve,
            None,
        )
    }

    fn update_with_freedom_at_using<F, R, W>(
        freedom_path: &Path,
        credentials_path: &Path,
        mutation: F,
        write_freedom: Option<W>,
        inline_telegram_token: InlineTelegramTokenPolicy,
        expected_freedom_source: Option<&[u8]>,
    ) -> Result<R>
    where
        F: FnOnce(&mut super::FreedomConfig, &mut Self) -> Result<R>,
        W: FnOnce(&Path, &[u8]) -> Result<()>,
    {
        Self::update_with_freedom_at_using_and_fault(
            freedom_path,
            credentials_path,
            mutation,
            write_freedom,
            inline_telegram_token,
            expected_freedom_source,
            |_| Ok(()),
        )
    }

    fn update_with_freedom_at_using_and_fault<F, R, W, H>(
        freedom_path: &Path,
        credentials_path: &Path,
        mutation: F,
        write_freedom: Option<W>,
        inline_telegram_token: InlineTelegramTokenPolicy,
        expected_freedom_source: Option<&[u8]>,
        fault: H,
    ) -> Result<R>
    where
        F: FnOnce(&mut super::FreedomConfig, &mut Self) -> Result<R>,
        W: FnOnce(&Path, &[u8]) -> Result<()>,
        H: FnMut(DualFileFaultPoint) -> Result<()>,
    {
        let freedom_dir = transaction_directory(freedom_path);
        anyhow::ensure!(
            freedom_dir == transaction_directory(credentials_path),
            "freedom.yaml and credentials.yaml must be sibling files for a durable transaction"
        );

        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    let freedom_before = FileSnapshot::capture(freedom_path)?;
                    let credentials_before = FileSnapshot::capture(credentials_path)?;
                    if let Some(expected) = expected_freedom_source {
                        anyhow::ensure!(
                            freedom_before.present_bytes() == Some(expected),
                            "freedom.yaml changed after its reviewed snapshot; retry the command"
                        );
                    }

                    // Strict raw loads use the already-held boundary and avoid
                    // redundant effective/keychain supplementation.
                    let mut freedom = super::FreedomConfig::load_from_path_unlocked(freedom_path)
                        .with_context(|| {
                        format!("load {} for dual-file update", freedom_path.display())
                    })?;
                    let mut credentials = Self::load_or_default_unlocked(credentials_path)
                        .with_context(|| {
                            format!("load {} for dual-file update", credentials_path.display())
                        })?;
                    let value = mutation(&mut freedom, &mut credentials)?;

                    // Render and validate both exact target images before PREPARED is
                    // durable. No journal can therefore describe an unpublishable pair.
                    let freedom_body = write_freedom
                        .as_ref()
                        .map(|_| {
                            render_freedom_preserving_unknown_yaml(
                                &freedom,
                                &freedom_before,
                                inline_telegram_token,
                            )
                        })
                        .transpose()?;
                    let freedom_after = match freedom_body.as_ref() {
                        Some(body) => {
                            FileSnapshot::Present(zeroize::Zeroizing::new(body.as_bytes().to_vec()))
                        }
                        None => freedom_before.duplicate(),
                    };
                    let credentials_after = credentials.rendered_file_snapshot_preserving_unknown(
                        credentials_path,
                        &credentials_before,
                    )?;

                    publish_prepared_file_pair(
                        freedom_path,
                        credentials_path,
                        &freedom_dir,
                        &freedom_before,
                        &freedom_after,
                        &credentials_before,
                        &credentials_after,
                        value,
                        write_freedom,
                        fault,
                    )
                })
            })
        })
    }
}

#[cfg(test)]
mod n8n_adoption_transaction_tests {
    use super::{
        Credentials, FileSnapshot, JournalFileSnapshot, N8nAdoptionCustody,
        N8nAdoptionCustodyState, N8nAdoptionPhase, classify_n8n_adoption_custody,
        cleanup_n8n_keychain_custody,
    };
    use crate::config::keychain::SecretStore as _;
    use crate::config::{FreedomConfig, LoopbackHttpEndpoint, N8nInstanceConfig};
    use crate::secret::SecretString;

    #[test]
    fn file_adoption_publishes_and_rolls_back_only_its_exact_generation() {
        let dir = tempfile::tempdir().expect("temporary home");
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom,
            FreedomConfig::default()
                .public_yaml()
                .expect("public config"),
        )
        .expect("write public config");
        let instance = N8nInstanceConfig {
            endpoint: LoopbackHttpEndpoint::parse("http://127.0.0.1:5678")
                .expect("loopback endpoint"),
            api_version: Some("v1".to_string()),
        };
        let job_id = "018f4f64-5700-7000-8000-000000000001";
        let prepared = Credentials::prepare_n8n_adoption_at(
            &freedom,
            &credentials,
            job_id,
            instance,
            SecretString::from("n8n-test-key"),
        )
        .expect("prepare custody");
        Credentials::commit_prepared_n8n_adoption_at(prepared).expect("publish exact pair");
        assert_eq!(
            Credentials::inspect_n8n_adoption_custody_at(&freedom, &credentials, job_id)
                .expect("inspect custody"),
            N8nAdoptionCustodyState::Published,
        );
        Credentials::rollback_n8n_adoption_at(&freedom, &credentials, job_id)
            .expect("exact rollback");
        assert!(
            FreedomConfig::load_from_path(&freedom)
                .expect("reload public config")
                .n8n_instance
                .is_none()
        );
        assert!(
            Credentials::load_or_default_unlocked(&credentials)
                .expect("reload credentials")
                .n8n_api_key
                .is_none()
        );
    }

    #[test]
    fn keychain_custody_serialization_has_only_references_not_key_material() {
        let snapshot =
            FileSnapshot::Present(zeroize::Zeroizing::new(b"n8n_instance: null\n".to_vec()));
        let custody = N8nAdoptionCustody {
            job_id: "018f4f64-5700-7000-8000-000000000001".to_string(),
            phase: N8nAdoptionPhase::Prepared,
            keychain_mode: true,
            freedom_before: JournalFileSnapshot::from_file_snapshot(&snapshot),
            credentials_before: JournalFileSnapshot::from_file_snapshot(&snapshot),
            freedom_after: JournalFileSnapshot::from_file_snapshot(&snapshot),
            credentials_after: JournalFileSnapshot::from_file_snapshot(&snapshot),
            keychain_before_present: true,
            keychain_backup_key: Some(
                "n8n_api_key.backup.018f4f64-5700-7000-8000-000000000001".to_string(),
            ),
            keychain_candidate_key: Some(
                "n8n_api_key.candidate.018f4f64-5700-7000-8000-000000000001".to_string(),
            ),
        };
        let serialized = serde_yaml::to_string(&custody).expect("serialize custody");
        assert!(!serialized.contains("n8n-test-key"));
        assert!(!serialized.contains("previous-key-material"));
    }

    #[test]
    fn stale_source_cas_refuses_publication_and_preserves_the_later_bytes() {
        let dir = tempfile::tempdir().expect("temporary home");
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(&freedom, "operator_id: first\nunknown_extension: retain\n").unwrap();
        let prepared = Credentials::prepare_n8n_adoption_at(
            &freedom,
            &credentials,
            "018f4f64-5700-7000-8000-000000000002",
            N8nInstanceConfig {
                endpoint: LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap(),
                api_version: None,
            },
            SecretString::from("n8n-test-key"),
        )
        .unwrap();
        std::fs::write(&freedom, "operator_id: later\nunknown_extension: retain\n").unwrap();
        assert!(Credentials::commit_prepared_n8n_adoption_at(prepared).is_err());
        assert_eq!(
            std::fs::read_to_string(&freedom).unwrap(),
            "operator_id: later\nunknown_extension: retain\n"
        );
    }

    #[test]
    fn adoption_round_trip_retains_unknown_public_yaml() {
        let dir = tempfile::tempdir().expect("temporary home");
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom,
            "operator_id: sam\nfuture_extension:\n  untouched: true\n",
        )
        .unwrap();
        let job_id = "018f4f64-5700-7000-8000-000000000003";
        let prepared = Credentials::prepare_n8n_adoption_at(
            &freedom,
            &credentials,
            job_id,
            N8nInstanceConfig {
                endpoint: LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap(),
                api_version: None,
            },
            SecretString::from("n8n-test-key"),
        )
        .unwrap();
        Credentials::commit_prepared_n8n_adoption_at(prepared).unwrap();
        Credentials::rollback_n8n_adoption_at(&freedom, &credentials, job_id).unwrap();
        let rendered = std::fs::read_to_string(&freedom).unwrap();
        assert!(rendered.contains("future_extension:"));
        assert!(rendered.contains("untouched: true"));
    }

    #[test]
    fn durable_phase_classifier_distinguishes_pair_pending_and_repairable_rollback() {
        assert_eq!(
            classify_n8n_adoption_custody(
                N8nAdoptionPhase::CanonicalUpdatedPairPending,
                true,
                false,
                false,
                true
            )
            .unwrap(),
            N8nAdoptionCustodyState::CanonicalUpdatedPairPending,
        );
        assert_eq!(
            classify_n8n_adoption_custody(
                N8nAdoptionPhase::PairRestoredKeychainPending,
                true,
                false,
                false,
                true
            )
            .unwrap(),
            N8nAdoptionCustodyState::PairRestoredKeychainPending,
        );
        assert!(
            classify_n8n_adoption_custody(N8nAdoptionPhase::Published, false, false, false, false)
                .is_err()
        );
        assert_eq!(
            classify_n8n_adoption_custody(
                N8nAdoptionPhase::ReadyFinalizationPending,
                false,
                true,
                false,
                true
            )
            .unwrap(),
            N8nAdoptionCustodyState::ReadyFinalizationPending,
        );
    }

    #[test]
    fn injected_keychain_cleanup_can_retry_after_a_partial_delete() {
        struct FailCandidateDeleteOnce {
            inner: crate::config::keychain::InMemorySecretStore,
            fail_once: std::sync::Mutex<bool>,
        }
        impl crate::config::keychain::SecretStore for FailCandidateDeleteOnce {
            fn get(&self, key: &str) -> anyhow::Result<Option<SecretString>> {
                self.inner.get(key)
            }
            fn set(&self, key: &str, value: &SecretString) -> anyhow::Result<()> {
                self.inner.set(key, value)
            }
            fn delete(&self, key: &str) -> anyhow::Result<()> {
                let mut fail_once = self.fail_once.lock().unwrap();
                if key.contains("candidate") && *fail_once {
                    *fail_once = false;
                    anyhow::bail!("injected candidate delete failure");
                }
                self.inner.delete(key)
            }
            fn backend_name(&self) -> &'static str {
                "injected n8n custody test store"
            }
        }
        let snapshot =
            FileSnapshot::Present(zeroize::Zeroizing::new(b"n8n_instance: null\n".to_vec()));
        let custody = N8nAdoptionCustody {
            job_id: "018f4f64-5700-7000-8000-000000000004".to_string(),
            phase: N8nAdoptionPhase::ReadyFinalizationPending,
            keychain_mode: true,
            freedom_before: JournalFileSnapshot::from_file_snapshot(&snapshot),
            credentials_before: JournalFileSnapshot::from_file_snapshot(&snapshot),
            freedom_after: JournalFileSnapshot::from_file_snapshot(&snapshot),
            credentials_after: JournalFileSnapshot::from_file_snapshot(&snapshot),
            keychain_before_present: false,
            keychain_backup_key: Some(
                "n8n_api_key.backup.018f4f64-5700-7000-8000-000000000004".to_string(),
            ),
            keychain_candidate_key: Some(
                "n8n_api_key.candidate.018f4f64-5700-7000-8000-000000000004".to_string(),
            ),
        };
        let store = FailCandidateDeleteOnce {
            inner: Default::default(),
            fail_once: std::sync::Mutex::new(true),
        };
        store
            .set(
                custody.keychain_backup_key.as_deref().unwrap(),
                &SecretString::from("before"),
            )
            .unwrap();
        store
            .set(
                custody.keychain_candidate_key.as_deref().unwrap(),
                &SecretString::from("target"),
            )
            .unwrap();
        assert!(cleanup_n8n_keychain_custody(&store, &custody).is_err());
        assert!(
            store
                .get(custody.keychain_candidate_key.as_deref().unwrap())
                .unwrap()
                .is_some()
        );
        cleanup_n8n_keychain_custody(&store, &custody).unwrap();
        assert!(
            store
                .get(custody.keychain_candidate_key.as_deref().unwrap())
                .unwrap()
                .is_none()
        );
    }
    fn adopt_and_finish_file_binding(
        freedom: &std::path::Path,
        credentials: &std::path::Path,
        job_id: &str,
    ) -> LoopbackHttpEndpoint {
        let endpoint = LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap();
        let prepared = Credentials::prepare_n8n_adoption_at(
            freedom,
            credentials,
            job_id,
            N8nInstanceConfig {
                endpoint: endpoint.clone(),
                api_version: Some("v1".to_owned()),
            },
            SecretString::from("n8n-test-key"),
        )
        .unwrap();
        Credentials::commit_prepared_n8n_adoption_at(prepared).unwrap();
        Credentials::finish_n8n_adoption_at(freedom, credentials, job_id).unwrap();
        endpoint
    }

    #[test]
    fn owned_file_binding_clear_is_exact_idempotent_and_preserves_unknown_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom,
            "operator_id: sam\nfuture_extension:\n  retain: true\n",
        )
        .unwrap();
        let job_id = "018f4f64-5700-7000-8000-000000000101";
        let endpoint = adopt_and_finish_file_binding(&freedom, &credentials, job_id);

        assert_eq!(
            Credentials::clear_owned_n8n_binding_at(&freedom, &credentials, job_id, &endpoint)
                .unwrap(),
            super::N8nOwnedCleanupOutcome::Cleared,
        );
        assert!(
            FreedomConfig::load_from_path(&freedom)
                .unwrap()
                .n8n_instance
                .is_none()
        );
        assert!(
            Credentials::load_or_default_unlocked(&credentials)
                .unwrap()
                .n8n_api_key
                .is_none()
        );
        assert!(
            std::fs::read_to_string(&freedom)
                .unwrap()
                .contains("future_extension:")
        );
        assert_eq!(
            Credentials::clear_owned_n8n_binding_at(&freedom, &credentials, job_id, &endpoint)
                .unwrap(),
            super::N8nOwnedCleanupOutcome::AlreadyAbsent,
        );
    }

    #[test]
    fn owned_cleanup_preserves_unproven_changed_and_partial_generations() {
        let dir = tempfile::tempdir().unwrap();
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(&freedom, FreedomConfig::default().public_yaml().unwrap()).unwrap();
        let endpoint = LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap();
        let job_id = "018f4f64-5700-7000-8000-000000000102";
        assert_eq!(
            Credentials::clear_owned_n8n_binding_at(&freedom, &credentials, job_id, &endpoint)
                .unwrap(),
            super::N8nOwnedCleanupOutcome::PreservedUnproven,
        );

        let endpoint = adopt_and_finish_file_binding(&freedom, &credentials, job_id);
        let mut config = FreedomConfig::load_from_path(&freedom).unwrap();
        config.n8n_instance = Some(N8nInstanceConfig {
            endpoint: LoopbackHttpEndpoint::parse("http://127.0.0.1:5679").unwrap(),
            api_version: None,
        });
        std::fs::write(&freedom, config.public_yaml().unwrap()).unwrap();
        assert_eq!(
            Credentials::clear_owned_n8n_binding_at(&freedom, &credentials, job_id, &endpoint)
                .unwrap(),
            super::N8nOwnedCleanupOutcome::PreservedChanged,
        );

        let mut changed = Credentials::load_or_default_unlocked(&credentials).unwrap();
        changed.n8n_api_key = None;
        changed.write(&credentials).unwrap();
        assert_eq!(
            Credentials::clear_owned_n8n_binding_at(&freedom, &credentials, job_id, &endpoint)
                .unwrap(),
            super::N8nOwnedCleanupOutcome::PreservedChanged,
        );
    }

    #[test]
    fn owned_cleanup_preserves_a_backend_switch_before_already_absent() {
        let dir = tempfile::tempdir().unwrap();
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(&freedom, FreedomConfig::default().public_yaml().unwrap()).unwrap();
        let job_id = "018f4f64-5700-7000-8000-000000000103";
        let endpoint = adopt_and_finish_file_binding(&freedom, &credentials, job_id);
        let mut config = FreedomConfig::load_from_path(&freedom).unwrap();
        config.secrets_backend = crate::config::SecretsBackend::Keychain;
        config.n8n_instance = None;
        std::fs::write(&freedom, config.public_yaml().unwrap()).unwrap();
        Credentials::default().write(&credentials).unwrap();

        assert_eq!(
            Credentials::clear_owned_n8n_binding_at(&freedom, &credentials, job_id, &endpoint)
                .unwrap(),
            super::N8nOwnedCleanupOutcome::PreservedChanged,
        );
    }
    #[test]
    fn pending_finalization_without_a_receipt_never_mints_retroactive_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(&freedom, FreedomConfig::default().public_yaml().unwrap()).unwrap();
        let job_id = "018f4f64-5700-7000-8000-000000000104";
        let endpoint = LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap();
        let prepared = Credentials::prepare_n8n_adoption_at(
            &freedom,
            &credentials,
            job_id,
            N8nInstanceConfig {
                endpoint: endpoint.clone(),
                api_version: None,
            },
            SecretString::from("n8n-test-key"),
        )
        .unwrap();
        Credentials::commit_prepared_n8n_adoption_at(prepared).unwrap();
        let custody_path = super::n8n_adoption_custody_path(&freedom, job_id).unwrap();
        let mut custody = super::load_n8n_adoption_custody(&custody_path).unwrap();
        custody.phase = N8nAdoptionPhase::ReadyFinalizationPending;
        super::persist_n8n_adoption_custody(&custody_path, &custody).unwrap();

        Credentials::finish_n8n_adoption_at(&freedom, &credentials, job_id).unwrap();
        let receipt = super::n8n_owned_binding_receipt_path(&freedom, job_id).unwrap();
        assert!(
            super::load_n8n_owned_binding_receipt(&receipt)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            Credentials::clear_owned_n8n_binding_at(&freedom, &credentials, job_id, &endpoint)
                .unwrap(),
            super::N8nOwnedCleanupOutcome::PreservedUnproven,
        );
    }
    #[test]
    fn owned_cleanup_preserves_a_replaced_key_with_the_original_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(&freedom, FreedomConfig::default().public_yaml().unwrap()).unwrap();
        let job_id = "018f4f64-5700-7000-8000-000000000105";
        let endpoint = adopt_and_finish_file_binding(&freedom, &credentials, job_id);
        let mut replacement = Credentials::load_or_default_unlocked(&credentials).unwrap();
        replacement.n8n_api_key = Some(SecretString::from("later-n8n-test-key"));
        replacement.write(&credentials).unwrap();
        let freedom_before = std::fs::read(&freedom).unwrap();
        let credentials_before = std::fs::read(&credentials).unwrap();

        assert_eq!(
            Credentials::clear_owned_n8n_binding_at(&freedom, &credentials, job_id, &endpoint)
                .unwrap(),
            super::N8nOwnedCleanupOutcome::PreservedChanged,
        );
        assert_eq!(std::fs::read(&freedom).unwrap(), freedom_before);
        assert_eq!(std::fs::read(&credentials).unwrap(), credentials_before);
    }

    #[test]
    fn owned_cleanup_preserves_a_changed_api_version_with_the_original_endpoint_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(&freedom, FreedomConfig::default().public_yaml().unwrap()).unwrap();
        let job_id = "018f4f64-5700-7000-8000-000000000106";
        let endpoint = adopt_and_finish_file_binding(&freedom, &credentials, job_id);
        let mut config = FreedomConfig::load_from_path(&freedom).unwrap();
        config.n8n_instance.as_mut().unwrap().api_version = Some("v2".to_owned());
        std::fs::write(&freedom, config.public_yaml().unwrap()).unwrap();
        let freedom_before = std::fs::read(&freedom).unwrap();
        let credentials_before = std::fs::read(&credentials).unwrap();

        assert_eq!(
            Credentials::clear_owned_n8n_binding_at(&freedom, &credentials, job_id, &endpoint)
                .unwrap(),
            super::N8nOwnedCleanupOutcome::PreservedChanged,
        );
        assert_eq!(std::fs::read(&freedom).unwrap(), freedom_before);
        assert_eq!(std::fs::read(&credentials).unwrap(), credentials_before);
    }

    #[test]
    fn wrong_receipt_job_fails_before_writing_the_file_pair() {
        let dir = tempfile::tempdir().unwrap();
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(&freedom, FreedomConfig::default().public_yaml().unwrap()).unwrap();
        let job_id = "018f4f64-5700-7000-8000-000000000107";
        let endpoint = adopt_and_finish_file_binding(&freedom, &credentials, job_id);
        let receipt_path = super::n8n_owned_binding_receipt_path(&freedom, job_id).unwrap();
        let mut receipt = super::load_n8n_owned_binding_receipt(&receipt_path)
            .unwrap()
            .unwrap();
        receipt.job_id = "018f4f64-5700-7000-8000-000000000108".to_owned();
        super::persist_n8n_owned_binding_receipt(&receipt_path, &receipt).unwrap();
        let freedom_before = std::fs::read(&freedom).unwrap();
        let credentials_before = std::fs::read(&credentials).unwrap();

        assert!(
            Credentials::clear_owned_n8n_binding_at(&freedom, &credentials, job_id, &endpoint)
                .is_err()
        );
        assert_eq!(std::fs::read(&freedom).unwrap(), freedom_before);
        assert_eq!(std::fs::read(&credentials).unwrap(), credentials_before);
    }

    #[test]
    fn pending_receipt_never_rebinds_a_replacement_key() {
        let dir = tempfile::tempdir().unwrap();
        let freedom = dir.path().join("freedom.yaml");
        let credentials = dir.path().join("credentials.yaml");
        std::fs::write(&freedom, FreedomConfig::default().public_yaml().unwrap()).unwrap();
        let job_id = "018f4f64-5700-7000-8000-000000000109";
        let endpoint = LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap();
        let prepared = Credentials::prepare_n8n_adoption_at(
            &freedom,
            &credentials,
            job_id,
            N8nInstanceConfig {
                endpoint,
                api_version: Some("v1".to_owned()),
            },
            SecretString::from("n8n-test-key"),
        )
        .unwrap();
        Credentials::commit_prepared_n8n_adoption_at(prepared).unwrap();
        let receipt_path = super::n8n_owned_binding_receipt_path(&freedom, job_id).unwrap();
        let receipt = super::N8nOwnedBindingReceipt {
            job_id: job_id.to_owned(),
            endpoint_origin: "http://127.0.0.1:5678".to_owned(),
            api_version: Some("v1".to_owned()),
            api_key_commitment: super::n8n_key_commitment(&SecretString::from("n8n-test-key")),
            keychain_mode: false,
        };
        super::persist_n8n_owned_binding_receipt(&receipt_path, &receipt).unwrap();
        let custody_path = super::n8n_adoption_custody_path(&freedom, job_id).unwrap();
        let mut custody = super::load_n8n_adoption_custody(&custody_path).unwrap();
        custody.phase = N8nAdoptionPhase::ReadyFinalizationPending;
        super::persist_n8n_adoption_custody(&custody_path, &custody).unwrap();
        let mut replacement = Credentials::load_or_default_unlocked(&credentials).unwrap();
        replacement.n8n_api_key = Some(SecretString::from("later-n8n-test-key"));
        replacement.write(&credentials).unwrap();

        assert!(Credentials::finish_n8n_adoption_at(&freedom, &credentials, job_id).is_err());
        assert_eq!(
            super::load_n8n_owned_binding_receipt(&receipt_path)
                .unwrap()
                .unwrap()
                .api_key_commitment,
            receipt.api_key_commitment,
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegacySshMigrationOutcome {
    Unchanged,
    Migrated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DualFileFaultPoint {
    JournalPrepared,
    CredentialsPublished,
    FreedomPublished,
    DirectorySynced,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DualFileTestFaultPoint {
    JournalPrepared,
    FreedomPublished,
    DirectorySynced,
}

#[derive(Debug, thiserror::Error)]
#[error("dual-file target publication crossed its recovery boundary")]
struct DualFileTargetPublicationCrossed;

fn target_publication_crossed_error(source: anyhow::Error) -> anyhow::Error {
    if dual_file_target_publication_crossed(&source) {
        return source;
    }
    source.context(DualFileTargetPublicationCrossed)
}

/// True only when a returned error may follow publication of the complete
/// target pair. Callers that maintain a coupled external store (for example
/// the OS keychain) must retain its new generation in this case: recovery may
/// already have committed the new file generation, or may do so on next load.
pub(crate) fn dual_file_target_publication_crossed(error: &anyhow::Error) -> bool {
    error.is::<DualFileTargetPublicationCrossed>()
}

#[cfg(test)]
pub(crate) fn test_target_publication_crossed_error(source: anyhow::Error) -> anyhow::Error {
    target_publication_crossed_error(source)
}

fn validate_exact_pair_target(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
                "{label} restore target {} must be a regular file, never a symlink or directory",
                path.display()
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("inspect {label} target {}", path.display()))
        }
    }
}

fn validate_raw_freedom_target(path: &Path, target: Option<&[u8]>) -> Result<()> {
    let Some(target) = target else {
        return Ok(());
    };
    let body = std::str::from_utf8(target)
        .with_context(|| format!("restored freedom config {} is not UTF-8", path.display()))?;
    let candidate: super::FreedomConfig = serde_yaml::from_str(body)
        .with_context(|| format!("parse restored freedom config {}", path.display()))?;
    let _ = candidate.public_yaml()?;
    Ok(())
}

fn validate_raw_credentials_target(path: &Path, target: Option<&[u8]>) -> Result<()> {
    let Some(target) = target else {
        return Ok(());
    };
    if credentials_blob_is_encrypted(target) {
        anyhow::ensure!(
            target.len() >= CONF_MAGIC.len() + 12 + 16,
            "restored encrypted credentials {} are truncated",
            path.display()
        );
        return Ok(());
    }
    let body = std::str::from_utf8(target)
        .with_context(|| format!("restored credentials {} are not UTF-8", path.display()))?;
    let _: Credentials = serde_yaml::from_str(body)
        .with_context(|| format!("parse restored credentials {}", path.display()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn publish_prepared_file_pair<R, W, H>(
    freedom_path: &Path,
    credentials_path: &Path,
    freedom_dir: &Path,
    freedom_before: &FileSnapshot,
    freedom_after: &FileSnapshot,
    credentials_before: &FileSnapshot,
    credentials_after: &FileSnapshot,
    value: R,
    write_freedom: Option<W>,
    mut fault: H,
) -> Result<R>
where
    W: FnOnce(&Path, &[u8]) -> Result<()>,
    H: FnMut(DualFileFaultPoint) -> Result<()>,
{
    let needs_freedom_publication = !freedom_before.same_as(freedom_after);
    let journal = DualFileJournal::prepared(
        freedom_path,
        credentials_path,
        freedom_before,
        freedom_after,
        credentials_before,
        credentials_after,
    )?;
    let journal_path = freedom_dir.join(DUAL_FILE_JOURNAL_NAME);
    journal.persist(&journal_path)?;
    fault(DualFileFaultPoint::JournalPrepared)?;

    if let Err(write_error) = credentials_after.restore(credentials_path) {
        return Err(transaction_write_error(
            freedom_dir,
            "credential phase failed",
            write_error,
            !needs_freedom_publication,
        ));
    }
    if let Err(error) = fault(DualFileFaultPoint::CredentialsPublished) {
        return if needs_freedom_publication {
            Err(error)
        } else {
            Err(target_publication_crossed_error(error))
        };
    }

    if let Some(write_freedom) = write_freedom {
        let target = freedom_after
            .present_bytes()
            .context("freedom target unexpectedly missing for requested publication")?;
        if let Err(write_error) = write_freedom(freedom_path, target) {
            return Err(transaction_write_error(
                freedom_dir,
                "freedom config phase failed",
                write_error,
                true,
            ));
        }
    }
    fault(DualFileFaultPoint::FreedomPublished).map_err(target_publication_crossed_error)?;

    let actual_freedom =
        FileSnapshot::capture(freedom_path).map_err(target_publication_crossed_error)?;
    let actual_credentials =
        FileSnapshot::capture(credentials_path).map_err(target_publication_crossed_error)?;
    if !actual_freedom.same_as(freedom_after) || !actual_credentials.same_as(credentials_after) {
        return Err(transaction_write_error(
            freedom_dir,
            "dual-file publication verification failed",
            anyhow::anyhow!("published bytes do not match the PREPARED target"),
            true,
        ));
    }

    sync_transaction_directory(freedom_dir).map_err(target_publication_crossed_error)?;
    fault(DualFileFaultPoint::DirectorySynced).map_err(target_publication_crossed_error)?;
    crate::util::atomic_write::durable_remove_file(&journal_path)
        .with_context(|| {
            format!(
                "durably remove committed journal {}",
                journal_path.display()
            )
        })
        .map_err(target_publication_crossed_error)?;
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InlineTelegramTokenPolicy {
    Preserve,
    Remove,
}

enum FileSnapshot {
    Missing,
    Present(zeroize::Zeroizing<Vec<u8>>),
}

struct SensitiveYamlValue(serde_yaml::Value);

impl Drop for SensitiveYamlValue {
    fn drop(&mut self) {
        zeroize_yaml_value(&mut self.0);
    }
}

fn zeroize_yaml_value(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::String(value) => value.zeroize(),
        serde_yaml::Value::Sequence(values) => {
            for value in values {
                zeroize_yaml_value(value);
            }
        }
        serde_yaml::Value::Mapping(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                zeroize_yaml_value(&mut key);
                zeroize_yaml_value(&mut value);
            }
        }
        serde_yaml::Value::Tagged(value) => zeroize_yaml_value(&mut value.value),
        _ => {}
    }
}

#[derive(Default, Deserialize)]
struct LegacyInlineSecrets {
    #[serde(default)]
    provider_key: Option<SecretString>,
    #[serde(default)]
    telegram_token: Option<SecretString>,
    #[serde(default)]
    inference: LegacyInlineInferenceSecrets,
}

#[derive(Default, Deserialize)]
struct LegacyInlineInferenceSecrets {
    #[serde(default)]
    left: LegacyInlineSlotSecret,
    #[serde(default)]
    right: LegacyInlineSlotSecret,
    #[serde(default)]
    cerebellum: LegacyInlineSlotSecret,
    #[serde(default)]
    default_slot: LegacyInlineSlotSecret,
}

#[derive(Default, Deserialize)]
struct LegacyInlineSlotSecret {
    #[serde(default)]
    key: Option<SecretString>,
}

fn overlay_known_yaml(target: &mut serde_yaml::Value, source: serde_yaml::Value) {
    match source {
        serde_yaml::Value::Mapping(source) => {
            if let serde_yaml::Value::Mapping(target) = target {
                for (key, value) in source {
                    match target.get_mut(&key) {
                        Some(existing) => overlay_known_yaml(existing, value),
                        None => {
                            target.insert(key, value);
                        }
                    }
                }
            } else {
                *target = serde_yaml::Value::Mapping(source);
            }
        }
        serde_yaml::Value::Sequence(source) => {
            if let serde_yaml::Value::Sequence(target) = target {
                if target.len() == source.len() {
                    for (existing, value) in target.iter_mut().zip(source) {
                        overlay_known_yaml(existing, value);
                    }
                } else {
                    *target = source;
                }
            } else {
                *target = serde_yaml::Value::Sequence(source);
            }
        }
        source => *target = source,
    }
}

/// `overlay_known_yaml` intentionally preserves extension fields, but named
/// account IDs are a typed, security-bearing map: an absent typed key means a
/// completed retirement, never an unknown extension. Remove only those stale
/// direct account entries before the generic recursive overlay so unrelated
/// siblings and unknown fields beneath surviving accounts remain intact.
fn remove_retired_channel_account_yaml(
    root: &mut serde_yaml::Value,
    channel: &str,
    live: &std::collections::BTreeMap<crate::channels::registry::ChannelAccountId, impl Sized>,
) {
    let serde_yaml::Value::Mapping(root) = root else {
        return;
    };
    let key = |name: &str| serde_yaml::Value::String(name.to_owned());
    let Some(serde_yaml::Value::Mapping(accounts)) = root.get_mut(key("channel_accounts")) else {
        return;
    };
    let Some(serde_yaml::Value::Mapping(channel_accounts)) = accounts.get_mut(key(channel)) else {
        return;
    };
    channel_accounts.retain(|entry, _| match entry.as_str() {
        Some(id) => crate::channels::registry::ChannelAccountId::new(id.to_owned())
            .map(|account| live.contains_key(&account))
            // Unknown/malformed YAML is retained so the subsequent typed
            // validation, rather than retirement, reports it fail-closed.
            .unwrap_or(true),
        None => true,
    });
}

fn render_freedom_preserving_unknown_yaml(
    freedom: &super::FreedomConfig,
    before: &FileSnapshot,
    inline_telegram_token: InlineTelegramTokenPolicy,
) -> Result<zeroize::Zeroizing<String>> {
    let FileSnapshot::Present(before) = before else {
        anyhow::bail!("freedom.yaml disappeared before dual-file serialization");
    };
    let legacy = serde_yaml::from_slice::<LegacyInlineSecrets>(before)
        .context("parse legacy inline secrets before dual-file update")?;
    let mut merged = SensitiveYamlValue(
        serde_yaml::from_slice(before)
            .context("parse original freedom.yaml before dual-file update")?,
    );

    // `loop_config.token_budget` is the read-only legacy alias for
    // `tool_call_budget`. Remove the alias before overlaying the canonical
    // typed value; retaining both makes Serde report a duplicate field and
    // would strand upgraded configs on every later dual-file mutation.
    if let serde_yaml::Value::Mapping(root) = &mut merged.0 {
        let loop_key = serde_yaml::Value::String("loop_config".to_string());
        if let Some(serde_yaml::Value::Mapping(loop_config)) = root.get_mut(&loop_key) {
            let legacy_key = serde_yaml::Value::String("token_budget".to_string());
            if let Some(mut legacy_value) = loop_config.remove(&legacy_key) {
                zeroize_yaml_value(&mut legacy_value);
            }
        }
    }

    // Run the canonical public renderer first for all validation gates. The
    // persisted clone below then receives only secrets proven to have existed
    // inline in the pre-transaction file. Generic callers preserve every
    // unrelated secret; the Telegram adoption path alone migrates its token.
    let _ = freedom.public_yaml()?;
    let mut persisted = freedom.clone();
    persisted.telegram_token = match inline_telegram_token {
        InlineTelegramTokenPolicy::Preserve => legacy.telegram_token,
        InlineTelegramTokenPolicy::Remove => None,
    };
    persisted.provider_key = legacy.provider_key;
    persisted.inference.left.key = legacy.inference.left.key;
    persisted.inference.right.key = legacy.inference.right.key;
    persisted.inference.cerebellum.key = legacy.inference.cerebellum.key;
    persisted.inference.default_slot.key = legacy.inference.default_slot.key;
    let known = serde_yaml::to_value(&persisted)
        .context("serialize known freedom.yaml fields for dual-file update")?;
    remove_retired_channel_account_yaml(
        &mut merged.0,
        "telegram",
        &persisted.channel_accounts.telegram,
    );
    remove_retired_channel_account_yaml(&mut merged.0, "slack", &persisted.channel_accounts.slack);
    overlay_known_yaml(&mut merged.0, known);
    let body = zeroize::Zeroizing::new(
        serde_yaml::to_string(&merged.0)
            .context("serialize freedom.yaml while preserving unknown fields")?,
    );

    // The structural merge must remain a valid, policy-compliant config. This
    // also catches a future schema collision where an old extension changes
    // the type expected by a newly adopted field.
    let merged_config: super::FreedomConfig = serde_yaml::from_str(&body)
        .context("validate merged freedom.yaml after dual-file update")?;
    let _ = merged_config.public_yaml()?;
    Ok(body)
}

impl FileSnapshot {
    fn capture(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Self::Present(zeroize::Zeroizing::new(bytes))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::Missing),
            Err(error) => Err(error).with_context(|| format!("snapshot {}", path.display())),
        }
    }

    fn restore(&self, path: &Path) -> Result<()> {
        match self {
            Self::Present(bytes) => {
                crate::util::atomic_write::atomic_write_private(path, bytes)
                    .with_context(|| format!("restore {}", path.display()))?;
            }
            Self::Missing => crate::util::atomic_write::durable_remove_file(path)
                .with_context(|| format!("durably remove {}", path.display()))?,
        }
        Ok(())
    }

    fn duplicate(&self) -> Self {
        match self {
            Self::Missing => Self::Missing,
            Self::Present(bytes) => {
                Self::Present(zeroize::Zeroizing::new(bytes.as_slice().to_vec()))
            }
        }
    }

    fn present_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Missing => None,
            Self::Present(bytes) => Some(bytes.as_slice()),
        }
    }

    fn same_as(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Missing, Self::Missing) => true,
            (Self::Present(left), Self::Present(right)) => left.as_slice() == right.as_slice(),
            _ => false,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFileSnapshot {
    present: bool,
    body_base64: String,
    sha256: String,
}

impl JournalFileSnapshot {
    fn from_file_snapshot(snapshot: &FileSnapshot) -> Self {
        let bytes = snapshot.present_bytes().unwrap_or_default();
        Self {
            present: snapshot.present_bytes().is_some(),
            body_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    fn decode(&self, label: &str) -> Result<FileSnapshot> {
        let decoded = zeroize::Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(&self.body_base64)
                .with_context(|| format!("decode {label} from dual-file journal"))?,
        );
        anyhow::ensure!(
            format!("{:x}", Sha256::digest(decoded.as_slice())) == self.sha256,
            "{label} checksum mismatch in dual-file journal"
        );
        if self.present {
            Ok(FileSnapshot::Present(decoded))
        } else {
            anyhow::ensure!(
                decoded.is_empty(),
                "missing {label} snapshot carries unexpected bytes"
            );
            Ok(FileSnapshot::Missing)
        }
    }
}

impl Drop for JournalFileSnapshot {
    fn drop(&mut self) {
        self.body_base64.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DualFileJournal {
    version: u8,
    state: String,
    freedom_file: String,
    credentials_file: String,
    freedom_before: JournalFileSnapshot,
    freedom_after: JournalFileSnapshot,
    credentials_before: JournalFileSnapshot,
    credentials_after: JournalFileSnapshot,
}

impl DualFileJournal {
    fn prepared(
        freedom_path: &Path,
        credentials_path: &Path,
        freedom_before: &FileSnapshot,
        freedom_after: &FileSnapshot,
        credentials_before: &FileSnapshot,
        credentials_after: &FileSnapshot,
    ) -> Result<Self> {
        let freedom_file = transaction_file_name(freedom_path, "freedom config")?;
        let credentials_file = transaction_file_name(credentials_path, "credentials")?;
        anyhow::ensure!(
            freedom_file != credentials_file,
            "freedom and credential transaction paths must be distinct"
        );
        Ok(Self {
            version: DUAL_FILE_JOURNAL_VERSION,
            state: DUAL_FILE_JOURNAL_STATE.to_string(),
            freedom_file,
            credentials_file,
            freedom_before: JournalFileSnapshot::from_file_snapshot(freedom_before),
            freedom_after: JournalFileSnapshot::from_file_snapshot(freedom_after),
            credentials_before: JournalFileSnapshot::from_file_snapshot(credentials_before),
            credentials_after: JournalFileSnapshot::from_file_snapshot(credentials_after),
        })
    }

    fn persist(&self, path: &Path) -> Result<()> {
        let mut body =
            serde_yaml::to_string(self).context("serialize dual-file PREPARED journal")?;
        if body.len() as u64 > MAX_DUAL_FILE_JOURNAL_BYTES {
            body.zeroize();
            anyhow::bail!(
                "dual-file PREPARED journal exceeds the {}-byte recovery limit",
                MAX_DUAL_FILE_JOURNAL_BYTES
            );
        }
        let result = crate::util::atomic_write::atomic_write_private(path, body.as_bytes())
            .with_context(|| format!("durably write private journal {}", path.display()));
        body.zeroize();
        result?;

        // PREPARED must be durable before the first target rename. The shared
        // atomic helper fsyncs file data; make namespace durability mandatory
        // here instead of accepting its best-effort parent sync.
        #[cfg(unix)]
        sync_transaction_directory(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
        )?;
        #[cfg(windows)]
        {
            let journal = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .with_context(|| format!("reopen PREPARED journal {}", path.display()))?;
            crate::wal::win_native::verify_private_file_handle(&journal)
                .with_context(|| format!("verify PREPARED journal DACL {}", path.display()))?;
            journal
                .sync_all()
                .with_context(|| format!("flush PREPARED journal {}", path.display()))?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == DUAL_FILE_JOURNAL_VERSION,
            "unsupported dual-file journal version {}",
            self.version
        );
        anyhow::ensure!(
            self.state == DUAL_FILE_JOURNAL_STATE,
            "unsupported dual-file journal state"
        );
        validate_transaction_file_name(&self.freedom_file, "freedom config")?;
        validate_transaction_file_name(&self.credentials_file, "credentials")?;
        anyhow::ensure!(
            self.freedom_file != self.credentials_file,
            "dual-file journal targets the same file twice"
        );
        Ok(())
    }
}

fn transaction_file_name(path: &Path, label: &str) -> Result<String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{label} path needs a UTF-8 file name"))?
        .to_string();
    validate_transaction_file_name(&name, label)?;
    Ok(name)
}

fn validate_transaction_file_name(name: &str, label: &str) -> Result<()> {
    let mut components = Path::new(name).components();
    anyhow::ensure!(
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none(),
        "{label} journal target must be one plain file name"
    );
    anyhow::ensure!(
        name != DUAL_FILE_JOURNAL_NAME && name != DUAL_FILE_LOCK_NAME,
        "{label} journal target collides with transaction metadata"
    );
    Ok(())
}

fn read_private_journal(path: &Path) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    use std::io::Read as _;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("open private journal {}", path.display()));
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect private journal {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= MAX_DUAL_FILE_JOURNAL_BYTES,
        "dual-file journal {} must be a regular file no larger than {} bytes",
        path.display(),
        MAX_DUAL_FILE_JOURNAL_BYTES
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode() & 0o777;
        anyhow::ensure!(
            mode & 0o077 == 0,
            "dual-file journal {} is readable outside its owner (mode {:o}); refusing to expose secret snapshots",
            path.display(),
            mode
        );
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_file_handle(&file)
        .with_context(|| format!("verify private journal DACL {}", path.display()))?;

    let mut raw = zeroize::Zeroizing::new(Vec::new());
    file.read_to_end(&mut raw)
        .with_context(|| format!("read private journal {}", path.display()))?;
    Ok(Some(raw))
}

fn sync_transaction_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(directory)
            .and_then(|handle| handle.sync_all())
            .with_context(|| format!("fsync transaction directory {}", directory.display()))?;
    }
    // Windows target files are FlushFileBuffers'd before their handle-bound
    // NTFS rename. Windows has no portable directory-fsync through std; the
    // rename/delete namespace changes are protected by the filesystem journal.
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

fn read_prepared_transaction(directory: &Path) -> Result<Option<(PathBuf, DualFileJournal)>> {
    let journal_path = directory.join(DUAL_FILE_JOURNAL_NAME);
    let Some(raw) = read_private_journal(&journal_path)? else {
        return Ok(None);
    };
    let journal: DualFileJournal = serde_yaml::from_slice(&raw)
        .with_context(|| format!("parse PREPARED journal {}", journal_path.display()))?;
    journal.validate()?;
    Ok(Some((journal_path, journal)))
}

fn recover_prepared_transaction_in(directory: &Path) -> Result<()> {
    let Some((journal_path, journal)) = read_prepared_transaction(directory)? else {
        return Ok(());
    };

    let freedom_path = directory.join(&journal.freedom_file);
    let credentials_path = directory.join(&journal.credentials_file);

    // The transaction process + OS locks are already held by the caller.
    // Take the canonical legacy locks as well so a pre-journal NEOTH process
    // cannot publish either target while recovery captures/restores the pair.
    let _freedom_mutex = super::lock_freedom_update();
    let _credentials_mutex = lock_cred();
    let _freedom_file_lock = crate::util::locked_file::lock_file_blocking(
        &freedom_path.with_extension("lock"),
        "freedom config recovery",
    )
    .with_context(|| {
        format!(
            "acquire freedom config recovery lock for {}",
            freedom_path.display()
        )
    })?;
    let _credentials_file_lock = lock_cred_file(&credentials_path).with_context(|| {
        format!(
            "acquire credentials recovery lock for {}",
            credentials_path.display()
        )
    })?;

    recover_prepared_journal_locked(directory, journal_path, journal).map(|_| ())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DualFileRecoveryOutcome {
    Committed,
    RolledBack,
}

/// Recover while the caller already holds both canonical process and file
/// locks. This is exclusively the returned-write-error path inside the normal
/// transaction and must not attempt to reacquire non-reentrant file locks.
fn recover_prepared_transaction_in_locked(
    directory: &Path,
) -> Result<Option<DualFileRecoveryOutcome>> {
    let Some((journal_path, journal)) = read_prepared_transaction(directory)? else {
        return Ok(None);
    };
    recover_prepared_journal_locked(directory, journal_path, journal).map(Some)
}

fn recover_prepared_journal_locked(
    directory: &Path,
    journal_path: PathBuf,
    journal: DualFileJournal,
) -> Result<DualFileRecoveryOutcome> {
    let freedom_path = directory.join(&journal.freedom_file);
    let credentials_path = directory.join(&journal.credentials_file);
    let freedom_before = journal.freedom_before.decode("freedom_before")?;
    let freedom_after = journal.freedom_after.decode("freedom_after")?;
    let credentials_before = journal.credentials_before.decode("credentials_before")?;
    let credentials_after = journal.credentials_after.decode("credentials_after")?;
    let current_freedom = FileSnapshot::capture(&freedom_path)?;
    let current_credentials = FileSnapshot::capture(&credentials_path)?;

    let freedom_known =
        current_freedom.same_as(&freedom_before) || current_freedom.same_as(&freedom_after);
    let credentials_known = current_credentials.same_as(&credentials_before)
        || current_credentials.same_as(&credentials_after);
    anyhow::ensure!(
        freedom_known && credentials_known,
        "PREPARED dual-file journal does not match current config bytes; refusing automatic recovery"
    );

    if current_freedom.same_as(&freedom_after) && current_credentials.same_as(&credentials_after) {
        sync_transaction_directory(directory)?;
        crate::util::atomic_write::durable_remove_file(&journal_path).with_context(|| {
            format!("durably clear committed journal {}", journal_path.display())
        })?;
        return Ok(DualFileRecoveryOutcome::Committed);
    }

    let freedom_result = freedom_before.restore(&freedom_path);
    let credentials_result = credentials_before.restore(&credentials_path);
    match (freedom_result, credentials_result) {
        (Ok(()), Ok(())) => {}
        (Err(freedom), Ok(())) => return Err(freedom).context("restore freedom config"),
        (Ok(()), Err(credentials)) => return Err(credentials).context("restore credentials"),
        (Err(freedom), Err(credentials)) => anyhow::bail!(
            "restore freedom config failed: {freedom:#}; restore credentials failed: {credentials:#}"
        ),
    }

    anyhow::ensure!(
        FileSnapshot::capture(&freedom_path)?.same_as(&freedom_before)
            && FileSnapshot::capture(&credentials_path)?.same_as(&credentials_before),
        "dual-file rollback verification failed; PREPARED journal retained"
    );
    sync_transaction_directory(directory)?;
    crate::util::atomic_write::durable_remove_file(&journal_path).with_context(|| {
        format!(
            "durably clear rolled-back journal {}",
            journal_path.display()
        )
    })?;
    Ok(DualFileRecoveryOutcome::RolledBack)
}

fn transaction_write_error(
    directory: &Path,
    phase: &str,
    write_error: anyhow::Error,
    may_have_complete_target: bool,
) -> anyhow::Error {
    match recover_prepared_transaction_in_locked(directory) {
        Ok(Some(DualFileRecoveryOutcome::Committed)) => {
            target_publication_crossed_error(write_error.context(format!(
                "{phase}; the complete published target pair was retained"
            )))
        }
        Ok(Some(DualFileRecoveryOutcome::RolledBack) | None) => {
            write_error.context(format!("{phase}; prior bytes restored"))
        }
        Err(recovery_error) => {
            let error = anyhow::anyhow!(
                "{phase} ({write_error:#}); PREPARED transaction recovery failed and the journal was retained: {recovery_error:#}"
            );
            if may_have_complete_target {
                target_publication_crossed_error(error)
            } else {
                error
            }
        }
    }
}

/// Unpredictable sibling temp path for an atomic credentials write
/// (GOLD-SEC-15 / A-34). Lives next to the target so the final
/// `fs::rename` stays on the same filesystem (atomic).
fn atomic_tmp_path(path: &Path) -> Result<std::path::PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|error| {
        anyhow::anyhow!("OS RNG unavailable for credentials temp name: {error}")
    })?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("credentials.yaml");
    Ok(path.with_file_name(format!(".{name}.{}.tmp", hex::encode(nonce))))
}

/// GR-081 — RAII cleanup that removes a secret temp file on drop (any early
/// return or panic) UNLESS disarmed after a successful rename, so a
/// partially-written plaintext secret never lingers on disk on a write / fsync /
/// rename / secure-create error path. Best-effort removal (a failed unlink is no
/// worse than the prior leak).
struct SecretTmpGuard {
    path: Option<PathBuf>,
    file: Option<std::fs::File>,
}

impl SecretTmpGuard {
    fn new(path: &Path, file: std::fs::File) -> Self {
        Self {
            path: Some(path.to_path_buf()),
            file: Some(file),
        }
    }

    #[cfg(windows)]
    fn file(&self) -> &std::fs::File {
        self.file.as_ref().expect("secret temp file is present")
    }

    fn file_mut(&mut self) -> &mut std::fs::File {
        self.file.as_mut().expect("secret temp file is present")
    }

    /// Call after the atomic rename succeeds — the temp is gone (renamed), so
    /// there is nothing left to clean up.
    fn disarm(mut self) {
        self.path = None;
    }
}

impl Drop for SecretTmpGuard {
    fn drop(&mut self) {
        // Windows private files deliberately deny delete sharing. Close the
        // exact created handle before attempting error-path cleanup.
        drop(self.file.take());
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(unix)]
pub(crate) fn write_mode_0600(path: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // Atomic write: create a 0600 temp, write+fsync, then rename over the
    // target. The mode is set at create time so the secrets are never on
    // disk under a wider mode, and a crash mid-write leaves the old file
    // intact (GOLD-SEC-15 / A-34).
    let tmp = atomic_tmp_path(path)?;
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("create credentials temp {} mode 0600", tmp.display()))?;
    // GR-081 — remove the secret temp on any early return below (write / fsync /
    // rename error or panic); disarmed only after the rename succeeds.
    let mut guard = SecretTmpGuard::new(&tmp, file);
    guard
        .file_mut()
        .write_all(body)
        .with_context(|| format!("write credentials body to {}", tmp.display()))?;
    guard
        .file_mut()
        .sync_all()
        .with_context(|| format!("fsync credentials temp {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("atomically replace credentials {}", path.display()))?;
    guard.disarm();
    Ok(())
}

#[cfg(windows)]
pub(crate) fn write_mode_0600(path: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    // GOLD-SEC-15 / A-34: lock the DACL to owner-only BEFORE the secret
    // bytes are written. Previously the body was written under the
    // inherited (potentially wider) ACL and only restricted afterwards —
    // a window where provider keys / channel tokens were readable on
    // disk. The protected TokenUser DACL is supplied to CreateFileW itself;
    // the exact verified handle remains open through the handle-bound rename.
    // Fail CLOSED: the DACL is the only at-rest protection, so if it can
    // not be set we refuse to write the secrets at all.
    let tmp = atomic_tmp_path(path)?;
    let file = crate::wal::win_native::create_private_file_new(&tmp)
        .with_context(|| format!("create credentials temp {}", tmp.display()))?;
    // GR-081 — the secret temp is removed on ANY early return below (secure-create,
    // write / fsync / rename error, or panic); disarmed only after
    // a successful rename.
    let mut guard = SecretTmpGuard::new(&tmp, file);
    guard
        .file_mut()
        .write_all(body)
        .with_context(|| format!("write credentials body to {}", tmp.display()))?;
    guard
        .file_mut()
        .sync_all()
        .with_context(|| format!("fsync credentials temp {}", tmp.display()))?;
    crate::wal::win_native::replace_private_file_handle(guard.file(), path)
        .with_context(|| format!("atomically replace credentials {}", path.display()))?;
    guard.disarm();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::keychain::SecretStore;

    fn ephemeral_test_secret() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn conf_key(seed: u8) -> crate::wal::crypto::WalSegmentKey {
        let m = crate::wal::crypto::WalMasterKey::from_bytes(&[seed; 32]).unwrap();
        crate::wal::crypto::derive_subkey(&m, crate::wal::crypto::INFO_CONFIG).unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn private_credentials_write_uses_the_process_token_sid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");

        write_mode_0600(&path, b"provider_key: secret\n").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"provider_key: secret\n");
        crate::wal::win_native::verify_private_dacl(&path).unwrap();
    }

    #[test]
    fn credentials_at_rest_round_trips_and_hides_the_secret() {
        let key = conf_key(11);
        let yaml = "provider_key: sk-supersecret-123\ntelegram_token: bot-abc\n";
        let blob = encrypt_credentials_body(&key, yaml).unwrap();
        assert!(blob.starts_with(CONF_MAGIC), "framed with the config magic");
        // The plaintext secret must not appear in the ciphertext.
        assert!(
            !blob.windows(11).any(|w| w == b"supersecret"),
            "ciphertext must not contain the plaintext secret"
        );
        assert_eq!(decrypt_credentials_body(&key, &blob).unwrap(), yaml);
    }

    #[test]
    fn credentials_decrypt_wrong_key_or_tamper_fails() {
        let blob = encrypt_credentials_body(&conf_key(1), "provider_key: x\n").unwrap();
        assert!(
            decrypt_credentials_body(&conf_key(2), &blob).is_err(),
            "wrong key"
        );
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 0xFF;
        assert!(
            decrypt_credentials_body(&conf_key(1), &tampered).is_err(),
            "tamper"
        );
    }

    #[test]
    fn legacy_plaintext_credentials_are_not_magic_framed() {
        // A plaintext YAML file does not carry CONF_MAGIC → load() reads it as
        // legacy plaintext (no key needed). The WAL ENC_MAGIC is also distinct.
        assert!(!b"provider_key: x\n".starts_with(CONF_MAGIC));
        assert_ne!(CONF_MAGIC, crate::wal::crypto::ENC_MAGIC);
    }
    use tempfile::tempdir;

    #[test]
    fn secret_tmp_guard_removes_on_drop_unless_disarmed() {
        // GR-081: an un-disarmed guard removes the secret temp on drop (the
        // error / early-return path); a disarmed guard leaves it (rename done).
        let dir = tempdir().unwrap();
        let leaked = dir.path().join(".leak.tmp");
        std::fs::write(&leaked, b"secret-bytes").unwrap();
        {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&leaked)
                .unwrap();
            let _g = SecretTmpGuard::new(&leaked, file);
        } // dropped without disarm → removed
        assert!(
            !leaked.exists(),
            "an un-disarmed guard must remove the temp on drop"
        );

        let kept = dir.path().join(".kept.tmp");
        std::fs::write(&kept, b"secret-bytes").unwrap();
        {
            let file = std::fs::OpenOptions::new().write(true).open(&kept).unwrap();
            let g = SecretTmpGuard::new(&kept, file);
            g.disarm();
        }
        assert!(
            kept.exists(),
            "a disarmed guard must leave the file (rename succeeded)"
        );
    }

    #[test]
    fn missing_file_returns_default() {
        let dir = tempdir().unwrap();
        let c = Credentials::load_or_default(&dir.path().join("absent.yaml")).unwrap();
        assert!(c.is_empty());
        assert!(c.provider_key.is_none());
        assert!(c.telegram_token.is_none());
    }

    #[test]
    fn parses_both_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::write(
            &path,
            "provider_key: sk-test\ntelegram_token: 12345:abcdef\n",
        )
        .unwrap();
        let c = Credentials::load_or_default(&path).unwrap();
        assert_eq!(c.provider_key.as_ref().unwrap().expose(), "sk-test");
        assert_eq!(c.telegram_token.as_ref().unwrap().expose(), "12345:abcdef");
        assert!(c.has_any());
    }

    #[test]
    fn direct_write_and_migration_blank_preserve_future_credential_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        std::fs::write(
            &path,
            "provider_key: old-provider\nfuture_secret: future-keep-me\n",
        )
        .unwrap();

        Credentials {
            provider_key: Some(SecretString::from("new-provider")),
            ..Default::default()
        }
        .write(&path)
        .unwrap();
        let updated: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(updated["provider_key"].as_str(), Some("new-provider"));
        assert_eq!(updated["future_secret"].as_str(), Some("future-keep-me"));

        Credentials::default().write(&path).unwrap();
        let blanked: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(blanked["provider_key"].is_null());
        assert_eq!(blanked["future_secret"].as_str(), Some("future-keep-me"));
    }

    #[test]
    fn direct_write_waits_for_legacy_credentials_file_lock() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        let legacy_lock = lock_cred_file(&path).unwrap();
        let started = Arc::new(Barrier::new(2));
        let (done, completion) = mpsc::channel();
        let writer = {
            let started = Arc::clone(&started);
            let path = path.clone();
            std::thread::spawn(move || {
                started.wait();
                Credentials {
                    provider_key: Some(SecretString::from("new-provider")),
                    ..Default::default()
                }
                .write(&path)
                .unwrap();
                done.send(()).unwrap();
            })
        };
        started.wait();
        let finished_early = completion.recv_timeout(Duration::from_millis(100)).is_ok();
        drop(legacy_lock);
        if !finished_early {
            completion.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        writer.join().unwrap();
        assert!(
            !finished_early,
            "direct writes must honor the canonical credentials file lock"
        );
    }

    #[test]
    fn omi_tokens_round_trip_without_public_or_diagnostic_leaks() {
        const API_KEY: &str = "omi_dev_secret_api_key";
        const INGEST_TOKEN: &str = "omi-secret-ingest-token";
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        let original = Credentials {
            omi_developer_api_key: Some(SecretString::from(API_KEY)),
            omi_ingest_token: Some(SecretString::from(INGEST_TOKEN)),
            ..Default::default()
        };
        assert!(original.has_any(), "OMI keys must count as credentials");
        let debug = format!("{original:?}");
        assert!(!debug.contains(API_KEY));
        assert!(!debug.contains(INGEST_TOKEN));

        original.write(&path).unwrap();
        assert_eq!(
            Credentials::credential_store_status(&path),
            CredentialStoreStatus::Ok
        );
        assert!(
            !Credentials::credential_store_status(&path)
                .as_str()
                .contains(API_KEY)
        );
        let loaded = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            loaded.omi_developer_api_key.as_ref().unwrap().expose(),
            API_KEY
        );
        assert_eq!(
            loaded.omi_ingest_token.as_ref().unwrap().expose(),
            INGEST_TOKEN
        );

        let public = serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap();
        assert!(!public.contains("omi_developer_api_key"));
        assert!(!public.contains("omi_ingest_token"));
        assert!(!public.contains(API_KEY));
        assert!(!public.contains(INGEST_TOKEN));
    }

    #[test]
    fn keet_capability_and_bearer_are_redacted_and_legacy_bearer_alias_loads() {
        const TOPIC: &str = "nk1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const BEARER: &str = "0123456789abcdef0123456789abcdef";
        let legacy = format!("keet_topic: {TOPIC}\npears_bearer_token: {BEARER}\n");
        let credentials: Credentials = serde_yaml::from_str(&legacy).unwrap();
        assert_eq!(
            credentials.keet_topic.as_ref().map(SecretString::expose),
            Some(TOPIC)
        );
        assert_eq!(
            credentials
                .keet_bridge_bearer_token
                .as_ref()
                .map(SecretString::expose),
            Some(BEARER)
        );
        let debug = format!("{credentials:?}");
        assert!(!debug.contains(TOPIC));
        assert!(!debug.contains(BEARER));

        let canonical = serde_yaml::to_string(&credentials).unwrap();
        assert!(canonical.contains("keet_bridge_bearer_token:"));
        assert!(!canonical.contains("pears_bearer_token:"));
    }

    #[test]
    fn legacy_pears_bearer_alias_is_canonicalized_during_lossless_rmw() {
        const TOPIC: &str = "nk1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const BEARER: &str = "0123456789abcdef0123456789abcdef";
        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        std::fs::write(
            &path,
            format!("keet_topic: {TOPIC}\npears_bearer_token: {BEARER}\nfuture_secret: keep-me\n"),
        )
        .unwrap();

        Credentials::update_at(&path, |credentials| {
            credentials.telegram_token = Some(SecretString::from("telegram-secret"));
            Ok(())
        })
        .unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("keet_bridge_bearer_token:"));
        assert!(!raw.contains("pears_bearer_token:"));
        assert!(raw.contains("future_secret: keep-me"));
        let loaded = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            loaded
                .keet_bridge_bearer_token
                .as_ref()
                .map(SecretString::expose),
            Some(BEARER)
        );
    }

    #[test]
    fn tts_keys_round_trip_only_in_credentials_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        let original = Credentials {
            elevenlabs_tts_api_key: Some(SecretString::from("eleven-secret")),
            azure_tts_api_key: Some(SecretString::from("azure-secret")),
            ..Default::default()
        };
        original.write(&path).unwrap();
        let loaded = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            loaded.elevenlabs_tts_api_key.as_ref().unwrap().expose(),
            "eleven-secret"
        );
        assert_eq!(
            loaded.azure_tts_api_key.as_ref().unwrap().expose(),
            "azure-secret"
        );
        let public = serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap();
        assert!(!public.contains("elevenlabs_tts_api_key"));
        assert!(!public.contains("azure_tts_api_key"));
        assert!(!format!("{original:?}").contains("eleven-secret"));
    }

    #[test]
    fn inbound_sender_policies_round_trip_with_channel_credentials() {
        // Every transport credential and exact sender policy must survive the
        // real lossless credentials store path as one startability contract.
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        let original = Credentials {
            discord_bot_token: Some(SecretString::from("bot-abc123")),
            discord_allowed_user_id: Some("123456789012345678".into()),
            slack_bot_token: Some(SecretString::from("xoxb-token")),
            slack_app_token: Some(SecretString::from("xapp-token")),
            slack_allowed_user_id: Some("U123456789".into()),
            whatsapp_token: Some(SecretString::from("meta-token")),
            whatsapp_allowed_sender: Some("491701234567".into()),
            signal_cli_url: Some("http://127.0.0.1:8080".into()),
            signal_phone_number: Some("+491701111111".into()),
            signal_allowed_sender: Some("+491702222222".into()),
            line_channel_access_token: Some(SecretString::from("line-token")),
            line_allowed_sender: Some("Uabcdef123456".into()),
            ..Default::default()
        };
        original.write(&path).unwrap();
        let loaded = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            loaded.discord_bot_token.as_ref().unwrap().expose(),
            "bot-abc123"
        );
        assert_eq!(
            loaded.discord_allowed_user_id.as_deref(),
            Some("123456789012345678")
        );
        assert_eq!(loaded.slack_allowed_user_id.as_deref(), Some("U123456789"));
        assert_eq!(
            loaded.whatsapp_allowed_sender.as_deref(),
            Some("491701234567")
        );
        assert_eq!(
            loaded.signal_allowed_sender.as_deref(),
            Some("+491702222222")
        );
        assert_eq!(loaded.line_allowed_sender.as_deref(), Some("Uabcdef123456"));
        assert!(loaded.has_any());
    }

    #[test]
    fn parses_partial_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, "provider_key: just-the-key\n").unwrap();
        let c = Credentials::load_or_default(&path).unwrap();
        assert!(c.provider_key.is_some());
        assert!(c.telegram_token.is_none());
    }

    #[test]
    fn parses_per_slot_inference_keys_and_counts_non_empty() {
        // GR-041: a credentials file with only a per-slot inference key must
        // parse it AND not be treated as empty (else save would delete the
        // file and the key would be lost — the very gap this finding closed).
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::write(
            &path,
            "inference_left_key: left-secret\ninference_default_slot_key: default-secret\n",
        )
        .unwrap();
        let c = Credentials::load_or_default(&path).unwrap();
        assert!(c.inference_left_key.is_some());
        assert!(c.inference_default_slot_key.is_some());
        assert!(c.inference_right_key.is_none());
        assert!(c.inference_cerebellum_key.is_none());
        assert!(!c.is_empty(), "a per-slot key must count toward non-empty");
    }

    #[test]
    fn write_creates_file_with_both_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        let c = Credentials {
            provider_key: Some(SecretString::from("sk-x")),
            telegram_token: Some(SecretString::from("tg-y")),
            ..Default::default()
        };
        c.write(&path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("provider_key"));
        assert!(body.contains("sk-x"));
        assert!(body.contains("telegram_token"));
        assert!(body.contains("tg-y"));
    }

    #[test]
    fn write_empty_credentials_removes_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, "provider_key: stale\n").unwrap();
        let c = Credentials::default();
        c.write(&path).unwrap();
        assert!(
            !path.exists(),
            "empty credentials must remove the stub file"
        );
    }

    #[test]
    fn write_skips_when_empty_and_no_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        let c = Credentials::default();
        c.write(&path).unwrap();
        assert!(!path.exists(), "empty credentials must not create the file");
    }

    #[test]
    fn write_empty_credentials_reports_a_failed_revocation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::create_dir(&path).unwrap();

        let error = Credentials::default().write(&path).unwrap_err();

        assert!(error.to_string().contains("remove empty credential store"));
        assert!(path.is_dir(), "failed revocation must remain observable");
    }

    #[test]
    fn bad_yaml_returns_error_not_silent_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, "this is = not [valid").unwrap();
        let r = Credentials::load_or_default(&path);
        assert!(r.is_err(), "bad YAML must surface as error");
    }

    // ── B17 regression tests ───────────────────────────────────────────────

    #[test]
    fn load_or_default_notfound_returns_default() {
        // TOCTOU fix: direct fs::read, only NotFound → Ok(default).
        let dir = tempdir().unwrap();
        let path = dir.path().join("absent.yaml");
        let c = Credentials::load_or_default(&path).unwrap();
        assert!(c.is_empty(), "missing file must return empty default");
    }

    #[test]
    fn credential_store_status_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("no.yaml");
        assert_eq!(
            Credentials::credential_store_status(&path),
            CredentialStoreStatus::Missing
        );
    }

    #[test]
    fn credential_store_status_ok() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, "provider_key: sk-test\n").unwrap();
        assert_eq!(
            Credentials::credential_store_status(&path),
            CredentialStoreStatus::Ok
        );
    }

    #[test]
    fn credential_store_status_invalid_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, "this is = not [valid yaml").unwrap();
        assert_eq!(
            Credentials::credential_store_status(&path),
            CredentialStoreStatus::Invalid
        );
    }

    #[test]
    fn credential_store_status_invalid_utf8() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        // Non-UTF-8 bytes, no CONF_MAGIC prefix.
        std::fs::write(&path, [0xFF, 0xFE, 0x00, 0x01]).unwrap();
        assert_eq!(
            Credentials::credential_store_status(&path),
            CredentialStoreStatus::Invalid
        );
    }

    #[test]
    fn update_at_missing_file_creates_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        // File does not exist yet — update_at must create it with the mutated creds.
        Credentials::update_at(&path, |c| {
            c.telegram_token = Some(SecretString::from("bot-token"));
            Ok(())
        })
        .unwrap();
        let loaded = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            loaded.telegram_token.as_ref().unwrap().expose(),
            "bot-token"
        );
    }

    #[test]
    fn update_at_never_writes_on_load_failure() {
        // STOP invariant: a malformed YAML file must not be overwritten.
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        let sentinel = "this is = not [valid yaml SENTINEL_BYTES_MUST_SURVIVE";
        std::fs::write(&path, sentinel).unwrap();
        let original_bytes = std::fs::read(&path).unwrap();

        let r = Credentials::update_at(&path, |_c| -> Result<()> { Ok(()) });
        assert!(r.is_err(), "update_at on malformed YAML must return Err");
        let after_bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            original_bytes, after_bytes,
            "file bytes must be identical after a failed update_at"
        );
    }

    #[test]
    fn dual_file_update_rolls_back_both_files_when_second_write_fails() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let mut original_freedom = crate::config::FreedomConfig::default();
        original_freedom.telegram_user_id = Some(111_111_111);
        std::fs::write(
            &freedom_path,
            serde_yaml::to_string(&original_freedom).unwrap(),
        )
        .unwrap();
        Credentials {
            telegram_token: Some(SecretString::from("111111111:old-token")),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();
        let freedom_before = std::fs::read(&freedom_path).unwrap();
        let credentials_before = std::fs::read(&credentials_path).unwrap();

        let error = Credentials::update_with_freedom_at_using(
            &freedom_path,
            &credentials_path,
            |freedom, credentials| {
                freedom.telegram_user_id = Some(222_222_222);
                credentials.telegram_token = Some(SecretString::from("222222222:new-token"));
                Ok(())
            },
            Some(|_: &Path, _: &[u8]| anyhow::bail!("injected second-file failure")),
            InlineTelegramTokenPolicy::Preserve,
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("bytes restored"));
        assert_eq!(std::fs::read(&freedom_path).unwrap(), freedom_before);
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            credentials_before
        );
        assert!(
            !dir.path().join(DUAL_FILE_JOURNAL_NAME).exists(),
            "returned write errors must finish rollback and durably clear PREPARED"
        );
    }

    #[test]
    fn reported_second_write_error_after_publication_retains_and_marks_new_pair() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let mut original_freedom = crate::config::FreedomConfig::default();
        original_freedom.telegram_user_id = Some(111_111_111);
        std::fs::write(
            &freedom_path,
            serde_yaml::to_string(&original_freedom).unwrap(),
        )
        .unwrap();
        Credentials {
            telegram_token: Some(SecretString::from("111111111:old-token")),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();

        let error = Credentials::update_with_freedom_at_using(
            &freedom_path,
            &credentials_path,
            |freedom, credentials| {
                freedom.telegram_user_id = Some(222_222_222);
                credentials.telegram_token = Some(SecretString::from("222222222:new-token"));
                Ok(())
            },
            Some(|path: &Path, body: &[u8]| {
                crate::util::atomic_write::atomic_write_private(path, body)?;
                anyhow::bail!("injected error after second target publication")
            }),
            InlineTelegramTokenPolicy::Preserve,
            None,
        )
        .unwrap_err();

        assert!(dual_file_target_publication_crossed(&error));
        assert!(format!("{error:#}").contains("injected error after second target publication"));
        assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());
        let loaded = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap();
        assert_eq!(loaded.telegram_user_id, Some(222_222_222));
        assert_eq!(
            loaded.telegram_token.as_ref().unwrap().expose(),
            "222222222:new-token"
        );
    }

    fn assert_dual_file_crash_recovery(
        point: DualFileFaultPoint,
        committed: bool,
        recover_via_credentials: bool,
        recover_via_wal: bool,
    ) {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let mut original_freedom = crate::config::FreedomConfig::default();
        original_freedom.telegram_user_id = Some(111_111_111);
        std::fs::write(
            &freedom_path,
            serde_yaml::to_string(&original_freedom).unwrap(),
        )
        .unwrap();
        Credentials {
            telegram_token: Some(SecretString::from("111111111:old-token")),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();

        let error = Credentials::update_with_freedom_at_using_and_fault(
            &freedom_path,
            &credentials_path,
            |freedom, credentials| {
                freedom.telegram_user_id = Some(222_222_222);
                credentials.telegram_token = Some(SecretString::from("222222222:new-token"));
                Ok(())
            },
            Some(|path: &Path, body: &[u8]| {
                crate::util::atomic_write::atomic_write_private(path, body)
                    .map_err(anyhow::Error::from)
            }),
            InlineTelegramTokenPolicy::Preserve,
            None,
            |current| {
                if current == point {
                    anyhow::bail!("injected process crash at {current:?}");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(
            dual_file_target_publication_crossed(&error),
            point == DualFileFaultPoint::FreedomPublished
        );
        assert!(format!("{error:#}").contains("injected process crash"));

        let journal_path = dir.path().join(DUAL_FILE_JOURNAL_NAME);
        assert!(
            journal_path.exists(),
            "simulated crash must retain PREPARED"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&journal_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0,
                "journal carries secret snapshots and must never be group/world-readable"
            );
        }

        let expected_id = if committed { 222_222_222 } else { 111_111_111 };
        let expected_token = if committed {
            "222222222:new-token"
        } else {
            "111111111:old-token"
        };
        // Either public runtime entrypoint MUST recover the pair before it
        // parses its requested file.
        if recover_via_credentials {
            let recovered = Credentials::load_or_default(&credentials_path).unwrap();
            assert_eq!(
                recovered.telegram_token.as_ref().unwrap().expose(),
                expected_token
            );
        }
        if recover_via_wal {
            assert_eq!(
                crate::config::load_wal_config(&freedom_path).unwrap(),
                crate::config::WalConfig::default()
            );
        }
        let loaded = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap();
        assert_eq!(loaded.telegram_user_id, Some(expected_id));
        assert_eq!(
            loaded.telegram_token.as_ref().unwrap().expose(),
            expected_token
        );
        assert!(
            !journal_path.exists(),
            "successful commit-or-rollback recovery must durably clear PREPARED"
        );

        // Recovery is idempotent: a second independent credential/config load
        // observes exactly the already-decided pair and performs no mutation.
        let credentials = Credentials::load_or_default(&credentials_path).unwrap();
        assert_eq!(
            credentials.telegram_token.as_ref().unwrap().expose(),
            expected_token
        );
        let loaded_again = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap();
        assert_eq!(loaded_again.telegram_user_id, Some(expected_id));
    }

    #[test]
    fn crash_after_prepared_journal_rolls_back_before_runtime_load() {
        assert_dual_file_crash_recovery(DualFileFaultPoint::JournalPrepared, false, false, false);
    }

    #[test]
    fn crash_after_credentials_rename_rolls_back_before_runtime_load() {
        assert_dual_file_crash_recovery(
            DualFileFaultPoint::CredentialsPublished,
            false,
            true,
            false,
        );
    }

    #[test]
    fn crash_after_freedom_rename_commits_before_runtime_load() {
        assert_dual_file_crash_recovery(DualFileFaultPoint::FreedomPublished, true, false, false);
    }

    #[test]
    fn unchanged_freedom_target_marks_credentials_publication_as_complete_pair() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let freedom_target =
            serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap();
        std::fs::write(&freedom_path, &freedom_target).unwrap();
        Credentials {
            telegram_token: Some(SecretString::from("111111111:old-token")),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();
        let staged_credentials_path = dir.path().join("staged-credentials.yaml");
        Credentials {
            telegram_token: Some(SecretString::from("222222222:new-token")),
            ..Default::default()
        }
        .write(&staged_credentials_path)
        .unwrap();
        let credentials_target = std::fs::read(&staged_credentials_path).unwrap();
        std::fs::remove_file(staged_credentials_path).unwrap();

        let error = Credentials::publish_exact_raw_pair_at_using_fault(
            &freedom_path,
            &credentials_path,
            Some(freedom_target.as_bytes()),
            Some(&credentials_target),
            |point| {
                if point == DualFileFaultPoint::CredentialsPublished {
                    anyhow::bail!("injected failure after complete credentials-only change");
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(dual_file_target_publication_crossed(&error));
        let loaded = Credentials::load_or_default(&credentials_path).unwrap();
        assert_eq!(
            loaded.telegram_token.as_ref().unwrap().expose(),
            "222222222:new-token"
        );
        assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());
    }

    #[test]
    fn credential_only_publication_error_is_marked_and_recovers_after_image() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&freedom_path, "operator_id: credential-only\n").unwrap();
        Credentials {
            provider_key: Some(SecretString::from("staged-provider")),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();

        let error = Credentials::update_raw_freedom_with_credentials_at_using_fault(
            &freedom_path,
            &credentials_path,
            |_source, credentials| {
                credentials.provider_key = None;
                Ok((None, ()))
            },
            |point| {
                if point == DualFileFaultPoint::CredentialsPublished {
                    anyhow::bail!("injected credential-only publication failure");
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(dual_file_target_publication_crossed(&error));
        assert!(format!("{error:#}").contains("injected credential-only publication failure"));
        assert!(dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());

        let pair = crate::config::load_runtime_config_pair_from_path(&freedom_path).unwrap();
        assert!(pair.raw_credentials.provider_key.is_none());
        assert_eq!(pair.config.operator_id.as_deref(), Some("credential-only"));
        assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());
    }

    #[test]
    fn wal_loader_recovers_prepared_pair_before_partial_read() {
        assert_dual_file_crash_recovery(
            DualFileFaultPoint::CredentialsPublished,
            false,
            false,
            true,
        );
    }

    #[test]
    fn raw_first_run_transaction_recovers_missing_pair_after_crash() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");

        let error = Credentials::update_raw_freedom_with_credentials_at_using_fault(
            &freedom_path,
            &credentials_path,
            |source, credentials| {
                assert!(source.is_none());
                credentials.provider_key = Some(SecretString::from("first-run-provider"));
                Ok((
                    Some("operator_id: first-run\nfuture_extension: keep-me\n".to_string()),
                    (),
                ))
            },
            |point| {
                if point == DualFileFaultPoint::CredentialsPublished {
                    anyhow::bail!("injected first-run crash");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected first-run crash"));
        assert!(dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());

        let pair =
            crate::config::load_runtime_config_pair_from_path_or_default(&freedom_path).unwrap();
        assert!(pair.raw_credentials.is_empty());
        assert!(!freedom_path.exists());
        assert!(!credentials_path.exists());
        assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());

        Credentials::update_raw_freedom_with_credentials_at(
            &freedom_path,
            &credentials_path,
            |source, credentials| {
                assert!(source.is_none());
                credentials.provider_key = Some(SecretString::from("committed-provider"));
                Ok((
                    Some("operator_id: committed\nfuture_extension: keep-me\n".to_string()),
                    (),
                ))
            },
        )
        .unwrap();
        let pair = crate::config::load_runtime_config_pair_from_path(&freedom_path).unwrap();
        assert_eq!(pair.config.operator_id.as_deref(), Some("committed"));
        assert_eq!(
            pair.credentials.provider_key.as_ref().unwrap().expose(),
            "committed-provider"
        );
        let raw: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom_path).unwrap()).unwrap();
        assert_eq!(raw["future_extension"].as_str(), Some("keep-me"));
    }

    #[test]
    fn exact_encrypted_pair_restore_recovers_crashes_without_reencoding() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let mut old_config = crate::config::FreedomConfig::default();
        old_config.operator_id = Some("old".to_string());
        let old_freedom = serde_yaml::to_string(&old_config).unwrap().into_bytes();
        let old_credentials = b"provider_key: old-provider\n".to_vec();
        std::fs::write(&freedom_path, &old_freedom).unwrap();
        std::fs::write(&credentials_path, &old_credentials).unwrap();

        let mut new_config = crate::config::FreedomConfig::default();
        new_config.operator_id = Some("restored".to_string());
        let new_freedom = serde_yaml::to_string(&new_config).unwrap().into_bytes();
        let mut encrypted = CONF_MAGIC.to_vec();
        encrypted.extend_from_slice(&[7_u8; 12]);
        encrypted.extend_from_slice(&[9_u8; 32]);

        let interrupted = Credentials::publish_exact_raw_pair_at_using_fault(
            &freedom_path,
            &credentials_path,
            Some(&new_freedom),
            Some(&encrypted),
            |point| {
                if point == DualFileFaultPoint::CredentialsPublished {
                    anyhow::bail!("injected exact restore crash");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(
            interrupted
                .to_string()
                .contains("injected exact restore crash")
        );
        let rolled_back = crate::config::snapshot_raw_config_pair(&freedom_path).unwrap();
        assert_eq!(
            rolled_back.freedom.as_ref().map(|bytes| bytes.as_slice()),
            Some(old_freedom.as_slice())
        );
        assert_eq!(
            rolled_back
                .credentials
                .as_ref()
                .map(|bytes| bytes.as_slice()),
            Some(old_credentials.as_slice())
        );

        let interrupted = Credentials::publish_exact_raw_pair_at_using_fault(
            &freedom_path,
            &credentials_path,
            Some(&new_freedom),
            Some(&encrypted),
            |point| {
                if point == DualFileFaultPoint::FreedomPublished {
                    anyhow::bail!("injected post-pair crash");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{interrupted:#}").contains("injected post-pair crash"));
        let committed = crate::config::snapshot_raw_config_pair(&freedom_path).unwrap();
        assert_eq!(
            committed.freedom.as_ref().map(|bytes| bytes.as_slice()),
            Some(new_freedom.as_slice())
        );
        assert_eq!(
            committed.credentials.as_ref().map(|bytes| bytes.as_slice()),
            Some(encrypted.as_slice())
        );
        assert!(committed.credentials_encrypted);
        assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_pair_restore_rejects_existing_symlink_target() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let outside = dir.path().join("outside.yaml");
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&outside, "outside: untouched\n").unwrap();
        symlink(&outside, &freedom_path).unwrap();
        let body = serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap();

        let error = Credentials::publish_exact_raw_pair_at(
            &freedom_path,
            &credentials_path,
            Some(body.as_bytes()),
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("never a symlink"));
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "outside: untouched\n"
        );
    }

    #[test]
    fn coherent_pair_reader_blocks_writer_between_freedom_and_credentials() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let mut original_freedom = crate::config::FreedomConfig::default();
        original_freedom.telegram_user_id = Some(111_111_111);
        std::fs::write(
            &freedom_path,
            serde_yaml::to_string(&original_freedom).unwrap(),
        )
        .unwrap();
        Credentials {
            telegram_token: Some(SecretString::from("111111111:old-token")),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();

        let freedom_for_reader = freedom_path.clone();
        let freedom_loaded = Arc::new(Barrier::new(2));
        let release_reader = Arc::new(Barrier::new(2));
        let reader = {
            let freedom_loaded = Arc::clone(&freedom_loaded);
            let release_reader = Arc::clone(&release_reader);
            std::thread::spawn(move || {
                crate::config::load_runtime_config_pair_from_path_with_hook(
                    &freedom_for_reader,
                    move || {
                        freedom_loaded.wait();
                        release_reader.wait();
                    },
                )
                .unwrap()
            })
        };

        freedom_loaded.wait();
        let writer_started = Arc::new(Barrier::new(2));
        let (writer_done, writer_result) = mpsc::channel();
        let writer = {
            let writer_started = Arc::clone(&writer_started);
            let freedom_path = freedom_path.clone();
            let credentials_path = credentials_path.clone();
            std::thread::spawn(move || {
                writer_started.wait();
                Credentials::update_telegram_with_freedom_at(
                    &freedom_path,
                    &credentials_path,
                    |config, credentials| {
                        config.telegram_user_id = Some(222_222_222);
                        credentials.telegram_token =
                            Some(SecretString::from("222222222:new-token"));
                        Ok(())
                    },
                )
                .unwrap();
                writer_done.send(()).unwrap();
            })
        };
        writer_started.wait();
        let writer_finished_early = writer_result
            .recv_timeout(Duration::from_millis(100))
            .is_ok();

        release_reader.wait();
        let pair = reader.join().unwrap();
        assert_eq!(pair.config.telegram_user_id, Some(111_111_111));
        assert_eq!(
            pair.config.telegram_token.as_ref().unwrap().expose(),
            "111111111:old-token"
        );
        assert_eq!(
            pair.credentials.telegram_token.as_ref().unwrap().expose(),
            "111111111:old-token"
        );
        if !writer_finished_early {
            writer_result.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        writer.join().unwrap();
        assert!(
            !writer_finished_early,
            "writer must remain blocked while the pair loader holds its shared boundary"
        );

        let pair = crate::config::load_runtime_config_pair_from_path(&freedom_path).unwrap();
        assert_eq!(pair.config.telegram_user_id, Some(222_222_222));
        assert_eq!(
            pair.credentials.telegram_token.as_ref().unwrap().expose(),
            "222222222:new-token"
        );
    }

    #[test]
    fn coherent_pair_reader_waits_for_pre_journal_legacy_writer() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let mut old_freedom = crate::config::FreedomConfig::default();
        old_freedom.operator_id = Some("old-generation".to_string());
        std::fs::write(&freedom_path, serde_yaml::to_string(&old_freedom).unwrap()).unwrap();
        Credentials {
            provider_key: Some(SecretString::from("old-provider")),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();

        let (credentials_published_tx, credentials_published_rx) = mpsc::channel();
        let (finish_writer_tx, finish_writer_rx) = mpsc::channel();
        let writer_freedom = freedom_path.clone();
        let writer_credentials = credentials_path.clone();
        let writer = std::thread::spawn(move || {
            // Baseline/pre-journal NEOTH lock order and publication order:
            // both legacy locks stay held while credentials lands first and
            // freedom.yaml lands second.
            let _freedom_mutex = crate::config::lock_freedom_update();
            let _credentials_mutex = lock_cred();
            let _freedom_file_lock = crate::util::locked_file::lock_file_blocking(
                &writer_freedom.with_extension("lock"),
                "legacy freedom config",
            )
            .unwrap();
            let _credentials_file_lock = lock_cred_file(&writer_credentials).unwrap();

            let new_credentials = Credentials {
                provider_key: Some(SecretString::from("new-provider")),
                ..Default::default()
            };
            let credentials_body =
                zeroize::Zeroizing::new(serde_yaml::to_string(&new_credentials).unwrap());
            crate::util::atomic_write::atomic_write_private(
                &writer_credentials,
                credentials_body.as_bytes(),
            )
            .unwrap();
            credentials_published_tx.send(()).unwrap();
            finish_writer_rx.recv().unwrap();

            let mut new_freedom = crate::config::FreedomConfig::default();
            new_freedom.operator_id = Some("new-generation".to_string());
            let freedom_body = new_freedom.public_yaml().unwrap();
            crate::util::atomic_write::atomic_write_private(
                &writer_freedom,
                freedom_body.as_bytes(),
            )
            .unwrap();
        });

        credentials_published_rx.recv().unwrap();
        let (reader_tx, reader_rx) = mpsc::channel();
        let reader_path = freedom_path.clone();
        let reader = std::thread::spawn(move || {
            reader_tx
                .send(crate::config::load_runtime_config_pair_from_path(
                    &reader_path,
                ))
                .expect("coherent reader receiver must remain connected");
        });
        assert!(
            reader_rx.recv_timeout(Duration::from_millis(150)).is_err(),
            "coherent reader must wait while the legacy writer exposes its intermediate pair"
        );

        finish_writer_tx.send(()).unwrap();
        writer.join().unwrap();
        let pair = reader_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        reader.join().unwrap();
        assert_eq!(pair.config.operator_id.as_deref(), Some("new-generation"));
        assert_eq!(
            pair.raw_credentials
                .provider_key
                .as_ref()
                .map(SecretString::expose),
            Some("new-provider")
        );
        assert_eq!(
            pair.credentials
                .provider_key
                .as_ref()
                .map(SecretString::expose),
            Some("new-provider")
        );
    }

    #[test]
    fn nested_dual_writer_is_rejected_without_losing_outer_update() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
        )
        .unwrap();
        Credentials::default().write(&credentials_path).unwrap();
        let nested_mutation_called = std::cell::Cell::new(false);

        Credentials::update_with_freedom_at(
            &freedom_path,
            &credentials_path,
            |config, credentials| {
                let nested = Credentials::update_with_freedom_at(
                    &freedom_path,
                    &credentials_path,
                    |nested_config, nested_credentials| {
                        nested_mutation_called.set(true);
                        nested_config.operator_id = Some("inner".to_string());
                        nested_credentials.telegram_token = Some(SecretString::from("inner-token"));
                        Ok(())
                    },
                )
                .unwrap_err();
                assert!(nested.to_string().contains("refusing nested config writer"));
                assert!(!nested_mutation_called.get());

                config.operator_id = Some("outer".to_string());
                credentials.provider_key = Some(SecretString::from("outer-provider"));
                Ok(())
            },
        )
        .unwrap();

        let pair = crate::config::load_runtime_config_pair_from_path(&freedom_path).unwrap();
        assert_eq!(pair.config.operator_id.as_deref(), Some("outer"));
        assert_eq!(
            pair.credentials
                .provider_key
                .as_ref()
                .map(SecretString::expose),
            Some("outer-provider")
        );
        assert!(pair.credentials.telegram_token.is_none());
    }

    #[test]
    fn coherent_pair_or_default_keeps_existing_credentials_without_freedom() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&credentials_path, "provider_key: repair-provider\n").unwrap();

        let pair =
            crate::config::load_runtime_config_pair_from_path_or_default(&freedom_path).unwrap();
        assert_eq!(
            pair.raw_credentials.provider_key.as_ref().unwrap().expose(),
            "repair-provider"
        );
        assert_eq!(
            pair.credentials.provider_key.as_ref().unwrap().expose(),
            "repair-provider"
        );
        assert_eq!(
            pair.config.provider_key.as_ref().unwrap().expose(),
            "repair-provider"
        );
    }

    #[test]
    fn reviewed_dual_update_rejects_newer_freedom_generation_before_mutation() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            "operator_id: reviewed\nfuture_extension: keep-me\n",
        )
        .unwrap();
        std::fs::write(&credentials_path, "provider_key: original-secret\n").unwrap();
        let reviewed_source = std::fs::read(&freedom_path).unwrap();

        crate::config::FreedomConfig::update_at(&freedom_path, |config| {
            config.language_primary = Some("de".to_string());
            Ok(())
        })
        .unwrap();
        let current_freedom = std::fs::read(&freedom_path).unwrap();
        let current_credentials = std::fs::read(&credentials_path).unwrap();
        let mut mutation_ran = false;

        let error = Credentials::update_with_freedom_at_if_source(
            &freedom_path,
            &credentials_path,
            &reviewed_source,
            |_config, credentials| {
                mutation_ran = true;
                credentials.provider_key = Some(SecretString::from("stale-secret"));
                Ok(())
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("changed after its reviewed snapshot")
        );
        assert!(!mutation_ran);
        assert_eq!(std::fs::read(&freedom_path).unwrap(), current_freedom);
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            current_credentials
        );
    }

    #[test]
    fn recovery_rejects_unknown_bytes_and_retains_prepared_journal() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
        )
        .unwrap();
        Credentials {
            telegram_token: Some(SecretString::from("111111111:old-token")),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();

        Credentials::update_with_freedom_at_using_and_fault(
            &freedom_path,
            &credentials_path,
            |freedom, credentials| {
                freedom.telegram_user_id = Some(222_222_222);
                credentials.telegram_token = Some(SecretString::from("222222222:new-token"));
                Ok(())
            },
            Some(|path: &Path, body: &[u8]| {
                crate::util::atomic_write::atomic_write_private(path, body)
                    .map_err(anyhow::Error::from)
            }),
            InlineTelegramTokenPolicy::Preserve,
            None,
            |point| {
                if point == DualFileFaultPoint::CredentialsPublished {
                    anyhow::bail!("injected crash");
                }
                Ok(())
            },
        )
        .unwrap_err();

        crate::util::atomic_write::atomic_write_private(
            &credentials_path,
            b"telegram_token: 333333333:unexpected\n",
        )
        .unwrap();
        let error = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match current config bytes")
        );
        assert!(
            dir.path().join(DUAL_FILE_JOURNAL_NAME).exists(),
            "ambiguous recovery must fail closed and retain forensic state"
        );
    }

    #[test]
    fn telegram_dual_file_update_preserves_unrelated_inline_legacy_secrets() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let mut freedom = crate::config::FreedomConfig::default();
        freedom.provider_key = Some(SecretString::from("legacy-provider"));
        freedom.telegram_token = Some(SecretString::from("111111111:legacy-telegram"));
        freedom.inference.left.key = Some(SecretString::from("legacy-left"));
        freedom.inference.right.key = Some(SecretString::from("legacy-right"));
        freedom.inference.cerebellum.key = Some(SecretString::from("legacy-cerebellum"));
        freedom.inference.default_slot.key = Some(SecretString::from("legacy-default"));
        std::fs::write(&freedom_path, serde_yaml::to_string(&freedom).unwrap()).unwrap();

        Credentials::update_telegram_with_freedom_at(
            &freedom_path,
            &credentials_path,
            |config, credentials| {
                config.telegram_user_id = Some(222_222_222);
                credentials.telegram_token = Some(SecretString::from("222222222:new-telegram"));
                Ok(())
            },
        )
        .unwrap();

        let persisted: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom_path).unwrap()).unwrap();
        assert_eq!(persisted["provider_key"].as_str(), Some("legacy-provider"));
        assert_eq!(
            persisted["inference"]["left"]["key"].as_str(),
            Some("legacy-left")
        );
        assert_eq!(
            persisted["inference"]["right"]["key"].as_str(),
            Some("legacy-right")
        );
        assert_eq!(
            persisted["inference"]["cerebellum"]["key"].as_str(),
            Some("legacy-cerebellum")
        );
        assert_eq!(
            persisted["inference"]["default_slot"]["key"].as_str(),
            Some("legacy-default")
        );
        assert!(persisted["telegram_token"].is_null());
    }

    #[test]
    fn cluster_secret_update_preserves_all_inline_secrets_and_unknown_yaml() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let mut freedom = crate::config::FreedomConfig::default();
        freedom.provider_key = Some(SecretString::from("legacy-provider"));
        freedom.telegram_token = Some(SecretString::from("111111111:legacy-telegram"));
        freedom.inference.left.key = Some(SecretString::from("legacy-left"));
        freedom.inference.right.key = Some(SecretString::from("legacy-right"));
        freedom.inference.cerebellum.key = Some(SecretString::from("legacy-cerebellum"));
        freedom.inference.default_slot.key = Some(SecretString::from("legacy-default"));

        let mut raw = serde_yaml::to_value(&freedom).unwrap();
        raw.as_mapping_mut().unwrap().insert(
            serde_yaml::Value::String("future_extension".to_string()),
            serde_yaml::Value::String("keep-me".to_string()),
        );
        raw["cluster"].as_mapping_mut().unwrap().insert(
            serde_yaml::Value::String("future_transport_option".to_string()),
            serde_yaml::Value::String("nested-keep".to_string()),
        );
        std::fs::write(&freedom_path, serde_yaml::to_string(&raw).unwrap()).unwrap();
        std::fs::write(
            &credentials_path,
            "future_secret: future-credential-keep-me\n",
        )
        .unwrap();

        Credentials::update_with_freedom_at(
            &freedom_path,
            &credentials_path,
            |config, credentials| {
                config.cluster.name = Some("gold-cluster".to_string());
                credentials.cluster_passphrase = Some(SecretString::from("cluster-secret"));
                Ok(())
            },
        )
        .unwrap();

        let persisted: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom_path).unwrap()).unwrap();
        assert_eq!(persisted["provider_key"].as_str(), Some("legacy-provider"));
        assert_eq!(
            persisted["telegram_token"].as_str(),
            Some("111111111:legacy-telegram")
        );
        assert_eq!(
            persisted["inference"]["left"]["key"].as_str(),
            Some("legacy-left")
        );
        assert_eq!(
            persisted["inference"]["right"]["key"].as_str(),
            Some("legacy-right")
        );
        assert_eq!(
            persisted["inference"]["cerebellum"]["key"].as_str(),
            Some("legacy-cerebellum")
        );
        assert_eq!(
            persisted["inference"]["default_slot"]["key"].as_str(),
            Some("legacy-default")
        );
        assert_eq!(persisted["future_extension"].as_str(), Some("keep-me"));
        assert_eq!(
            persisted["cluster"]["future_transport_option"].as_str(),
            Some("nested-keep")
        );
        assert_eq!(persisted["cluster"]["name"].as_str(), Some("gold-cluster"));
        let persisted_credentials: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&credentials_path).unwrap()).unwrap();
        assert_eq!(
            persisted_credentials["future_secret"].as_str(),
            Some("future-credential-keep-me")
        );
        assert_eq!(
            Credentials::load_or_default(&credentials_path)
                .unwrap()
                .cluster_passphrase
                .as_ref()
                .unwrap()
                .expose(),
            "cluster-secret"
        );
    }

    #[test]
    fn dual_file_update_canonicalizes_loop_budget_alias_and_preserves_unknowns() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let mut raw = serde_yaml::to_value(crate::config::FreedomConfig::default()).unwrap();
        raw.as_mapping_mut().unwrap().insert(
            serde_yaml::Value::String("future_extension".to_string()),
            serde_yaml::Value::String("top-level-keep".to_string()),
        );
        let loop_config = raw["loop_config"].as_mapping_mut().unwrap();
        loop_config.remove(serde_yaml::Value::String("tool_call_budget".to_string()));
        loop_config.insert(
            serde_yaml::Value::String("token_budget".to_string()),
            serde_yaml::Value::Number(17_u64.into()),
        );
        loop_config.insert(
            serde_yaml::Value::String("future_loop_option".to_string()),
            serde_yaml::Value::String("nested-keep".to_string()),
        );
        std::fs::write(&freedom_path, serde_yaml::to_string(&raw).unwrap()).unwrap();

        Credentials::update_with_freedom_at(
            &freedom_path,
            &credentials_path,
            |config, credentials| {
                config.cluster.name = Some("alias-upgrade".to_string());
                credentials.cluster_passphrase = Some(SecretString::from("alias-secret"));
                Ok(())
            },
        )
        .unwrap();

        let persisted: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom_path).unwrap()).unwrap();
        assert_eq!(
            persisted["loop_config"]["tool_call_budget"].as_u64(),
            Some(17)
        );
        assert!(
            persisted["loop_config"].get("token_budget").is_none(),
            "the read-only alias must not survive beside its canonical field"
        );
        assert_eq!(
            persisted["loop_config"]["future_loop_option"].as_str(),
            Some("nested-keep")
        );
        assert_eq!(
            persisted["future_extension"].as_str(),
            Some("top-level-keep")
        );
        crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap();
    }

    #[test]
    fn encrypted_credentials_update_preserves_unknown_secret() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let mut freedom = serde_yaml::to_value(crate::config::FreedomConfig::default()).unwrap();
        freedom.as_mapping_mut().unwrap().insert(
            serde_yaml::Value::String("wal".to_string()),
            serde_yaml::from_str("encryption: aes256_gcm_siv\n").unwrap(),
        );
        std::fs::write(&freedom_path, serde_yaml::to_string(&freedom).unwrap()).unwrap();

        let key_path = crate::wal::master_key::master_key_path(dir.path());
        crate::wal::master_key::load_or_init_master_key(&key_path).unwrap();
        let key = crate::wal::master_key::config_subkey_at(dir.path()).unwrap();
        let original =
            "telegram_token: 111111111:old-token\nfuture_secret: encrypted-future-keep-me\n";
        crate::util::atomic_write::atomic_write_private(
            &credentials_path,
            &encrypt_credentials_body(&key, original).unwrap(),
        )
        .unwrap();

        Credentials::update_with_freedom_at(
            &freedom_path,
            &credentials_path,
            |config, credentials| {
                config.cluster.name = Some("encrypted-cluster".to_string());
                credentials.cluster_passphrase =
                    Some(SecretString::from("encrypted-cluster-secret"));
                Ok(())
            },
        )
        .unwrap();

        let encrypted = std::fs::read(&credentials_path).unwrap();
        assert!(encrypted.starts_with(CONF_MAGIC));
        assert!(
            !encrypted
                .windows("encrypted-future-keep-me".len())
                .any(|window| window == b"encrypted-future-keep-me")
        );
        let plaintext = zeroize::Zeroizing::new(
            decrypt_credentials_body(&key, &encrypted).expect("decrypt updated credentials"),
        );
        let persisted: serde_yaml::Value = serde_yaml::from_str(&plaintext).unwrap();
        assert_eq!(
            persisted["future_secret"].as_str(),
            Some("encrypted-future-keep-me")
        );
        assert_eq!(
            persisted["cluster_passphrase"].as_str(),
            Some("encrypted-cluster-secret")
        );
    }

    #[test]
    fn concurrent_update_at_both_preserved() {
        // Ten barrier-synced threads each setting a different field via
        // update_at on the same path. At the end, both the first writer's
        // field AND subsequent writers' fields must all be present — no
        // silent lost-update.
        use std::sync::{Arc, Barrier};
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("concurrent.yaml"));
        const N: usize = 10;
        let barrier = Arc::new(Barrier::new(N));

        // Each thread writes a unique discord_bot_token last-writer-wins is
        // acceptable here; what must NOT happen is for any write to
        // corrupt the file or for a load failure to go undetected.
        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let p = Arc::clone(&path);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                Credentials::update_at(&p, move |c| {
                    c.irc_nick = Some(format!("bot-{i}"));
                    Ok(())
                })
                .expect("concurrent update_at must not return Err");
            }));
        }
        for h in handles {
            h.join().expect("thread must not panic");
        }
        // File must be loadable and non-empty after all concurrent writes.
        let loaded = Credentials::load_or_default(&path).unwrap();
        assert!(
            loaded.irc_nick.is_some(),
            "concurrent updates must leave a valid credential in the file"
        );
    }

    #[test]
    fn roundtrip_via_write_then_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        let original = Credentials {
            provider_key: Some(SecretString::from("sk-roundtrip")),
            telegram_token: None,
            ..Default::default()
        };
        original.write(&path).unwrap();
        let loaded = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            loaded.provider_key.as_ref().unwrap().expose(),
            "sk-roundtrip"
        );
        assert!(loaded.telegram_token.is_none());
    }

    fn legacy_telegram_freedom_yaml(backend: &str, inline_token: Option<&str>) -> String {
        let token = inline_token
            .map(|value| format!("telegram_token: {value}\n"))
            .unwrap_or_default();
        format!(
            "secrets_backend: {backend}\ntelegram_user_id: 424242\n{token}future_extension:\n  nested: preserve-me\n"
        )
    }

    fn telegram_account_id() -> crate::channels::registry::ChannelAccountId {
        "primary".parse().expect("canonical test account id")
    }

    fn committed_keychain_telegram_pair(allowed_user_id: u64) -> (String, &'static [u8]) {
        (
            format!(
                "secrets_backend: keychain\nchannel_accounts:\n  telegram:\n    primary:\n      allowed_user_id: {allowed_user_id}\nfuture_extension: preserve\n"
            ),
            b"channel_accounts:\n  telegram:\n    primary:\n      token: null\nfuture_secret: preserve\n",
        )
    }

    fn assert_cleanup_refused_without_pair_rewrite(
        allowed_user_id: u64,
        dynamic_token: Option<&str>,
    ) {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let (freedom_before, credentials_before) =
            committed_keychain_telegram_pair(allowed_user_id);
        std::fs::write(&freedom_path, &freedom_before).unwrap();
        std::fs::write(&credentials_path, credentials_before).unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        let account_id = telegram_account_id();
        let dynamic_key = crate::config::keychain::telegram_account_token_key(&account_id);
        store
            .set("telegram_token", &SecretString::from("legacy-must-remain"))
            .unwrap();
        if let Some(dynamic_token) = dynamic_token {
            store
                .set(&dynamic_key, &SecretString::from(dynamic_token))
                .unwrap();
        }

        let error = Credentials::migrate_legacy_telegram_to_account_at_using_fault_and_store(
            &freedom_path,
            &credentials_path,
            account_id,
            Some(&store),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("already configured")
                || error.to_string().contains("no non-blank dynamic token"),
            "unexpected cleanup refusal: {error:#}"
        );
        assert_eq!(
            store.get("telegram_token").unwrap().unwrap().expose(),
            "legacy-must-remain"
        );
        assert_eq!(
            std::fs::read(&freedom_path).unwrap(),
            freedom_before.as_bytes()
        );
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            credentials_before
        );
    }

    struct FailIfTouchedStore;

    impl crate::config::keychain::SecretStore for FailIfTouchedStore {
        fn get(&self, _key: &str) -> Result<Option<SecretString>> {
            anyhow::bail!("file-mode migration must not read the OS store")
        }

        fn set(&self, _key: &str, _value: &SecretString) -> Result<()> {
            anyhow::bail!("file-mode migration must not write the OS store")
        }

        fn delete(&self, _key: &str) -> Result<()> {
            anyhow::bail!("file-mode migration must not delete from the OS store")
        }

        fn backend_name(&self) -> &'static str {
            "fail-if-touched"
        }
    }

    struct FailLegacyDeleteOnceStore {
        inner: crate::config::keychain::InMemorySecretStore,
        fail_legacy_delete: std::sync::Mutex<bool>,
    }

    impl Default for FailLegacyDeleteOnceStore {
        fn default() -> Self {
            Self {
                inner: crate::config::keychain::InMemorySecretStore::default(),
                fail_legacy_delete: std::sync::Mutex::new(true),
            }
        }
    }

    impl crate::config::keychain::SecretStore for FailLegacyDeleteOnceStore {
        fn get(&self, key: &str) -> Result<Option<SecretString>> {
            self.inner.get(key)
        }

        fn set(&self, key: &str, value: &SecretString) -> Result<()> {
            self.inner.set(key, value)
        }

        fn delete(&self, key: &str) -> Result<()> {
            if key == "telegram_token" {
                let mut fail = self
                    .fail_legacy_delete
                    .lock()
                    .expect("delete-fault store lock poisoned");
                if *fail {
                    *fail = false;
                    anyhow::bail!("injected one-time legacy Telegram delete failure");
                }
            }
            self.inner.delete(key)
        }

        fn backend_name(&self) -> &'static str {
            "fail-legacy-delete-once"
        }
    }

    #[test]
    fn legacy_telegram_file_migration_uses_inline_precedence_and_preserves_unknown_yaml() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            legacy_telegram_freedom_yaml("file", Some("inline-wins")),
        )
        .unwrap();
        std::fs::write(
            &credentials_path,
            "telegram_token: credentials-loses\nfuture_secret:\n  nested: preserve-too\n",
        )
        .unwrap();

        Credentials::migrate_legacy_telegram_to_account_at_using_fault_and_store(
            &freedom_path,
            &credentials_path,
            telegram_account_id(),
            Some(&FailIfTouchedStore),
            |_| Ok(()),
        )
        .unwrap();

        let persisted_freedom: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom_path).unwrap()).unwrap();
        assert!(persisted_freedom["telegram_token"].is_null());
        assert!(persisted_freedom["telegram_user_id"].is_null());
        assert_eq!(
            persisted_freedom["future_extension"]["nested"].as_str(),
            Some("preserve-me")
        );
        let credentials = Credentials::load_or_default(&credentials_path).unwrap();
        assert!(credentials.telegram_token.is_none());
        assert_eq!(
            credentials
                .channel_accounts
                .telegram
                .get(&telegram_account_id())
                .and_then(|entry| entry.token.as_ref())
                .map(SecretString::expose),
            Some("inline-wins")
        );
        let raw_credentials: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&credentials_path).unwrap()).unwrap();
        assert_eq!(
            raw_credentials["future_secret"]["nested"].as_str(),
            Some("preserve-too")
        );
        let pair = crate::config::load_runtime_config_pair_from_path(&freedom_path).unwrap();
        let accounts = pair.authenticated_telegram_accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].token().expose(), "inline-wins");
    }

    #[test]
    fn legacy_telegram_keychain_migration_uses_singleton_only_after_file_sources() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            legacy_telegram_freedom_yaml("keychain", None),
        )
        .unwrap();
        std::fs::write(&credentials_path, "future_secret: preserve\n").unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        let account_id = telegram_account_id();
        let dynamic_key = crate::config::keychain::telegram_account_token_key(&account_id);
        store
            .set(&dynamic_key, &SecretString::from("dynamic-before"))
            .unwrap();
        store
            .set("telegram_token", &SecretString::from("legacy-store-token"))
            .unwrap();

        Credentials::migrate_legacy_telegram_to_account_at_using_fault_and_store(
            &freedom_path,
            &credentials_path,
            account_id.clone(),
            Some(&store),
            |_| Ok(()),
        )
        .unwrap();

        let credentials = Credentials::load_or_default(&credentials_path).unwrap();
        assert!(credentials.telegram_token.is_none());
        assert!(
            credentials
                .channel_accounts
                .telegram
                .get(&account_id)
                .expect("keychain account placeholder")
                .token
                .is_none(),
            "keychain mode persists an explicit null placeholder, never a file token"
        );
        assert_eq!(
            store.get(&dynamic_key).unwrap().unwrap().expose(),
            "legacy-store-token"
        );
        assert!(store.get("telegram_token").unwrap().is_none());
        let mut effective = credentials.clone();
        crate::config::keychain::supplement_telegram_account_tokens(&mut effective, &store)
            .unwrap();
        assert_eq!(
            effective
                .channel_accounts
                .telegram
                .get(&account_id)
                .and_then(|entry| entry.token.as_ref())
                .map(SecretString::expose),
            Some("legacy-store-token")
        );
        let raw_credentials = std::fs::read_to_string(&credentials_path).unwrap();
        assert!(raw_credentials.contains("future_secret"));
    }

    #[test]
    fn legacy_telegram_keychain_prefers_inline_then_credentials_then_singleton() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            legacy_telegram_freedom_yaml("keychain", Some("inline-wins")),
        )
        .unwrap();
        std::fs::write(&credentials_path, "telegram_token: credentials-loses\n").unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        let account_id = telegram_account_id();
        let dynamic_key = crate::config::keychain::telegram_account_token_key(&account_id);
        store
            .set("telegram_token", &SecretString::from("store-loses"))
            .unwrap();

        Credentials::migrate_legacy_telegram_to_account_at_using_fault_and_store(
            &freedom_path,
            &credentials_path,
            account_id.clone(),
            Some(&store),
            |_| Ok(()),
        )
        .unwrap();

        assert_eq!(
            store.get(&dynamic_key).unwrap().unwrap().expose(),
            "inline-wins"
        );
        assert!(store.get("telegram_token").unwrap().is_none());
        let credentials = Credentials::load_or_default(&credentials_path).unwrap();
        assert!(credentials.telegram_token.is_none());
        assert!(
            credentials
                .channel_accounts
                .telegram
                .get(&account_id)
                .expect("keychain account placeholder")
                .token
                .is_none()
        );
    }

    #[test]
    fn legacy_telegram_keychain_uses_credentials_before_singleton() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            legacy_telegram_freedom_yaml("keychain", None),
        )
        .unwrap();
        std::fs::write(&credentials_path, "telegram_token: credentials-wins\n").unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        let account_id = telegram_account_id();
        let dynamic_key = crate::config::keychain::telegram_account_token_key(&account_id);
        store
            .set("telegram_token", &SecretString::from("store-loses"))
            .unwrap();

        Credentials::migrate_legacy_telegram_to_account_at_using_fault_and_store(
            &freedom_path,
            &credentials_path,
            account_id,
            Some(&store),
            |_| Ok(()),
        )
        .unwrap();

        assert_eq!(
            store.get(&dynamic_key).unwrap().unwrap().expose(),
            "credentials-wins"
        );
        assert!(store.get("telegram_token").unwrap().is_none());
        assert!(
            Credentials::load_or_default(&credentials_path)
                .unwrap()
                .telegram_token
                .is_none()
        );
    }

    #[test]
    fn legacy_telegram_first_publication_failure_restores_dynamic_snapshot_and_pair() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let freedom_before = legacy_telegram_freedom_yaml("keychain", Some("inline-target"));
        let credentials_before = b"future_secret: preserve\n".to_vec();
        std::fs::write(&freedom_path, &freedom_before).unwrap();
        std::fs::write(&credentials_path, &credentials_before).unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        let account_id = telegram_account_id();
        let dynamic_key = crate::config::keychain::telegram_account_token_key(&account_id);
        store
            .set(&dynamic_key, &SecretString::from("dynamic-before"))
            .unwrap();
        store
            .set("telegram_token", &SecretString::from("legacy-must-remain"))
            .unwrap();

        let error = Credentials::migrate_legacy_telegram_to_account_at_using_fault_and_store(
            &freedom_path,
            &credentials_path,
            account_id,
            Some(&store),
            |point| {
                if point == DualFileFaultPoint::CredentialsPublished {
                    anyhow::bail!("injected first publication failure");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(!dual_file_target_publication_crossed(&error));
        assert_eq!(
            store.get(&dynamic_key).unwrap().unwrap().expose(),
            "dynamic-before"
        );
        assert_eq!(
            store.get("telegram_token").unwrap().unwrap().expose(),
            "legacy-must-remain"
        );
        assert!(dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());

        let recovered = crate::config::load_runtime_config_diagnostic_snapshot_using_store(
            &freedom_path,
            Some(&store),
        )
        .unwrap()
        .config
        .expect("recovered legacy Telegram config");
        assert!(recovered.channel_accounts.telegram.is_empty());
        assert_eq!(recovered.telegram_user_id, Some(424242));
        assert_eq!(
            std::fs::read_to_string(&freedom_path).unwrap(),
            freedom_before
        );
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            credentials_before
        );
        assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());
    }

    #[test]
    fn legacy_telegram_after_boundary_fault_retains_dynamic_target_for_recovery() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            legacy_telegram_freedom_yaml("keychain", Some("inline-target")),
        )
        .unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        let account_id = telegram_account_id();
        let dynamic_key = crate::config::keychain::telegram_account_token_key(&account_id);
        store
            .set(&dynamic_key, &SecretString::from("dynamic-before"))
            .unwrap();
        store
            .set("telegram_token", &SecretString::from("legacy-stale"))
            .unwrap();

        let error = Credentials::migrate_legacy_telegram_to_account_at_using_fault_and_store(
            &freedom_path,
            &credentials_path,
            account_id.clone(),
            Some(&store),
            |point| {
                if point == DualFileFaultPoint::FreedomPublished {
                    anyhow::bail!("injected after-boundary failure");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(dual_file_target_publication_crossed(&error));
        assert_eq!(
            store.get(&dynamic_key).unwrap().unwrap().expose(),
            "inline-target"
        );
        assert!(dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());

        let recovered = crate::config::load_runtime_config_diagnostic_snapshot_using_store(
            &freedom_path,
            Some(&store),
        )
        .unwrap()
        .config
        .expect("recovered migrated Telegram config");
        assert!(recovered.telegram_token.is_none());
        assert!(recovered.telegram_user_id.is_none());
        assert!(
            recovered
                .channel_accounts
                .telegram
                .contains_key(&account_id)
        );
        assert!(
            Credentials::load_or_default(&credentials_path)
                .unwrap()
                .channel_accounts
                .telegram
                .get(&account_id)
                .expect("recovered keychain placeholder")
                .token
                .is_none()
        );
        assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());
    }

    #[test]
    fn legacy_telegram_post_commit_cleanup_retries_without_rewriting_pair() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            legacy_telegram_freedom_yaml("keychain", Some("inline-target")),
        )
        .unwrap();
        let store = FailLegacyDeleteOnceStore::default();
        let account_id = telegram_account_id();
        let dynamic_key = crate::config::keychain::telegram_account_token_key(&account_id);
        store
            .set("telegram_token", &SecretString::from("legacy-stale"))
            .unwrap();

        let error = Credentials::migrate_legacy_telegram_to_account_at_using_fault_and_store(
            &freedom_path,
            &credentials_path,
            account_id.clone(),
            Some(&store),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("already committed"));
        assert!(store.get("telegram_token").unwrap().is_some());
        assert_eq!(
            store.get(&dynamic_key).unwrap().unwrap().expose(),
            "inline-target"
        );
        let freedom_after_commit = std::fs::read(&freedom_path).unwrap();
        let credentials_after_commit = std::fs::read(&credentials_path).unwrap();

        // A stale scalar singleton must not be reintroduced into a mapped
        // runtime generation while its delete retry is pending.
        let raw_credentials = Credentials::load_or_default(&credentials_path).unwrap();
        let mut effective_credentials = raw_credentials.clone();
        crate::config::keychain::supplement_from_store(&mut effective_credentials, &store).unwrap();
        crate::config::keychain::supplement_telegram_account_tokens(
            &mut effective_credentials,
            &store,
        )
        .unwrap();
        assert!(effective_credentials.telegram_token.is_none());
        let config =
            crate::config::FreedomConfig::load_public_from_path_unlocked(&freedom_path).unwrap();
        let pair = crate::config::RuntimeConfigPair {
            config,
            raw_credentials,
            credentials: effective_credentials,
        };
        let accounts = pair.authenticated_telegram_accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].token().expose(), "inline-target");

        Credentials::migrate_legacy_telegram_to_account_at_using_fault_and_store(
            &freedom_path,
            &credentials_path,
            account_id,
            Some(&store),
            |_| Ok(()),
        )
        .unwrap();
        assert!(store.get("telegram_token").unwrap().is_none());
        assert_eq!(std::fs::read(&freedom_path).unwrap(), freedom_after_commit);
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            credentials_after_commit
        );
    }

    #[test]
    fn legacy_telegram_cleanup_rejects_zero_allowed_user_id_without_delete() {
        assert_cleanup_refused_without_pair_rewrite(0, Some("valid-dynamic-token"));
    }

    #[test]
    fn legacy_telegram_cleanup_rejects_missing_dynamic_token_without_delete() {
        assert_cleanup_refused_without_pair_rewrite(424242, None);
    }

    #[test]
    fn legacy_telegram_cleanup_rejects_blank_dynamic_token_without_delete() {
        assert_cleanup_refused_without_pair_rewrite(424242, Some("   "));
    }

    fn legacy_ssh_freedom_yaml(password: &str) -> String {
        format!(
            "operator_id: alex\n\
             future_extension:\n\
             \u{20}\u{20}keep: true\n\
             ssh_tunnels:\n\
             \u{20}\u{20}- endpoint:\n\
             \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}host: bastion.example\n\
             \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}username: alex\n\
             \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}auth:\n\
             \u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}\u{20}password: {password}\n\
             \u{20}\u{20}\u{20}\u{20}remote_host: 127.0.0.1\n\
             \u{20}\u{20}\u{20}\u{20}remote_port: 5432\n"
        )
    }

    fn test_ssh_tunnel(password: &str) -> crate::transport::ssh_config::SshTunnelConfig {
        crate::transport::ssh_config::SshTunnelConfig {
            endpoint: crate::transport::ssh_config::SshEndpoint {
                host: "keychain.example".into(),
                port: 22,
                username: "alex".into(),
                auth: crate::transport::ssh_config::SshAuth::Password(SecretString::from(password)),
            },
            remote_host: "127.0.0.1".into(),
            remote_port: 5432,
            local_port: 0,
            jump_hosts: Vec::new(),
            max_retries: 5,
            retry_delay: std::time::Duration::from_secs(2),
        }
    }

    fn assert_keychain_ssh_authority_is_not_persisted(
        authority: Vec<crate::transport::ssh_config::SshTunnelConfig>,
    ) {
        use crate::config::keychain::SecretStore as _;

        let authority_passwords = authority
            .iter()
            .filter_map(|tunnel| match &tunnel.endpoint.auth {
                crate::transport::ssh_config::SshAuth::Password(secret) => {
                    Some(secret.expose_secret().to_owned())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let legacy_password = ephemeral_test_secret();
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            format!(
                "secrets_backend: keychain\n{}",
                legacy_ssh_freedom_yaml(&legacy_password)
            ),
        )
        .unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        let keychain_credentials = Credentials {
            ssh_tunnels: Some(authority.clone()),
            ..Default::default()
        };
        let secret = crate::config::keychain::ssh_tunnels_secret(&keychain_credentials)
            .unwrap()
            .unwrap();
        store.set("ssh_tunnels", &secret).unwrap();

        assert_eq!(
            Credentials::migrate_legacy_ssh_tunnels_at_using_fault_and_store(
                &freedom_path,
                &credentials_path,
                Some(&store),
                |_| Ok(()),
            )
            .unwrap(),
            LegacySshMigrationOutcome::Migrated,
        );

        let public = std::fs::read_to_string(&freedom_path).unwrap();
        assert!(!public.contains("ssh_tunnels"));
        assert!(!public.contains(&legacy_password));
        let raw = Credentials::load_or_default(&credentials_path).unwrap();
        assert!(
            raw.ssh_tunnels.is_none(),
            "keychain authority must not be copied into credentials.yaml"
        );
        if credentials_path.exists() {
            let private = std::fs::read_to_string(&credentials_path).unwrap();
            assert!(!private.contains("ssh_tunnels"));
            for password in &authority_passwords {
                assert!(
                    !private.contains(password),
                    "keychain password leaked into credentials.yaml"
                );
            }
        }
        let mut effective = raw;
        crate::config::keychain::supplement_from_store(&mut effective, &store).unwrap();
        assert_eq!(effective.ssh_tunnels, Some(authority));
    }

    #[test]
    fn keychain_ssh_authority_wins_without_leaking_into_credentials_file() {
        let password = ephemeral_test_secret();
        assert_keychain_ssh_authority_is_not_persisted(vec![test_ssh_tunnel(&password)]);
    }

    #[test]
    fn keychain_empty_ssh_authority_disables_legacy_without_file_copy() {
        assert_keychain_ssh_authority_is_not_persisted(Vec::new());
    }

    #[test]
    fn unavailable_keychain_aborts_legacy_ssh_migration_without_writing() {
        struct UnavailableKeychain;

        impl crate::config::keychain::SecretStore for UnavailableKeychain {
            fn get(&self, key: &str) -> Result<Option<SecretString>> {
                if key == "ssh_tunnels" {
                    anyhow::bail!("injected keychain read failure for {key}");
                }
                Ok(None)
            }

            fn set(&self, _key: &str, _value: &SecretString) -> Result<()> {
                anyhow::bail!("unexpected keychain write")
            }

            fn delete(&self, _key: &str) -> Result<()> {
                anyhow::bail!("unexpected keychain delete")
            }

            fn backend_name(&self) -> &'static str {
                "unavailable-keychain (test)"
            }
        }

        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let legacy_password = ephemeral_test_secret();
        let freedom_before = format!(
            "secrets_backend: keychain\n{}",
            legacy_ssh_freedom_yaml(&legacy_password)
        )
        .into_bytes();
        let credentials_before = b"future_secret: preserve-exactly\n".to_vec();
        std::fs::write(&freedom_path, &freedom_before).unwrap();
        std::fs::write(&credentials_path, &credentials_before).unwrap();

        let error = Credentials::migrate_legacy_ssh_tunnels_at_using_fault_and_store(
            &freedom_path,
            &credentials_path,
            Some(&UnavailableKeychain),
            |_| Ok(()),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("read SSH tunnel credential bundle from keychain"));
        assert_eq!(std::fs::read(&freedom_path).unwrap(), freedom_before);
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            credentials_before
        );
        assert!(
            !dir.path().join(DUAL_FILE_JOURNAL_NAME).exists(),
            "authority resolution must fail before preparing publication"
        );
    }

    #[test]
    fn legacy_ssh_tunnels_migrate_atomically_and_remain_effective() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let password = ephemeral_test_secret();
        std::fs::write(&freedom_path, legacy_ssh_freedom_yaml(&password)).unwrap();

        let effective = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap();
        assert_eq!(effective.ssh_tunnels.len(), 1);
        match &effective.ssh_tunnels[0].endpoint.auth {
            crate::transport::ssh_config::SshAuth::Password(secret) => {
                assert!(
                    secret.expose_secret() == password.as_str(),
                    "effective SSH password did not match the migrated value"
                );
            }
            _ => panic!("unexpected migrated SSH auth variant"),
        }

        let public = std::fs::read_to_string(&freedom_path).unwrap();
        assert!(!public.contains("ssh_tunnels"));
        assert!(!public.contains(&password));
        assert!(public.contains("future_extension"));
        let credentials = Credentials::load_or_default(&credentials_path).unwrap();
        assert_eq!(
            credentials
                .ssh_tunnels
                .as_ref()
                .expect("dedicated SSH authority")
                .len(),
            1
        );
        assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());
    }

    #[test]
    fn dedicated_empty_ssh_authority_wins_and_removes_legacy_block() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let legacy_password = ephemeral_test_secret();
        std::fs::write(&freedom_path, legacy_ssh_freedom_yaml(&legacy_password)).unwrap();
        Credentials {
            ssh_tunnels: Some(Vec::new()),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();

        let effective = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap();
        assert!(effective.ssh_tunnels.is_empty());
        let public = std::fs::read_to_string(&freedom_path).unwrap();
        assert!(!public.contains("ssh_tunnels"));
        assert!(!public.contains(&legacy_password));
        let credentials = Credentials::load_or_default(&credentials_path).unwrap();
        assert_eq!(credentials.ssh_tunnels, Some(Vec::new()));
    }

    #[test]
    fn dedicated_ssh_authority_removes_malformed_legacy_block_without_parsing_it() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            "operator_id: alex\nssh_tunnels:\n  - endpoint: definitely-not-a-map\n",
        )
        .unwrap();
        Credentials {
            ssh_tunnels: Some(Vec::new()),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();

        let effective = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap();
        assert!(effective.ssh_tunnels.is_empty());
        let public = std::fs::read_to_string(&freedom_path).unwrap();
        assert!(!public.contains("ssh_tunnels"));
        assert!(!public.contains("definitely-not-a-map"));
        assert_eq!(
            Credentials::load_or_default(&credentials_path)
                .unwrap()
                .ssh_tunnels,
            Some(Vec::new())
        );
    }

    #[test]
    fn malformed_legacy_ssh_tunnels_write_nothing() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let freedom_before =
            b"operator_id: alex\nssh_tunnels:\n  - endpoint: definitely-not-a-map\n".to_vec();
        let credentials_before = b"future_secret: preserve-exactly\n".to_vec();
        std::fs::write(&freedom_path, &freedom_before).unwrap();
        std::fs::write(&credentials_path, &credentials_before).unwrap();

        let error = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("legacy freedom.yaml::ssh_tunnels")
        );
        assert_eq!(std::fs::read(&freedom_path).unwrap(), freedom_before);
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            credentials_before
        );
        assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());
    }

    #[test]
    fn legacy_ssh_migration_recovers_every_prepared_crash_image() {
        for crash_point in [
            DualFileFaultPoint::JournalPrepared,
            DualFileFaultPoint::CredentialsPublished,
            DualFileFaultPoint::FreedomPublished,
            DualFileFaultPoint::DirectorySynced,
        ] {
            let dir = tempdir().unwrap();
            let freedom_path = dir.path().join("freedom.yaml");
            let credentials_path = dir.path().join("credentials.yaml");
            let password = ephemeral_test_secret();
            std::fs::write(&freedom_path, legacy_ssh_freedom_yaml(&password)).unwrap();
            std::fs::write(
                &credentials_path,
                "future_secret: preserve-through-recovery\n",
            )
            .unwrap();

            let error = Credentials::migrate_legacy_ssh_tunnels_at_using_fault(
                &freedom_path,
                &credentials_path,
                |point| {
                    if point == crash_point {
                        anyhow::bail!("injected migration crash");
                    }
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(
                dual_file_target_publication_crossed(&error),
                matches!(
                    crash_point,
                    DualFileFaultPoint::FreedomPublished | DualFileFaultPoint::DirectorySynced
                )
            );
            assert!(format!("{error:#}").contains("injected migration crash"));

            let effective = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap();
            assert_eq!(effective.ssh_tunnels.len(), 1);
            let public = std::fs::read_to_string(&freedom_path).unwrap();
            assert!(!public.contains("ssh_tunnels"));
            assert!(!public.contains(&password));
            let private = std::fs::read_to_string(&credentials_path).unwrap();
            assert!(private.contains("future_secret"));
            assert!(private.contains(&password));
            assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());
        }
    }

    #[test]
    fn legacy_ssh_migration_preserves_unknown_credential_fields() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let password = ephemeral_test_secret();
        std::fs::write(&freedom_path, legacy_ssh_freedom_yaml(&password)).unwrap();
        std::fs::write(&credentials_path, "future_secret:\n  nested: keep-me\n").unwrap();

        crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap();
        let raw = std::fs::read_to_string(&credentials_path).unwrap();
        assert!(raw.contains("future_secret"));
        assert!(raw.contains("keep-me"));
        assert!(raw.contains("ssh_tunnels"));
        assert!(raw.contains(&format!("password: {password}")));
    }

    #[test]
    fn public_config_update_preserves_dedicated_ssh_authority_on_slim_builds() {
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
        )
        .unwrap();
        let password = ephemeral_test_secret();
        Credentials {
            ssh_tunnels: Some(vec![crate::transport::ssh_config::SshTunnelConfig {
                endpoint: crate::transport::ssh_config::SshEndpoint {
                    host: "bastion.example".into(),
                    port: 22,
                    username: "alex".into(),
                    auth: crate::transport::ssh_config::SshAuth::Password(SecretString::from(
                        password.clone(),
                    )),
                },
                remote_host: "127.0.0.1".into(),
                remote_port: 5432,
                local_port: 0,
                jump_hosts: Vec::new(),
                max_retries: 5,
                retry_delay: Duration::from_secs(2),
            }]),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();
        let credential_before = std::fs::read(&credentials_path).unwrap();

        crate::config::FreedomConfig::update_at(&freedom_path, |config| {
            config.operator_id = Some("updated".into());
            Ok(())
        })
        .unwrap();

        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            credential_before,
            "public-only RMW must not touch the private SSH authority"
        );
        let effective = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap();
        assert_eq!(effective.operator_id.as_deref(), Some("updated"));
        assert_eq!(effective.ssh_tunnels.len(), 1);
        match &effective.ssh_tunnels[0].endpoint.auth {
            crate::transport::ssh_config::SshAuth::Password(secret) => {
                assert!(
                    secret.expose_secret() == password.as_str(),
                    "effective SSH password changed during public-only update"
                );
            }
            _ => panic!("unexpected effective SSH auth variant"),
        }
    }

    #[test]
    fn public_config_update_migrates_legacy_ssh_before_read_modify_write() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let password = ephemeral_test_secret();
        std::fs::write(&freedom_path, legacy_ssh_freedom_yaml(&password)).unwrap();

        crate::config::FreedomConfig::update_at(&freedom_path, |config| {
            config.operator_id = Some("updated".into());
            Ok(())
        })
        .unwrap();

        let public = std::fs::read_to_string(&freedom_path).unwrap();
        assert!(!public.contains("ssh_tunnels"));
        assert!(!public.contains(&password));
        assert!(public.contains("future_extension"));
        let credentials = Credentials::load_or_default(&credentials_path).unwrap();
        let tunnels = credentials.ssh_tunnels.expect("migrated SSH authority");
        assert_eq!(tunnels.len(), 1);
        match &tunnels[0].endpoint.auth {
            crate::transport::ssh_config::SshAuth::Password(secret) => {
                assert!(
                    secret.expose_secret() == password.as_str(),
                    "read-modify-write migration changed the SSH password"
                );
            }
            _ => panic!("unexpected migrated SSH auth variant"),
        }
    }

    #[test]
    fn migration_verification_accepts_present_ssh_and_rejects_absent_or_null() {
        let field = vec!["ssh_tunnels".to_string()];
        let present: Credentials = serde_yaml::from_str(
            "ssh_tunnels:\n  - endpoint:\n      host: bastion.example\n      username: alex\n      auth:\n        password: secret\n    remote_host: 127.0.0.1\n    remote_port: 5432\n",
        )
        .unwrap();
        assert!(present.missing_migration_fields(&field).unwrap().is_empty());

        let disabled = Credentials {
            ssh_tunnels: Some(Vec::new()),
            ..Default::default()
        };
        assert!(
            disabled
                .missing_migration_fields(&field)
                .unwrap()
                .is_empty(),
            "Some([]) is a present authoritative disabled state"
        );
        assert_eq!(
            Credentials::default()
                .missing_migration_fields(&field)
                .unwrap(),
            field
        );
    }

    #[test]
    fn matrix_policy_roundtrip_and_secure_default() {
        let legacy: Credentials = serde_yaml::from_str(
            "matrix_homeserver: https://matrix.example.org\n\
             matrix_user_id: '@bot:example.org'\n",
        )
        .unwrap();
        assert!(
            legacy.matrix_requires_encryption(),
            "files predating the policy field must default to encrypted rooms"
        );

        let configured = Credentials {
            matrix_homeserver: Some("https://matrix.example.org".into()),
            matrix_user_id: Some("@bot:example.org".into()),
            matrix_allowed_user_id: Some("@alice:example.org".into()),
            matrix_allowed_room_ids: Some("!safe:example.org,!ops:example.org".into()),
            matrix_require_encryption: Some(false),
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&configured).unwrap();
        let restored: Credentials = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            restored.matrix_allowed_user_id.as_deref(),
            Some("@alice:example.org")
        );
        assert_eq!(
            restored.matrix_allowed_room_ids.as_deref(),
            Some("!safe:example.org,!ops:example.org")
        );
        assert!(!restored.matrix_requires_encryption());
        assert!(!restored.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn written_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        let c = Credentials {
            provider_key: Some(SecretString::from("sk-x")),
            telegram_token: None,
            ..Default::default()
        };
        c.write(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    fn named_telegram_account(value: &str) -> crate::channels::registry::ChannelAccountId {
        value.parse().expect("canonical test account id")
    }

    fn mapped_telegram_freedom_yaml(backend: &str) -> String {
        format!(
            "secrets_backend: {backend}\nchannel_accounts:\n  telegram:\n    ops_a:\n      allowed_user_id: 11\nfuture_extension:\n  preserve: true\n"
        )
    }

    fn mapped_telegram_credentials_yaml(token: Option<&str>) -> String {
        let token = token
            .map(|token| format!("      token: {token}\n"))
            .unwrap_or_else(|| "      token: null\n".to_owned());
        format!(
            "channel_accounts:\n  telegram:\n    ops_a:\n{token}future_secret:\n  preserve: exact\n"
        )
    }

    #[test]
    fn telegram_account_upsert_file_candidate_preserves_other_account_and_unknown_yaml() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&freedom_path, mapped_telegram_freedom_yaml("file")).unwrap();
        std::fs::write(
            &credentials_path,
            mapped_telegram_credentials_yaml(Some("ops-a-token")),
        )
        .unwrap();

        let prepared = Credentials::prepare_telegram_account_upsert_at_using_store(
            &freedom_path,
            &credentials_path,
            named_telegram_account("ops_b"),
            22,
            SecretString::from("ops-b-token"),
            Some(&FailIfTouchedStore),
        )
        .unwrap();
        assert_eq!(prepared.account_id().as_str(), "ops_b");
        let candidate = prepared
            .candidate_pair()
            .authenticated_telegram_accounts()
            .unwrap();
        assert_eq!(candidate.len(), 2);
        assert!(candidate.iter().any(|account| {
            account.channel_ref().account_id.as_str() == "ops_a"
                && account.token().expose() == "ops-a-token"
        }));
        assert!(candidate.iter().any(|account| {
            account.channel_ref().account_id.as_str() == "ops_b"
                && account.token().expose() == "ops-b-token"
        }));

        Credentials::commit_prepared_telegram_account_upsert_at_using_fault_and_store(
            prepared,
            Some(&FailIfTouchedStore),
            |_| Ok(()),
        )
        .unwrap();
        let pair = crate::config::load_runtime_config_pair_from_path(&freedom_path).unwrap();
        assert_eq!(pair.authenticated_telegram_accounts().unwrap().len(), 2);
        let raw = std::fs::read_to_string(&credentials_path).unwrap();
        assert!(raw.contains("preserve: exact"));
        assert!(raw.contains("ops-a-token"));
        assert!(raw.contains("ops-b-token"));
    }

    #[test]
    fn telegram_account_upsert_refuses_zero_or_blank_before_any_file_or_store_access() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let zero = match Credentials::prepare_telegram_account_upsert_at_using_store(
            &freedom_path,
            &credentials_path,
            named_telegram_account("ops_b"),
            0,
            SecretString::from("token"),
            Some(&FailIfTouchedStore),
        ) {
            Ok(_) => panic!("zero sender must be refused"),
            Err(error) => error,
        };
        assert!(zero.to_string().contains("nonzero"));
        let blank = match Credentials::prepare_telegram_account_upsert_at_using_store(
            &freedom_path,
            &credentials_path,
            named_telegram_account("ops_b"),
            22,
            SecretString::from(" \t "),
            Some(&FailIfTouchedStore),
        ) {
            Ok(_) => panic!("blank token must be refused"),
            Err(error) => error,
        };
        assert!(blank.to_string().contains("non-blank"));
        assert!(!freedom_path.exists());
        assert!(!credentials_path.exists());
    }

    #[test]
    fn telegram_account_upsert_keychain_uses_dynamic_key_and_null_yaml_placeholder() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&freedom_path, mapped_telegram_freedom_yaml("keychain")).unwrap();
        std::fs::write(&credentials_path, mapped_telegram_credentials_yaml(None)).unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        let ops_a_key =
            crate::config::keychain::telegram_account_token_key(&named_telegram_account("ops_a"));
        let ops_b_key =
            crate::config::keychain::telegram_account_token_key(&named_telegram_account("ops_b"));
        store
            .set(&ops_a_key, &SecretString::from("ops-a-token"))
            .unwrap();

        let prepared = Credentials::prepare_telegram_account_upsert_at_using_store(
            &freedom_path,
            &credentials_path,
            named_telegram_account("ops_b"),
            22,
            SecretString::from("ops-b-token"),
            Some(&store),
        )
        .unwrap();
        assert_eq!(
            prepared
                .candidate_pair()
                .authenticated_telegram_accounts()
                .unwrap()
                .len(),
            2
        );
        Credentials::commit_prepared_telegram_account_upsert_at_using_fault_and_store(
            prepared,
            Some(&store),
            |_| Ok(()),
        )
        .unwrap();

        assert_eq!(
            store.get(&ops_a_key).unwrap().unwrap().expose(),
            "ops-a-token"
        );
        assert_eq!(
            store.get(&ops_b_key).unwrap().unwrap().expose(),
            "ops-b-token"
        );
        assert!(store.get("telegram_token").unwrap().is_none());
        let persisted: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&credentials_path).unwrap()).unwrap();
        assert!(persisted["channel_accounts"]["telegram"]["ops_b"]["token"].is_null());
        assert_eq!(
            persisted["future_secret"]["preserve"].as_str(),
            Some("exact")
        );
    }

    #[test]
    fn telegram_account_upsert_commit_refuses_selected_or_unselected_dynamic_drift() {
        for (changed_account, changed_token) in
            [("ops_b", "raced-selected"), ("ops_a", "raced-other")]
        {
            let dir = tempdir().unwrap();
            let freedom_path = dir.path().join("freedom.yaml");
            let credentials_path = dir.path().join("credentials.yaml");
            let freedom_before = mapped_telegram_freedom_yaml("keychain");
            let credentials_before = mapped_telegram_credentials_yaml(None);
            std::fs::write(&freedom_path, &freedom_before).unwrap();
            std::fs::write(&credentials_path, &credentials_before).unwrap();
            let store = crate::config::keychain::InMemorySecretStore::default();
            let ops_a_key = crate::config::keychain::telegram_account_token_key(
                &named_telegram_account("ops_a"),
            );
            store
                .set(&ops_a_key, &SecretString::from("ops-a-token"))
                .unwrap();
            let prepared = Credentials::prepare_telegram_account_upsert_at_using_store(
                &freedom_path,
                &credentials_path,
                named_telegram_account("ops_b"),
                22,
                SecretString::from("ops-b-token"),
                Some(&store),
            )
            .unwrap();
            let changed_key = crate::config::keychain::telegram_account_token_key(
                &named_telegram_account(changed_account),
            );
            store
                .set(&changed_key, &SecretString::from(changed_token))
                .unwrap();

            let error =
                Credentials::commit_prepared_telegram_account_upsert_at_using_fault_and_store(
                    prepared,
                    Some(&store),
                    |_| Ok(()),
                )
                .unwrap_err();
            assert!(error.to_string().contains("reviewed candidate"));
            assert_eq!(
                std::fs::read_to_string(&freedom_path).unwrap(),
                freedom_before
            );
            assert_eq!(
                std::fs::read_to_string(&credentials_path).unwrap(),
                credentials_before
            );
            assert_eq!(
                store.get(&changed_key).unwrap().unwrap().expose(),
                changed_token
            );
        }
    }

    #[test]
    fn telegram_account_upsert_restores_selected_dynamic_snapshot_before_publication_boundary() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let freedom_before = mapped_telegram_freedom_yaml("keychain");
        let credentials_before = mapped_telegram_credentials_yaml(None);
        std::fs::write(&freedom_path, &freedom_before).unwrap();
        std::fs::write(&credentials_path, &credentials_before).unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        let ops_a_key =
            crate::config::keychain::telegram_account_token_key(&named_telegram_account("ops_a"));
        let ops_b_key =
            crate::config::keychain::telegram_account_token_key(&named_telegram_account("ops_b"));
        store
            .set(&ops_a_key, &SecretString::from("ops-a-token"))
            .unwrap();
        store
            .set(&ops_b_key, &SecretString::from("ops-b-before"))
            .unwrap();
        let prepared = Credentials::prepare_telegram_account_upsert_at_using_store(
            &freedom_path,
            &credentials_path,
            named_telegram_account("ops_b"),
            22,
            SecretString::from("ops-b-target"),
            Some(&store),
        )
        .unwrap();
        let error = Credentials::commit_prepared_telegram_account_upsert_at_using_fault_and_store(
            prepared,
            Some(&store),
            |point| {
                if point == DualFileFaultPoint::CredentialsPublished {
                    anyhow::bail!("injected first publication failure")
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(!dual_file_target_publication_crossed(&error));
        assert_eq!(
            store.get(&ops_b_key).unwrap().unwrap().expose(),
            "ops-b-before"
        );
        let _ = crate::config::load_runtime_config_diagnostic_snapshot_using_store(
            &freedom_path,
            Some(&store),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&freedom_path).unwrap(),
            freedom_before
        );
        assert_eq!(
            std::fs::read_to_string(&credentials_path).unwrap(),
            credentials_before
        );
    }

    #[test]
    fn telegram_account_upsert_after_boundary_fault_retains_target_for_recovery() {
        let dir = tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&freedom_path, mapped_telegram_freedom_yaml("keychain")).unwrap();
        std::fs::write(&credentials_path, mapped_telegram_credentials_yaml(None)).unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        let ops_a = named_telegram_account("ops_a");
        let ops_b = named_telegram_account("ops_b");
        let ops_a_key = crate::config::keychain::telegram_account_token_key(&ops_a);
        let ops_b_key = crate::config::keychain::telegram_account_token_key(&ops_b);
        store
            .set(&ops_a_key, &SecretString::from("ops-a-token"))
            .unwrap();
        store
            .set(&ops_b_key, &SecretString::from("ops-b-before"))
            .unwrap();
        let prepared = Credentials::prepare_telegram_account_upsert_at_using_store(
            &freedom_path,
            &credentials_path,
            ops_b.clone(),
            22,
            SecretString::from("ops-b-target"),
            Some(&store),
        )
        .unwrap();

        let error = Credentials::commit_prepared_telegram_account_upsert_at_using_fault_and_store(
            prepared,
            Some(&store),
            |point| {
                if point == DualFileFaultPoint::FreedomPublished {
                    anyhow::bail!("injected after-boundary publication failure")
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(dual_file_target_publication_crossed(&error));
        assert_eq!(
            store.get(&ops_b_key).unwrap().unwrap().expose(),
            "ops-b-target"
        );
        assert!(dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());

        let _ = crate::config::load_runtime_config_diagnostic_snapshot_using_store(
            &freedom_path,
            Some(&store),
        )
        .unwrap();
        assert!(!dir.path().join(DUAL_FILE_JOURNAL_NAME).exists());
        let raw_credentials = Credentials::load_or_default(&credentials_path).unwrap();
        assert!(
            raw_credentials
                .channel_accounts
                .telegram
                .get(&ops_b)
                .expect("recovered keychain account placeholder")
                .token
                .is_none()
        );
        let mut effective_credentials = raw_credentials.clone();
        crate::config::keychain::supplement_telegram_account_tokens(
            &mut effective_credentials,
            &store,
        )
        .unwrap();
        let config =
            crate::config::FreedomConfig::load_public_from_path_unlocked(&freedom_path).unwrap();
        let pair = crate::config::RuntimeConfigPair {
            config,
            raw_credentials,
            credentials: effective_credentials,
        };
        let accounts = pair.authenticated_telegram_accounts().unwrap();
        assert_eq!(accounts.len(), 2);
        let selected = accounts
            .iter()
            .find(|account| account.channel_ref().account_id == ops_b)
            .expect("recovered selected Telegram account");
        assert_eq!(selected.allowed_user_id(), 22);
        assert_eq!(selected.token().expose(), "ops-b-target");
    }

    fn retirement_two_account_fixture(backend: &str) -> (String, String) {
        (
            format!("secrets_backend: {backend}\nchannel_accounts:\n  telegram:\n    ops_a:\n      allowed_user_id: 11\n    ops_b:\n      allowed_user_id: 22\nfuture_extension:\n  preserve: true\n"),
            "channel_accounts:\n  telegram:\n    ops_a:\n      token: ops-a-token\n    ops_b:\n      token: ops-b-token\nfuture_secret:\n  preserve: exact\n".to_owned(),
        )
    }

    #[test]
    fn retirement_add_edit_remove_readd_changes_a_generation_and_preserves_b() {
        let dir = tempdir().unwrap();
        let fp = dir.path().join("freedom.yaml");
        let cp = dir.path().join("credentials.yaml");
        let (freedom, credentials) = retirement_two_account_fixture("file");
        std::fs::write(&fp, freedom).unwrap();
        std::fs::write(&cp, credentials).unwrap();
        let a = named_telegram_account("ops_a");
        let b = named_telegram_account("ops_b");
        let add = Credentials::prepare_telegram_account_upsert_at(
            &fp,
            &cp,
            a.clone(),
            11,
            SecretString::from("same-token"),
        )
        .unwrap();
        Credentials::commit_prepared_telegram_account_upsert_at(add).unwrap();
        let first = crate::config::load_runtime_config_pair_from_path(&fp)
            .unwrap()
            .config
            .channel_accounts
            .telegram[&a]
            .incarnation
            .clone()
            .unwrap();
        let edit = Credentials::prepare_telegram_account_upsert_at(
            &fp,
            &cp,
            a.clone(),
            11,
            SecretString::from("rotated-token"),
        )
        .unwrap();
        Credentials::commit_prepared_telegram_account_upsert_at(edit).unwrap();
        assert_eq!(
            crate::config::load_runtime_config_pair_from_path(&fp)
                .unwrap()
                .config
                .channel_accounts
                .telegram[&a]
                .incarnation
                .as_ref(),
            Some(&first)
        );
        let remove = Credentials::prepare_telegram_account_removal_at(&fp, &cp, a.clone()).unwrap();
        Credentials::commit_prepared_telegram_account_removal_at(remove).unwrap();
        let removed = crate::config::load_runtime_config_pair_from_path(&fp).unwrap();
        assert!(!removed.config.channel_accounts.telegram.contains_key(&a));
        assert_eq!(
            removed.credentials.channel_accounts.telegram[&b]
                .token
                .as_ref()
                .unwrap()
                .expose(),
            "ops-b-token"
        );
        assert!(
            std::fs::read_to_string(&fp)
                .unwrap()
                .contains("preserve: true")
        );
        assert!(
            std::fs::read_to_string(&cp)
                .unwrap()
                .contains("preserve: exact")
        );
        let readd = Credentials::prepare_telegram_account_upsert_at(
            &fp,
            &cp,
            a.clone(),
            11,
            SecretString::from("same-token"),
        )
        .unwrap();
        Credentials::commit_prepared_telegram_account_upsert_at(readd).unwrap();
        assert_ne!(
            crate::config::load_runtime_config_pair_from_path(&fp)
                .unwrap()
                .config
                .channel_accounts
                .telegram[&a]
                .incarnation
                .as_ref(),
            Some(&first)
        );
    }

    #[test]
    fn retirement_final_account_and_cas_conflict_are_fail_closed() {
        let dir = tempdir().unwrap();
        let fp = dir.path().join("freedom.yaml");
        let cp = dir.path().join("credentials.yaml");
        std::fs::write(&fp, mapped_telegram_freedom_yaml("file")).unwrap();
        std::fs::write(&cp, mapped_telegram_credentials_yaml(Some("ops-a-token"))).unwrap();
        let a = named_telegram_account("ops_a");
        let prepared =
            Credentials::prepare_telegram_account_removal_at(&fp, &cp, a.clone()).unwrap();
        std::fs::write(
            &fp,
            format!("{}raced: true\n", mapped_telegram_freedom_yaml("file")),
        )
        .unwrap();
        assert!(
            Credentials::commit_prepared_telegram_account_removal_at(prepared)
                .unwrap_err()
                .to_string()
                .contains("reviewed retirement")
        );
        assert!(
            crate::config::load_runtime_config_pair_from_path(&fp)
                .unwrap()
                .authenticated_telegram_accounts()
                .unwrap()
                .len()
                == 1
        );
        let prepared = Credentials::prepare_telegram_account_removal_at(&fp, &cp, a).unwrap();
        Credentials::commit_prepared_telegram_account_removal_at(prepared).unwrap();
        let pair = crate::config::load_runtime_config_pair_from_path(&fp).unwrap();
        assert!(pair.config.channel_accounts.telegram.is_empty());
        assert!(
            pair.config.telegram_token.is_none()
                && pair.config.telegram_user_id.is_none()
                && pair.credentials.telegram_token.is_none()
        );
        assert!(pair.authenticated_telegram_accounts().unwrap().is_empty());
    }

    #[test]
    fn keychain_retirement_fault_boundaries_preserve_b_and_recover_coherent_pairs() {
        for (fault, crossed) in [
            (DualFileFaultPoint::CredentialsPublished, false),
            (DualFileFaultPoint::FreedomPublished, true),
        ] {
            let dir = tempdir().unwrap();
            let fp = dir.path().join("freedom.yaml");
            let cp = dir.path().join("credentials.yaml");
            let (freedom, _) = retirement_two_account_fixture("keychain");
            std::fs::write(&fp, freedom).unwrap();
            std::fs::write(&cp, "channel_accounts:\n  telegram:\n    ops_a: { token: null }\n    ops_b: { token: null }\n").unwrap();
            let store = crate::config::keychain::InMemorySecretStore::default();
            let a = named_telegram_account("ops_a");
            let b = named_telegram_account("ops_b");
            let ak = crate::config::keychain::telegram_account_token_key(&a);
            let bk = crate::config::keychain::telegram_account_token_key(&b);
            store.set(&ak, &SecretString::from("a")).unwrap();
            store.set(&bk, &SecretString::from("b")).unwrap();
            let prepared = Credentials::prepare_telegram_account_removal_at_using_store(
                &fp,
                &cp,
                a.clone(),
                Some(&store),
            )
            .unwrap();
            let error =
                Credentials::commit_prepared_telegram_account_removal_at_using_fault_and_store(
                    prepared,
                    Some(&store),
                    |point| {
                        if point == fault {
                            anyhow::bail!("fault")
                        } else {
                            Ok(())
                        }
                    },
                )
                .unwrap_err();
            assert_eq!(dual_file_target_publication_crossed(&error), crossed);
            assert_eq!(store.get(&bk).unwrap().unwrap().expose(), "b");
            let _ = crate::config::load_runtime_config_diagnostic_snapshot_using_store(
                &fp,
                Some(&store),
            )
            .unwrap();
            let config = crate::config::FreedomConfig::load_public_from_path_unlocked(&fp).unwrap();
            let raw = Credentials::load_or_default(&cp).unwrap();
            assert_eq!(config.channel_accounts.telegram.contains_key(&a), !crossed);
            assert_eq!(raw.channel_accounts.telegram.contains_key(&a), !crossed);
            assert!(
                config.channel_accounts.telegram.contains_key(&b)
                    && raw.channel_accounts.telegram.contains_key(&b)
            );
        }
    }
}

#[cfg(test)]
mod slack_account_transaction_tests {
    use super::*;
    use crate::channels::registry::ChannelAccountId;

    fn account(name: &str) -> ChannelAccountId {
        ChannelAccountId::new(name).unwrap()
    }

    fn seed() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let public = dir.path().join("freedom.yaml");
        let private = dir.path().join("credentials.yaml");
        std::fs::write(
            &public,
            "secrets_backend: file\nfuture_public:\n  keep: exactly\n",
        )
        .unwrap();
        std::fs::write(&private, "future_private:\n  keep: exactly\n").unwrap();
        (dir, public, private)
    }

    fn prepare(public: &Path, private: &Path, name: &str, bot: &str) -> PreparedSlackAccountUpsert {
        Credentials::prepare_slack_account_upsert_at(
            public,
            private,
            account(name),
            "U123ABC".into(),
            SecretString::from(bot),
            SecretString::from("xapp-fixture"),
        )
        .unwrap()
    }

    fn snapshots(public: &Path, private: &Path) -> (Vec<u8>, Vec<u8>) {
        (
            std::fs::read(public).unwrap(),
            std::fs::read(private).unwrap(),
        )
    }

    #[test]
    fn slack_upsert_persists_two_accounts_and_rotation_preserves_incarnation_and_extensions() {
        let (_dir, public, private) = seed();
        Credentials::commit_prepared_slack_account_upsert_at(
            prepare(&public, &private, "work", "xoxb-work"),
            "TTEAM1",
        )
        .unwrap();
        let before = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
        let incarnation = before.config.channel_accounts.slack[&account("work")]
            .incarnation
            .clone()
            .unwrap();
        let candidate = prepare(&public, &private, "personal", "xoxb-personal");
        assert_eq!(candidate.account_id(), &account("personal"));
        assert_eq!(
            candidate
                .candidate_pair()
                .authenticated_slack_accounts()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(before.credentials.channel_accounts.slack.len(), 1);
        Credentials::commit_prepared_slack_account_upsert_at(candidate, "TTEAM1").unwrap();
        Credentials::commit_prepared_slack_account_upsert_at(
            prepare(&public, &private, "work", "xoxb-rotated"),
            "TTEAM1",
        )
        .unwrap();
        let after = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
        assert_eq!(after.authenticated_slack_accounts().unwrap().len(), 2);
        assert_eq!(
            after.config.channel_accounts.slack[&account("work")]
                .incarnation
                .as_ref(),
            Some(&incarnation)
        );
        assert_eq!(
            after.credentials.channel_accounts.slack[&account("personal")]
                .bot_token
                .as_ref()
                .unwrap()
                .expose(),
            "xoxb-personal"
        );
        assert_eq!(
            after.credentials.channel_accounts.slack[&account("work")]
                .bot_token
                .as_ref()
                .unwrap()
                .expose(),
            "xoxb-rotated"
        );
        let public_text = std::fs::read_to_string(&public).unwrap();
        assert!(public_text.contains("future_public:") && public_text.contains("keep: exactly"));
        assert!(!public_text.contains("xoxb-") && !public_text.contains("xapp-"));
        assert!(
            std::fs::read_to_string(&private)
                .unwrap()
                .contains("future_private:")
        );
    }

    #[test]
    fn slack_workspace_binding_reuses_only_the_same_known_team() {
        let (_dir, public, private) = seed();
        Credentials::commit_prepared_slack_account_upsert_at(
            prepare(&public, &private, "work", "xoxb-first"),
            "TONE1",
        )
        .unwrap();
        let first = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
        let first_incarnation = first.config.channel_accounts.slack[&account("work")]
            .incarnation
            .clone();
        Credentials::commit_prepared_slack_account_upsert_at(
            Credentials::prepare_slack_account_rotation_at(
                &public,
                &private,
                account("work"),
                SecretString::from("xoxb-same"),
                SecretString::from("xapp-same"),
            )
            .unwrap(),
            "TONE1",
        )
        .unwrap();
        let same = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
        assert_eq!(
            same.config.channel_accounts.slack[&account("work")].incarnation,
            first_incarnation
        );
        Credentials::commit_prepared_slack_account_upsert_at(
            Credentials::prepare_slack_account_rotation_at(
                &public,
                &private,
                account("work"),
                SecretString::from("xoxb-other"),
                SecretString::from("xapp-other"),
            )
            .unwrap(),
            "TTWO2",
        )
        .unwrap();
        let crossed = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
        assert_ne!(
            crossed.config.channel_accounts.slack[&account("work")].incarnation,
            first_incarnation
        );
        assert_eq!(
            crossed.config.channel_accounts.slack[&account("work")]
                .team_id
                .as_deref(),
            Some("TTWO2")
        );
    }

    #[test]
    fn slack_unknown_workspace_and_invalid_observation_never_reuse_authority() {
        let (_dir, public, private) = seed();
        std::fs::write(
            &private,
            "slack_bot_token: bot\nslack_app_token: app\nslack_allowed_user_id: U123ABC\n",
        )
        .unwrap();
        Credentials::migrate_legacy_slack_to_account_at(&public, &private, account("work"))
            .unwrap();
        let migrated = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
        let old = migrated.config.channel_accounts.slack[&account("work")]
            .incarnation
            .clone();
        assert!(
            migrated.config.channel_accounts.slack[&account("work")]
                .team_id
                .is_none()
        );
        let invalid = Credentials::prepare_slack_account_rotation_at(
            &public,
            &private,
            account("work"),
            SecretString::from("xoxb-next"),
            SecretString::from("xapp-next"),
        )
        .unwrap();
        let before = snapshots(&public, &private);
        assert!(
            Credentials::commit_prepared_slack_account_upsert_at(invalid, "workspace").is_err()
        );
        assert_eq!(snapshots(&public, &private), before);
        Credentials::commit_prepared_slack_account_upsert_at(
            Credentials::prepare_slack_account_rotation_at(
                &public,
                &private,
                account("work"),
                SecretString::from("xoxb-next"),
                SecretString::from("xapp-next"),
            )
            .unwrap(),
            "TBOUND1",
        )
        .unwrap();
        let bound = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
        assert_ne!(
            bound.config.channel_accounts.slack[&account("work")].incarnation,
            old
        );
    }

    #[test]
    fn slack_known_workspace_without_an_incarnation_mints_one_at_verified_commit() {
        let (_dir, public, private) = seed();
        std::fs::write(
            &public,
            "secrets_backend: file\nchannel_accounts:\n  slack:\n    work:\n      allowed_user_id: U123ABC\n      team_id: TTEAM1\n",
        )
        .unwrap();
        std::fs::write(
            &private,
            "channel_accounts:\n  slack:\n    work:\n      bot_token: xoxb-before\n      app_token: xapp-before\n",
        )
        .unwrap();
        Credentials::commit_prepared_slack_account_upsert_at(
            Credentials::prepare_slack_account_rotation_at(
                &public,
                &private,
                account("work"),
                SecretString::from("xoxb-after"),
                SecretString::from("xapp-after"),
            )
            .unwrap(),
            "TTEAM1",
        )
        .unwrap();
        assert!(
            crate::config::load_runtime_config_pair_from_path(&public)
                .unwrap()
                .config
                .channel_accounts
                .slack[&account("work")]
                .incarnation
                .is_some()
        );
    }

    #[test]
    fn slack_upsert_cas_rejects_either_raw_file_drift_without_overwrite() {
        for change_public in [true, false] {
            let (_dir, public, private) = seed();
            let candidate = prepare(&public, &private, "work", "xoxb-candidate");
            let changed = if change_public { &public } else { &private };
            let mut text = std::fs::read_to_string(changed).unwrap();
            text.push_str("concurrent_extension: keep\n");
            std::fs::write(changed, text).unwrap();
            let before = snapshots(&public, &private);
            assert!(
                Credentials::commit_prepared_slack_account_upsert_at(candidate, "TTEAM1").is_err()
            );
            assert_eq!(snapshots(&public, &private), before);
        }
    }

    #[test]
    fn slack_retirement_removes_persisted_keys_and_readd_mints_a_new_generation() {
        let (_dir, public, private) = seed();
        for name in ["work", "personal"] {
            Credentials::commit_prepared_slack_account_upsert_at(
                prepare(&public, &private, name, name),
                "TTEAM1",
            )
            .unwrap();
        }
        let before = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
        let retired = before.config.channel_accounts.slack[&account("work")]
            .incarnation
            .clone()
            .unwrap();
        let survivor = before.config.channel_accounts.slack[&account("personal")].clone();
        let mut raw: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&public).unwrap()).unwrap();
        raw["channel_accounts"]["slack"]["personal"]["future_policy"] =
            serde_yaml::Value::String("retain".into());
        std::fs::write(&public, serde_yaml::to_string(&raw).unwrap()).unwrap();
        let candidate =
            Credentials::prepare_slack_account_removal_at(&public, &private, account("work"))
                .unwrap();
        assert_eq!(candidate.account_id(), &account("work"));
        Credentials::commit_prepared_slack_account_removal_at(candidate).unwrap();
        let after = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
        assert_eq!(after.authenticated_slack_accounts().unwrap().len(), 1);
        assert!(
            !after
                .config
                .channel_accounts
                .slack
                .contains_key(&account("work"))
        );
        assert!(
            !after
                .raw_credentials
                .channel_accounts
                .slack
                .contains_key(&account("work"))
        );
        assert_eq!(
            after.config.channel_accounts.slack[&account("personal")].incarnation,
            survivor.incarnation
        );
        assert_eq!(
            after.credentials.channel_accounts.slack[&account("personal")]
                .bot_token
                .as_ref()
                .unwrap()
                .expose(),
            "personal"
        );
        assert!(
            std::fs::read_to_string(&public)
                .unwrap()
                .contains("future_policy: retain")
        );
        Credentials::commit_prepared_slack_account_upsert_at(
            prepare(&public, &private, "work", "new-token"),
            "TTEAM1",
        )
        .unwrap();
        let readded = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
        assert_ne!(
            readded.config.channel_accounts.slack[&account("work")]
                .incarnation
                .as_ref(),
            Some(&retired)
        );
    }

    #[test]
    fn slack_retirement_rejects_unknown_account_and_stale_prepared_pair() {
        let (_dir, public, private) = seed();
        Credentials::commit_prepared_slack_account_upsert_at(
            prepare(&public, &private, "work", "work"),
            "TTEAM1",
        )
        .unwrap();
        let before = snapshots(&public, &private);
        assert!(
            Credentials::prepare_slack_account_removal_at(&public, &private, account("missing"))
                .is_err()
        );
        assert_eq!(snapshots(&public, &private), before);
        let candidate =
            Credentials::prepare_slack_account_removal_at(&public, &private, account("work"))
                .unwrap();
        Credentials::commit_prepared_slack_account_upsert_at(
            prepare(&public, &private, "personal", "personal"),
            "TTEAM1",
        )
        .unwrap();
        let updated = snapshots(&public, &private);
        assert!(Credentials::commit_prepared_slack_account_removal_at(candidate).is_err());
        assert_eq!(snapshots(&public, &private), updated);
        assert_eq!(
            crate::config::load_runtime_config_pair_from_path(&public)
                .unwrap()
                .authenticated_slack_accounts()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn slack_legacy_migration_moves_only_complete_triple_and_keeps_private_extensions() {
        for complete in [false, true] {
            let (_dir, public, private) = seed();
            let legacy = if complete {
                "slack_bot_token: bot\nslack_app_token: app\nslack_allowed_user_id: U123ABC\nfuture_private: retained\n"
            } else {
                "slack_bot_token: bot\nslack_allowed_user_id: U123ABC\nfuture_private: retained\n"
            };
            std::fs::write(&private, legacy).unwrap();
            let before = snapshots(&public, &private);
            let result = Credentials::migrate_legacy_slack_to_account_at(
                &public,
                &private,
                account("explicit"),
            );
            if !complete {
                assert!(result.is_err());
                assert_eq!(snapshots(&public, &private), before);
                continue;
            }
            result.unwrap();
            let pair = crate::config::load_runtime_config_pair_from_path(&public).unwrap();
            let accounts = pair.authenticated_slack_accounts().unwrap();
            assert_eq!(accounts.len(), 1);
            assert_eq!(accounts[0].channel_ref().account_id, account("explicit"));
            assert_eq!(accounts[0].bot_token().expose(), "bot");
            assert_eq!(accounts[0].app_token().expose(), "app");
            assert_eq!(accounts[0].allowed_user_id(), "U123ABC");
            assert!(pair.raw_credentials.slack_bot_token.is_none());
            assert!(pair.raw_credentials.slack_app_token.is_none());
            assert!(pair.raw_credentials.slack_allowed_user_id.is_none());
            assert!(
                std::fs::read_to_string(&private)
                    .unwrap()
                    .contains("future_private: retained")
            );
            let migrated = snapshots(&public, &private);
            assert!(
                Credentials::migrate_legacy_slack_to_account_at(
                    &public,
                    &private,
                    account("other")
                )
                .is_err()
            );
            assert_eq!(snapshots(&public, &private), migrated);
        }
    }

    #[test]
    fn slack_file_lifecycle_rejects_keychain_without_touching_either_file() {
        let (_dir, public, private) = seed();
        std::fs::write(
            &public,
            "secrets_backend: keychain\nfuture_public: retained\n",
        )
        .unwrap();
        std::fs::write(
            &private,
            "slack_bot_token: bot\nslack_app_token: app\nslack_allowed_user_id: U123ABC\n",
        )
        .unwrap();
        let before = snapshots(&public, &private);
        let result = Credentials::prepare_slack_account_upsert_at(
            &public,
            &private,
            account("work"),
            "U123ABC".into(),
            SecretString::from("new-bot"),
            SecretString::from("new-app"),
        );
        assert!(result.is_err());
        assert!(
            Credentials::prepare_slack_account_removal_at(&public, &private, account("work"))
                .is_err()
        );
        assert!(
            Credentials::migrate_legacy_slack_to_account_at(&public, &private, account("work"))
                .is_err()
        );
        assert_eq!(snapshots(&public, &private), before);
    }
}
