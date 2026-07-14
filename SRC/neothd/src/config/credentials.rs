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

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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

/// Default file: `<neoth_home>/credentials.yaml`.
pub fn default_path() -> PathBuf {
    super::FreedomConfig::default_neoth_home().join("credentials.yaml")
}

/// GOLD-ADAPT-CRYPTO-04 #5 — magic prefix marking an AEAD-encrypted
/// credentials.yaml. Distinct from the WAL `ENC_MAGIC` so the two at-rest
/// formats can never be confused. Layout: `CONF_MAGIC ‖ nonce(12) ‖ ciphertext`.
const CONF_MAGIC: &[u8] = b"NEOTH_CONF_ENCv1\n";

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

/// Shape of `credentials.yaml`. All fields optional so an operator who
/// hasn't configured a provider key (e.g. claude-cli OAuth only) doesn't
/// need to keep an empty key around.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Credentials {
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
    /// `freedom.yaml`. `save_public_to_default_path` strips those slot keys
    /// from `freedom.yaml`, so credentials.yaml is the only place they can be
    /// configured; on load they are merged back onto the matching slot.
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
    /// GOLD-PROG-16 — Discord bot token (sent as `Bot <token>`). When present
    /// alongside a provider, the daemon spawns the Discord gateway receive loop
    /// (`DiscordChannel::run`). The inbound adapter needs only the bot token —
    /// the gateway surfaces the channels itself.
    pub discord_bot_token: Option<SecretString>,
    /// GOLD-FEAT-10 — base URL of the operator's local `signal-cli` HTTP
    /// daemon (e.g. `http://127.0.0.1:8080`). When present alongside
    /// `signal_phone_number`, the daemon spawns the Signal receive loop
    /// (`SignalChannel::run`). Not a secret (a loopback URL) but lives here
    /// with the other channel config.
    pub signal_cli_url: Option<String>,
    /// GOLD-FEAT-10 — our registered Signal number (`+E.164`). Used as the
    /// `number` on every signal-cli send + the `/v1/receive/{number}` path.
    pub signal_phone_number: Option<String>,
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
    /// Legacy value written by the removed guessed Keet transport. Retained
    /// only so older credentials files round-trip and `channel remove keet`
    /// can erase it. It is never treated as usable authentication material.
    pub keet_seed_phrase: Option<SecretString>,
    /// Legacy value written by the removed guessed Pear HTTP bridge. Retained
    /// only for backward-compatible parsing and explicit cleanup; never used
    /// for a request.
    pub pears_bearer_token: Option<SecretString>,
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
}

impl Credentials {
    /// Secure default for existing credentials files that predate the field.
    pub fn matrix_requires_encryption(&self) -> bool {
        self.matrix_require_encryption.unwrap_or(true)
    }

    /// Read from `path`. Missing file returns `Credentials::default()`
    /// (a clean install has no secrets yet). Bad YAML is a hard error —
    /// silent fallback would mask a typo that disables an operator's
    /// configured provider.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        // B17 TOCTOU fix: single syscall, no TOCTOU window between exists() and
        // read(). Only ErrorKind::NotFound returns the default empty store; every
        // other error (permissions, I/O, keychain, corrupt YAML) propagates with
        // full path context so the caller can fail-closed.
        let raw = match std::fs::read(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(e).with_context(|| format!("read credentials at {}", path.display()));
            }
        };
        // CRYPTO-04 #5 — decrypt when at-rest-encrypted; else legacy plaintext.
        let body: String = if raw.starts_with(CONF_MAGIC) {
            let home = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let key = crate::wal::master_key::config_subkey_at(home).ok_or_else(|| {
                anyhow::anyhow!(
                    "credentials at {} are encrypted but the master key is unavailable \
                     (restore it: neoth security restore-master-key)",
                    path.display()
                )
            })?;
            decrypt_credentials_body(&key, &raw)
                .with_context(|| format!("decrypt credentials at {}", path.display()))?
        } else {
            String::from_utf8(raw)
                .with_context(|| format!("credentials at {} are not valid UTF-8", path.display()))?
        };
        let c: Self = serde_yaml::from_str(&body)
            .with_context(|| format!("parse credentials YAML at {}", path.display()))?;
        Ok(c)
    }

    /// Load the effective credential set for the configured secrets backend.
    /// File values win; a keychain backend only fills fields that remain empty.
    /// Store failures preserve the documented emergency-file fallback and are
    /// surfaced by downstream feature-specific credential validation.
    pub fn load_effective(path: &Path, backend: crate::config::SecretsBackend) -> Result<Self> {
        let mut credentials = Self::load_or_default(path)?;
        if backend == crate::config::SecretsBackend::Keychain {
            match crate::config::keychain::open_store() {
                Ok(store) => {
                    if let Err(error) = crate::config::keychain::supplement_from_store(
                        &mut credentials,
                        store.as_ref(),
                    ) {
                        tracing::warn!(
                            %error,
                            "OS keychain unavailable; using credentials.yaml emergency values"
                        );
                    }
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

    /// Write atomically mode 0600 (unix) or icacls-locked (windows).
    /// Skips entirely when both fields are `None` so a credentials-free
    /// install doesn't leave an empty placeholder file behind.
    pub fn write(&self, path: &Path) -> Result<()> {
        if self.is_empty() {
            // Nothing to write. Remove any existing stub to keep the
            // directory honest.
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create credentials dir {}", parent.display()))?;
        }
        // YAML round-trip is intentional (we DO want the plaintext in
        // the file on disk — that's the whole point of credentials.yaml).
        // What's at risk is the in-memory `String` until we return:
        // it's a plain `String`, not a `SecretString`, so it isn't
        // zeroized automatically. Wipe it before drop so a memory
        // disclosure bug elsewhere can't pull recently-written secrets
        // off the heap.
        use zeroize::Zeroize;
        let mut body = serde_yaml::to_string(self).context("serialise credentials")?;
        // CRYPTO-04 #5 — encrypt at rest when the operator enabled at-rest
        // encryption. FAIL-CLOSED: enabled-but-no-key refuses to write plaintext
        // secrets (more sensitive than WAL frames).
        let home = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let result = if crate::wal::master_key::wal_encryption_enabled_at(home)
            .context("resolve WAL/config at-rest encryption policy")?
        {
            match crate::wal::master_key::config_subkey_ensure_at(home) {
                Some(key) => match encrypt_credentials_body(&key, &body) {
                    Ok(blob) => write_mode_0600(path, &blob),
                    Err(e) => Err(e),
                },
                None => Err(anyhow::anyhow!(
                    "at-rest encryption enabled but master key unavailable — \
                     refusing to write plaintext credentials"
                )),
            }
        } else {
            write_mode_0600(path, body.as_bytes())
        };
        body.zeroize();
        result?;
        Ok(())
    }

    /// True when there are no secrets to persist.
    ///
    /// Destructured intentionally so adding a new field to `Credentials`
    /// without updating this method is a compile error rather than a
    /// silent wrong answer.
    pub fn is_empty(&self) -> bool {
        let Self {
            provider_key,
            elevenlabs_tts_api_key,
            azure_tts_api_key,
            telegram_token,
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
            whatsapp_baileys_url,
            whatsapp_baileys_token,
            whatsapp_baileys_allowed_senders,
            whatsapp_baileys_allowed_groups,
            slack_bot_token,
            slack_app_token,
            discord_bot_token,
            signal_cli_url,
            signal_phone_number,
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
            keet_seed_phrase,
            pears_bearer_token,
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
            paperless_url,
            paperless_token,
        } = self;
        provider_key.is_none()
            && elevenlabs_tts_api_key.is_none()
            && azure_tts_api_key.is_none()
            && telegram_token.is_none()
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
            && whatsapp_baileys_url.is_none()
            && whatsapp_baileys_token.is_none()
            && whatsapp_baileys_allowed_senders.is_none()
            && whatsapp_baileys_allowed_groups.is_none()
            && slack_bot_token.is_none()
            && slack_app_token.is_none()
            && discord_bot_token.is_none()
            && signal_cli_url.is_none()
            && signal_phone_number.is_none()
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
            && keet_seed_phrase.is_none()
            && pears_bearer_token.is_none()
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
    /// Acquires the intra-process `CRED_LOCK` (mutex-first) then the OS
    /// advisory lock on `<path>.lock`, reloads strictly under both locks,
    /// calls `mutation`, and atomically writes the result. Returns the
    /// mutation's return value.
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
        let _mutex = lock_cred();
        let _file_lock = lock_cred_file(path)
            .with_context(|| format!("acquire credentials lock for {}", path.display()))?;
        // Load strictly under both locks. Only NotFound returns Ok(default);
        // any other error propagates — NEVER writes into a failed-load.
        let mut creds = Self::load_or_default(path)
            .with_context(|| format!("load credentials at {} for update", path.display()))?;
        let result = mutation(&mut creds)?;
        creds
            .write(path)
            .with_context(|| format!("write credentials at {} after update", path.display()))?;
        Ok(result)
    }
}

/// Per-process-unique sibling temp path for an atomic credentials write
/// (GOLD-SEC-15 / A-34). Lives next to the target so the final
/// `fs::rename` stays on the same filesystem (atomic).
fn atomic_tmp_path(path: &Path) -> std::path::PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("credentials.yaml");
    path.with_file_name(format!(".{name}.tmp{}", std::process::id()))
}

/// GR-081 — RAII cleanup that removes a secret temp file on drop (any early
/// return or panic) UNLESS disarmed after a successful rename, so a
/// partially-written plaintext secret never lingers on disk on a write / fsync /
/// rename / DACL-restrict error path. Best-effort removal (a failed unlink is no
/// worse than the prior leak).
struct SecretTmpGuard {
    path: Option<PathBuf>,
}

impl SecretTmpGuard {
    fn new(path: &Path) -> Self {
        Self {
            path: Some(path.to_path_buf()),
        }
    }
    /// Call after the atomic rename succeeds — the temp is gone (renamed), so
    /// there is nothing left to clean up.
    fn disarm(mut self) {
        self.path = None;
    }
}

impl Drop for SecretTmpGuard {
    fn drop(&mut self) {
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
    let tmp = atomic_tmp_path(path);
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("create credentials temp {} mode 0600", tmp.display()))?;
    // GR-081 — remove the secret temp on any early return below (write / fsync /
    // rename error or panic); disarmed only after the rename succeeds.
    let guard = SecretTmpGuard::new(&tmp);
    file.write_all(body)
        .with_context(|| format!("write credentials body to {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync credentials temp {}", tmp.display()))?;
    drop(file);
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
    // disk. We create an empty temp, restrict it, write into the
    // already-restricted file, then atomically rename over the target.
    // Fail CLOSED: the DACL is the only at-rest protection, so if it can
    // not be set we refuse to write the secrets at all.
    let tmp = atomic_tmp_path(path);
    let _ = std::fs::remove_file(&tmp);
    std::fs::File::create(&tmp)
        .with_context(|| format!("create credentials temp {}", tmp.display()))?;
    // GR-081 — the secret temp is removed on ANY early return below (DACL-restrict
    // failure, open / write / fsync / rename error, or panic); disarmed only after
    // a successful rename.
    let guard = SecretTmpGuard::new(&tmp);
    if let Err(e) = crate::wal::win_acl::restrict_to_owner(&tmp) {
        return Err(anyhow::anyhow!(
            "refusing to write credentials {}: could not restrict the file to \
             owner-only (DACL) — the only at-rest protection for plaintext \
             secrets ({e})",
            path.display()
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&tmp)
        .with_context(|| format!("open restricted credentials temp {}", tmp.display()))?;
    file.write_all(body)
        .with_context(|| format!("write credentials body to {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync credentials temp {}", tmp.display()))?;
    drop(file);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("atomically replace credentials {}", path.display()))?;
    guard.disarm();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf_key(seed: u8) -> crate::wal::crypto::WalSegmentKey {
        let m = crate::wal::crypto::WalMasterKey::from_bytes(&[seed; 32]).unwrap();
        crate::wal::crypto::derive_subkey(&m, crate::wal::crypto::INFO_CONFIG).unwrap()
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
            let _g = SecretTmpGuard::new(&leaked);
        } // dropped without disarm → removed
        assert!(
            !leaked.exists(),
            "an un-disarmed guard must remove the temp on drop"
        );

        let kept = dir.path().join(".kept.tmp");
        std::fs::write(&kept, b"secret-bytes").unwrap();
        {
            let g = SecretTmpGuard::new(&kept);
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
    fn parses_discord_bot_token() {
        // GOLD-PROG-16: a discord_bot_token in credentials.yaml deserialises to
        // Some(SecretString) and marks the credentials non-empty.
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, "discord_bot_token: bot-abc123\n").unwrap();
        let c = Credentials::load_or_default(&path).unwrap();
        assert_eq!(c.discord_bot_token.as_ref().unwrap().expose(), "bot-abc123");
        assert!(c.has_any());
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
        std::fs::write(&path, "stale").unwrap();
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
}
