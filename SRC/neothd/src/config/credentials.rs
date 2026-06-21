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

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

/// Default file: `<neoth_home>/credentials.yaml`.
pub fn default_path() -> PathBuf {
    super::FreedomConfig::default_neoth_home().join("credentials.yaml")
}

/// Shape of `credentials.yaml`. All fields optional so an operator who
/// hasn't configured a provider key (e.g. claude-cli OAuth only) doesn't
/// need to keep an empty key around.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Credentials {
    /// LLM provider API key — OpenAI, Gemini, or compat endpoint.
    pub provider_key: Option<SecretString>,
    /// Telegram bot token from @BotFather.
    pub telegram_token: Option<SecretString>,
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
    /// developer console. Scaffold-only in v0.1.x — adapter returns
    /// `NotSupported` until the webhook/HTTP server lands.
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
    /// (any sender reaches the pipeline); set ⇒ only this id is accepted, others
    /// dropped + audited `0x3B CHANNEL_GATE_REJECTED`. Not a secret.
    pub matrix_allowed_user_id: Option<String>,
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
    /// K-3.5 (Session 21, 2026-05-23) — operator's 24-word Keet
    /// pairing phrase. Validated via `channels::keet::validate_seed_phrase`
    /// before persisting. Wrapped in SecretString so the same
    /// mlock+zeroize protections the provider keys carry apply here.
    pub keet_seed_phrase: Option<SecretString>,
    /// K-3.5 (Session 21, 2026-05-23) — bearer token the wizard
    /// generates for the Pears HTTP bridge. 32 random bytes hex-
    /// encoded (64 chars). `pear` reads this on launch; NEOTH
    /// attaches it to every PearsBridge::post_message / .health()
    /// request via `bearer_auth`.
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
    /// HMAC-authenticates every announce + (future) gossip/task frame, so a
    /// peer without the phrase can never join or impersonate. A secret →
    /// lives here in `SecretString` (mlock+zeroize), NOT in freedom.yaml.
    /// The PUBLIC cluster rendezvous name lives in `freedom.yaml::cluster.name`.
    pub cluster_passphrase: Option<SecretString>,
}

impl Credentials {
    /// Read from `path`. Missing file returns `Credentials::default()`
    /// (a clean install has no secrets yet). Bad YAML is a hard error —
    /// silent fallback would mask a typo that disables an operator's
    /// configured provider.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read credentials at {}", path.display()))?;
        let c: Self = serde_yaml::from_str(&body)
            .with_context(|| format!("parse credentials YAML at {}", path.display()))?;
        Ok(c)
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
        let result = write_mode_0600(path, body.as_bytes());
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
            telegram_token,
            inference_left_key,
            inference_right_key,
            inference_cerebellum_key,
            inference_default_slot_key,
            whatsapp_token,
            whatsapp_phone_id,
            whatsapp_verify_token,
            whatsapp_app_secret,
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
            mattermost_url,
            mattermost_token,
            mattermost_allowed_user_id,
            twitch_username,
            twitch_oauth_token,
            twitch_channels,
            nostr_secret_key,
            nostr_relays,
            nostr_allowed_pubkey,
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
        } = self;
        provider_key.is_none()
            && telegram_token.is_none()
            && inference_left_key.is_none()
            && inference_right_key.is_none()
            && inference_cerebellum_key.is_none()
            && inference_default_slot_key.is_none()
            && whatsapp_token.is_none()
            && whatsapp_phone_id.is_none()
            && whatsapp_verify_token.is_none()
            && whatsapp_app_secret.is_none()
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
            && mattermost_url.is_none()
            && mattermost_token.is_none()
            && mattermost_allowed_user_id.is_none()
            && twitch_username.is_none()
            && twitch_oauth_token.is_none()
            && twitch_channels.is_none()
            && nostr_secret_key.is_none()
            && nostr_relays.is_none()
            && nostr_allowed_pubkey.is_none()
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
    }

    /// True if either field is set. Mirror of `!is_empty()` for call-site
    /// readability.
    pub fn has_any(&self) -> bool {
        !self.is_empty()
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
