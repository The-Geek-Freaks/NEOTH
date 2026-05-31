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
            whatsapp_token,
            whatsapp_phone_id,
            whatsapp_verify_token,
            whatsapp_app_secret,
            slack_bot_token,
            slack_app_token,
            keet_seed_phrase,
            pears_bearer_token,
            todoist_token,
            google_oauth_client_id,
            google_oauth_client_secret,
            google_oauth_refresh_token,
        } = self;
        provider_key.is_none()
            && telegram_token.is_none()
            && whatsapp_token.is_none()
            && whatsapp_phone_id.is_none()
            && whatsapp_verify_token.is_none()
            && whatsapp_app_secret.is_none()
            && slack_bot_token.is_none()
            && slack_app_token.is_none()
            && keet_seed_phrase.is_none()
            && pears_bearer_token.is_none()
            && todoist_token.is_none()
            && google_oauth_client_id.is_none()
            && google_oauth_client_secret.is_none()
            && google_oauth_refresh_token.is_none()
    }

    /// True if either field is set. Mirror of `!is_empty()` for call-site
    /// readability.
    pub fn has_any(&self) -> bool {
        !self.is_empty()
    }
}

#[cfg(unix)]
pub(crate) fn write_mode_0600(path: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create credentials at {} mode 0600", path.display()))?;
    file.write_all(body)
        .with_context(|| format!("write credentials body to {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync credentials {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn write_mode_0600(path: &Path, body: &[u8]) -> Result<()> {
    std::fs::write(path, body)
        .with_context(|| format!("write credentials at {}", path.display()))?;
    if let Err(e) = crate::wal::win_acl::restrict_to_owner(path) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "credentials file DACL restriction failed; file inherits parent DACL",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
    fn parses_partial_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("c.yaml");
        std::fs::write(&path, "provider_key: just-the-key\n").unwrap();
        let c = Credentials::load_or_default(&path).unwrap();
        assert!(c.provider_key.is_some());
        assert!(c.telegram_token.is_none());
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
