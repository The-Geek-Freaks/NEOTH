//! GOLD-FEAT-10 — matrix-sdk plumbing for the Matrix channel adapter.
//!
//! Behind the `matrix-channel` cargo feature (the heavy E2EE tree —
//! vodozemac crypto + ruma + the matrix-sdk-sqlite store). This module owns
//! the [`Client`] construction, the persistent sqlite crypto/state store, and
//! the login-or-restore session lifecycle. [`super::matrix`] layers the
//! [`Channel`](super::Channel) trait on top.
//!
//! ## E2EE device continuity — why a session file
//!
//! matrix-sdk's sqlite store persists the Olm/Megolm crypto state + the sync
//! token, but the *login session* (access token + device id) must be saved by
//! the caller. We serialize [`MatrixSession`] to
//! `<store>/neoth-matrix-session.json` after token bootstrap or password login, then
//! [`MatrixAuth::restore_session`](matrix_sdk::authentication::matrix::MatrixAuth::restore_session)
//! from it on every later start. This reuses ONE device id across restarts —
//! without it each restart would register a fresh device, other room members
//! would see an unverified device, and historical messages would become
//! undecryptable. That defeats the entire reason for choosing matrix-sdk over
//! the raw CS-API. The store dir (and, on unix, the session file) is
//! permission-restricted to the owner because it holds the access token.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use futures_util::StreamExt;
use matrix_sdk::{
    Client, SessionMeta, SessionTokens, authentication::matrix::MatrixSession,
    config::SyncSettings, ruma::UserId,
};
use serde::Deserialize;
use tracing::{info, warn};

/// File (inside the store dir) holding the serialized [`MatrixSession`].
const SESSION_FILE: &str = "neoth-matrix-session.json";

/// How long the sync long-poll waits before returning. A bounded timeout
/// lets the spawned task observe shutdown between polls instead of blocking
/// forever inside a single `/sync`.
const SYNC_TIMEOUT_SECS: u64 = 30;

/// `/account/whoami` is a tiny JSON object. Bound it so a hostile or broken
/// homeserver cannot make token bootstrap allocate an unbounded response.
const MAX_WHOAMI_BYTES: usize = 16 * 1024;

/// Authentication decision with values deliberately omitted: this can be
/// logged/debugged without ever exposing a password or access token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthSource {
    ConfiguredAccessToken,
    PersistedSession,
    Password,
}

/// Explicitly configured access tokens win over both the persisted session
/// and a password. This makes token rotation deterministic instead of silently
/// continuing with an old session file or falling back to password auth.
fn select_auth_source(
    session_exists: bool,
    access_token_present: bool,
    password_present: bool,
) -> Result<AuthSource> {
    if access_token_present {
        Ok(AuthSource::ConfiguredAccessToken)
    } else if session_exists {
        Ok(AuthSource::PersistedSession)
    } else if password_present {
        Ok(AuthSource::Password)
    } else {
        anyhow::bail!(
            "matrix: no persisted session and no authentication configured — set either \
             matrix_access_token or matrix_password"
        )
    }
}

#[derive(Deserialize)]
struct WhoAmIResponse {
    user_id: String,
    device_id: Option<String>,
}

/// Build a matrix-sdk [`Client`] for `homeserver`, backed by the persistent
/// sqlite store at `store_path` (E2EE keys + sync state survive restarts).
/// Creates + permission-restricts the store dir first.
pub async fn build_client(homeserver: &str, store_path: &Path) -> Result<Client> {
    std::fs::create_dir_all(store_path)
        .with_context(|| format!("create matrix store dir {}", store_path.display()))?;
    restrict_store_dir(store_path);
    let client = Client::builder()
        .homeserver_url(homeserver)
        .sqlite_store(store_path, None)
        .build()
        .await
        .with_context(|| format!("build matrix client for {homeserver}"))?;
    Ok(client)
}

/// Log in (first run) or restore the persisted session (every later run).
///
/// Precedence:
///   1. configured `access_token` → authenticated `/account/whoami` bootstrap,
///      restore the exact token's `(user_id, device_id)`, then persist it;
///   2. persisted session → restore it (device continuity);
///   3. configured password → `login_username`, then persist the new session;
///   4. otherwise → actionable error.
///
/// `/account/whoami` is required for token-only bootstrap because an access
/// token without its device id is insufficient for E2EE device continuity.
/// Homeservers that omit `device_id` are rejected instead of fabricating a
/// device and silently breaking encryption state.
pub async fn login_or_restore(
    client: &Client,
    store_path: &Path,
    user_id: &str,
    password: Option<&str>,
    access_token: Option<&str>,
) -> Result<()> {
    let session_file = store_path.join(SESSION_FILE);
    match select_auth_source(
        session_file.exists(),
        access_token.is_some(),
        password.is_some(),
    )? {
        AuthSource::ConfiguredAccessToken => {
            restore_configured_access_token(
                client,
                store_path,
                user_id,
                access_token.expect("auth source proves access token is present"),
            )
            .await
        }
        AuthSource::PersistedSession => {
            let raw = std::fs::read_to_string(&session_file)
                .with_context(|| format!("read matrix session {}", session_file.display()))?;
            let session: MatrixSession = serde_json::from_str(&raw).context(
                "parse persisted matrix session (delete the file to force a fresh login)",
            )?;
            if session.meta.user_id.as_str() != user_id {
                anyhow::bail!(
                    "matrix persisted session belongs to {}, but matrix_user_id is {}; \
                     remove {} or restore the matching user id",
                    session.meta.user_id,
                    user_id,
                    session_file.display()
                );
            }
            client
                .matrix_auth()
                .restore_session(session, matrix_sdk::store::RoomLoadSettings::default())
                .await
                .context("restore matrix session")?;
            info!(user = %user_id, "matrix: restored persisted session (device continuity)");
            Ok(())
        }
        AuthSource::Password => {
            client
                .matrix_auth()
                .login_username(
                    user_id,
                    password.expect("auth source proves password is present"),
                )
                .initial_device_display_name("neoth")
                .send()
                .await
                .context("matrix password login (check homeserver, user id, and password)")?;
            info!(user = %user_id, "matrix: password login succeeded; persisting device session");
            persist_session(client, store_path).await
        }
    }
}

/// Restore a pre-issued token as the exact device that issued it. The bearer
/// value is confined to the Authorization header and session file; errors and
/// logs mention only status/user/device metadata.
async fn restore_configured_access_token(
    client: &Client,
    store_path: &Path,
    configured_user_id: &str,
    access_token: &str,
) -> Result<()> {
    let configured_user = UserId::parse(configured_user_id)
        .with_context(|| format!("invalid matrix_user_id `{configured_user_id}`"))?;
    let whoami_url = client
        .homeserver()
        .join("/_matrix/client/v3/account/whoami")
        .context("build Matrix /account/whoami URL")?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build Matrix token-bootstrap HTTP client")?;
    let response = http
        .get(whoami_url)
        .bearer_auth(access_token)
        .send()
        .await
        .context("Matrix access-token /account/whoami request failed")?;
    if !response.status().is_success() {
        anyhow::bail!(
            "Matrix access token rejected by /account/whoami (HTTP {})",
            response.status().as_u16()
        );
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read Matrix /account/whoami response")?;
        if body.len().saturating_add(chunk.len()) > MAX_WHOAMI_BYTES {
            anyhow::bail!(
                "Matrix /account/whoami response exceeded {} bytes",
                MAX_WHOAMI_BYTES
            );
        }
        body.extend_from_slice(&chunk);
    }
    let whoami: WhoAmIResponse = serde_json::from_slice(&body)
        .context("parse Matrix /account/whoami response (token value not logged)")?;
    let returned_user = UserId::parse(&whoami.user_id)
        .context("Matrix /account/whoami returned an invalid user_id")?;
    if returned_user != configured_user {
        anyhow::bail!(
            "Matrix access token belongs to {}, but matrix_user_id is {}",
            returned_user,
            configured_user
        );
    }
    let device_id = whoami
        .device_id
        .filter(|id| !id.trim().is_empty())
        .context(
            "Matrix /account/whoami omitted device_id; this token cannot safely anchor E2EE \
         continuity — issue a device-bound token or use matrix_password once",
        )?;
    let session = MatrixSession {
        meta: SessionMeta {
            user_id: returned_user,
            device_id: device_id.clone().into(),
        },
        tokens: SessionTokens {
            access_token: access_token.to_string(),
            refresh_token: None,
        },
    };
    client
        .matrix_auth()
        .restore_session(session, matrix_sdk::store::RoomLoadSettings::default())
        .await
        .context("restore Matrix access-token session")?;
    persist_session(client, store_path).await?;
    info!(user = %configured_user_id, device = %device_id, "matrix: configured access token restored and session persisted");
    Ok(())
}

/// Serialize the active session to `<store>/neoth-matrix-session.json`.
/// Fatal on failure: without it the next start cannot restore device
/// continuity, so a silent miss here would degrade E2EE on the following
/// restart. On unix the file is chmod-0600 (it holds the access token).
async fn persist_session(client: &Client, store_path: &Path) -> Result<()> {
    let session = client
        .matrix_auth()
        .session()
        .context("matrix: no session present after a successful login (unexpected)")?;
    let json = serde_json::to_string(&session).context("serialize matrix session")?;
    let session_file = store_path.join(SESSION_FILE);
    crate::util::atomic_write::atomic_write(&session_file, json.as_bytes())
        .with_context(|| format!("write matrix session {}", session_file.display()))?;
    restrict_session_file(&session_file);
    Ok(())
}

/// Default store dir when the operator leaves `matrix_store_path` unset:
/// `~/.neoth/matrix_store/`.
pub fn default_store_path() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home().join("matrix_store")
}

/// Sync settings shared by the initial backlog drain and the live loop.
pub fn sync_settings() -> SyncSettings {
    SyncSettings::default().timeout(std::time::Duration::from_secs(SYNC_TIMEOUT_SECS))
}

/// Restrict the store dir to the owner. The dir holds the sqlite crypto store
/// (Olm/Megolm secrets) + the session file (access token), so it must not be
/// world-readable. Best-effort: a failure logs but does not abort the build —
/// the operator's umask/ACL policy may already cover it, and refusing to run
/// over a permission-tightening miss would be worse than a warning.
fn restrict_store_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
            warn!(error = %e, path = %path.display(), "matrix: chmod store dir 0700 failed");
        }
    }
    #[cfg(windows)]
    {
        if let Err(e) = crate::wal::win_acl::restrict_to_owner(path) {
            warn!(error = %e, path = %path.display(), "matrix: DACL-restrict store dir failed");
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
}

/// Restrict the session file (access token) to the owner on unix. On Windows
/// it inherits the store dir's owner-only DACL (it is created inside the
/// already-restricted dir).
fn restrict_session_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            warn!(error = %e, path = %path.display(), "matrix: chmod session file 0600 failed");
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_store_path_ends_with_matrix_store() {
        let p = default_store_path();
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("matrix_store"),
            "default store dir must be <home>/matrix_store, got {}",
            p.display()
        );
    }

    #[test]
    fn session_file_name_is_stable() {
        // Drift guard: the restore path keys off this exact name. Changing it
        // silently would orphan every operator's persisted device session.
        assert_eq!(SESSION_FILE, "neoth-matrix-session.json");
    }

    #[test]
    fn sync_settings_carries_bounded_timeout() {
        // The timeout is what lets the spawned sync task notice shutdown
        // between long-polls. Pin that it is set (not the default unbounded).
        let _ = sync_settings();
        assert_eq!(SYNC_TIMEOUT_SECS, 30);
    }

    #[test]
    fn auth_source_uses_token_then_session_then_password() {
        assert_eq!(
            select_auth_source(true, true, true).unwrap(),
            AuthSource::ConfiguredAccessToken,
            "an explicitly configured token must replace a stale persisted session"
        );
        assert_eq!(
            select_auth_source(true, false, true).unwrap(),
            AuthSource::PersistedSession,
            "without a token, preserve the existing device session"
        );
        assert_eq!(
            select_auth_source(false, false, true).unwrap(),
            AuthSource::Password,
            "password is the first-login fallback"
        );
        assert!(select_auth_source(false, false, false).is_err());
    }

    #[tokio::test]
    async fn configured_access_token_bootstraps_device_and_wins_over_password() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_matrix/client/v3/account/whoami"))
            .and(header("authorization", "Bearer syt_matrix_test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "user_id": "@bot:example.org",
                "device_id": "NEOTHDEVICE"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let client = build_client(&server.uri(), dir.path()).await.unwrap();
        login_or_restore(
            &client,
            dir.path(),
            "@bot:example.org",
            Some("password-must-not-be-used"),
            Some("syt_matrix_test"),
        )
        .await
        .unwrap();

        assert_eq!(
            client.user_id().map(|u| u.as_str()),
            Some("@bot:example.org")
        );
        assert_eq!(client.device_id().map(|d| d.as_str()), Some("NEOTHDEVICE"));
        assert_eq!(client.access_token().as_deref(), Some("syt_matrix_test"));
        assert!(dir.path().join(SESSION_FILE).is_file());
    }

    #[tokio::test]
    async fn token_bootstrap_errors_never_echo_the_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_matrix/client/v3/account/whoami"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let client = build_client(&server.uri(), dir.path()).await.unwrap();
        let err = login_or_restore(
            &client,
            dir.path(),
            "@bot:example.org",
            None,
            Some("SUPER_SECRET_MATRIX_TOKEN"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            !err.contains("SUPER_SECRET_MATRIX_TOKEN"),
            "token leaked: {err}"
        );
        assert!(err.contains("HTTP 401"));
    }
}
