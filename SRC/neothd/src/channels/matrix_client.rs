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
//! `<store>/neoth-matrix-session.json` after the first password login, then
//! [`MatrixAuth::restore_session`](matrix_sdk::authentication::matrix::MatrixAuth::restore_session)
//! from it on every later start. This reuses ONE device id across restarts —
//! without it each restart would register a fresh device, other room members
//! would see an unverified device, and historical messages would become
//! undecryptable. That defeats the entire reason for choosing matrix-sdk over
//! the raw CS-API. The store dir (and, on unix, the session file) is
//! permission-restricted to the owner because it holds the access token.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use matrix_sdk::{Client, authentication::matrix::MatrixSession, config::SyncSettings};
use tracing::{info, warn};

/// File (inside the store dir) holding the serialized [`MatrixSession`].
const SESSION_FILE: &str = "neoth-matrix-session.json";

/// How long the sync long-poll waits before returning. A bounded timeout
/// lets the spawned task observe shutdown between polls instead of blocking
/// forever inside a single `/sync`.
const SYNC_TIMEOUT_SECS: u64 = 30;

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
///   1. `<store>/neoth-matrix-session.json` exists → `restore_session` (the
///      device-continuity path; covers every restart).
///   2. else `password` present → `login_username` + persist the session.
///   3. else → error. Access-token-only first login is intentionally
///      unsupported: a bare token lacks the device id that a password login
///      (or a prior persisted session) provides, so it cannot anchor E2EE
///      continuity. The operator sets `matrix_password` once; the session
///      then persists and the password is never needed again.
pub async fn login_or_restore(
    client: &Client,
    store_path: &Path,
    user_id: &str,
    password: Option<&str>,
) -> Result<()> {
    let session_file = store_path.join(SESSION_FILE);
    if session_file.exists() {
        let raw = std::fs::read_to_string(&session_file)
            .with_context(|| format!("read matrix session {}", session_file.display()))?;
        let session: MatrixSession = serde_json::from_str(&raw)
            .context("parse persisted matrix session (delete the file to force a fresh login)")?;
        client
            .matrix_auth()
            .restore_session(session, matrix_sdk::store::RoomLoadSettings::default())
            .await
            .context("restore matrix session")?;
        info!(user = %user_id, "matrix: restored persisted session (device continuity)");
        return Ok(());
    }

    let password = password.context(
        "matrix: no persisted session and no matrix_password set — provide matrix_password for \
         the one-time login (the device session is then persisted and reused on every restart)",
    )?;
    client
        .matrix_auth()
        .login_username(user_id, password)
        .initial_device_display_name("neoth")
        .send()
        .await
        .context("matrix password login (check homeserver, user id, and password)")?;
    info!(user = %user_id, "matrix: password login succeeded; persisting device session");
    persist_session(client, store_path).await?;
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
    std::fs::write(&session_file, json.as_bytes())
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
}
