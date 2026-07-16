//! D003-KEYCHAIN-01 — OS keychain integration for secrets at rest.
//!
//! # Dependency decision: windows-sys direct (no `keyring` crate)
//!
//! **Chosen**: `windows-sys 0.59` (`Win32_Security_Credentials` feature) for
//! Windows, plus the already-pinned native crates on macOS and Linux.
//!
//! **Rejected**: `keyring 3.x` — it wraps the same OS APIs but pins its OWN
//! versions of the platform crates. We already carry:
//! - `windows-sys "0.59"` (for VirtualLock + DACL)
//! - `security-framework "3"` on macOS (for browser-credential import)
//! - `secret-service "4"` on Linux (for same)
//!
//! Adding `keyring` would create version-conflict risk on all three platforms
//! for zero net benefit. Direct FFI against the already-pinned crates is the
//! right call here. Cost: zero new dependencies.
//!
//! # Service name convention
//!
//! | Platform | Target / Service      | Account / Attribute         |
//! |----------|-----------------------|-----------------------------|
//! | Windows  | `"neoth/{field_key}"` | username `"neoth"`          |
//! | macOS    | `"neoth"`             | account `"{field_key}"`     |
//! | Linux    | label `"neoth/{field_key}"` | attr `("neoth-key", "{field_key}")` |
//!
//! macOS uses Security.framework generic-password entries. Linux uses the
//! freedesktop Secret Service blocking client with DH-encrypted sessions; the
//! CLI calls it outside async executor hot paths. Headless Linux services need
//! an inherited/unlocked D-Bus session keyring or the backend returns an error.
//!
//! # Runtime degradation
//!
//! [`open_store`] returns `Err` when:
//! - The `keychain` cargo feature is absent (build-time opt-out).
//! - The OS store is unavailable at runtime (no D-Bus session, locked
//!   Keychain, insufficient privilege).
//!
//! The caller (`config::load_from_path`) logs the error at `warn!` level and
//! falls back to YAML values — existing behaviour is preserved.
//!
//! # Tests
//!
//! All tests use [`InMemorySecretStore`] — the real OS credential manager is
//! never touched by `cargo test`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

// ── field registry ───────────────────────────────────────────────────────────

/// Names of every `SecretString` field in [`crate::config::credentials::Credentials`].
///
/// Only these fields are migrated to/from the OS store. Non-secret fields
/// (`Option<String>` and primitives) remain in `credentials.yaml` regardless
/// of [`crate::config::SecretsBackend`].
///
/// MAINTENANCE: keep in sync with `Credentials` struct. The
/// `Credentials::is_empty()` destructuring already acts as a compile-time
/// exhaustiveness check for all fields; this slice covers the `SecretString`
/// subset that carries keychain-worthy secrets.
pub const SECRET_FIELD_KEYS: &[&str] = &[
    "provider_key",
    "elevenlabs_tts_api_key",
    "azure_tts_api_key",
    "telegram_token",
    "omi_developer_api_key",
    "omi_ingest_token",
    "inference_left_key",
    "inference_right_key",
    "inference_cerebellum_key",
    "inference_default_slot_key",
    "whatsapp_token",
    "whatsapp_verify_token",
    "whatsapp_app_secret",
    "whatsapp_baileys_token",
    "slack_bot_token",
    "slack_app_token",
    "discord_bot_token",
    "matrix_password",
    "matrix_access_token",
    "line_channel_access_token",
    "line_channel_secret",
    "irc_password",
    "mattermost_token",
    "twitch_oauth_token",
    "nostr_secret_key",
    "bluebubbles_password",
    "keet_topic",
    "keet_seed_phrase",
    "keet_bridge_bearer_token",
    "todoist_token",
    "google_oauth_client_secret",
    "google_oauth_refresh_token",
    "caldav_password",
    "ms_todo_client_secret",
    "ms_todo_refresh_token",
    "cluster_passphrase",
    "tududi_api_token",
    "paperless_token",
];

/// Typed view of every currently-set keychain-managed secret. Unlike a serde
/// mapping round-trip, this never copies plaintext into ordinary heap strings.
pub(crate) fn secret_fields(
    credentials: &crate::config::credentials::Credentials,
) -> impl Iterator<Item = (&'static str, &SecretString)> {
    SECRET_FIELD_KEYS
        .iter()
        .filter_map(|&field| secret_field(credentials, field).map(|value| (field, value)))
}

fn secret_field<'a>(
    credentials: &'a crate::config::credentials::Credentials,
    field: &str,
) -> Option<&'a SecretString> {
    match field {
        "provider_key" => credentials.provider_key.as_ref(),
        "elevenlabs_tts_api_key" => credentials.elevenlabs_tts_api_key.as_ref(),
        "azure_tts_api_key" => credentials.azure_tts_api_key.as_ref(),
        "telegram_token" => credentials.telegram_token.as_ref(),
        "omi_developer_api_key" => credentials.omi_developer_api_key.as_ref(),
        "omi_ingest_token" => credentials.omi_ingest_token.as_ref(),
        "inference_left_key" => credentials.inference_left_key.as_ref(),
        "inference_right_key" => credentials.inference_right_key.as_ref(),
        "inference_cerebellum_key" => credentials.inference_cerebellum_key.as_ref(),
        "inference_default_slot_key" => credentials.inference_default_slot_key.as_ref(),
        "whatsapp_token" => credentials.whatsapp_token.as_ref(),
        "whatsapp_verify_token" => credentials.whatsapp_verify_token.as_ref(),
        "whatsapp_app_secret" => credentials.whatsapp_app_secret.as_ref(),
        "whatsapp_baileys_token" => credentials.whatsapp_baileys_token.as_ref(),
        "slack_bot_token" => credentials.slack_bot_token.as_ref(),
        "slack_app_token" => credentials.slack_app_token.as_ref(),
        "discord_bot_token" => credentials.discord_bot_token.as_ref(),
        "matrix_password" => credentials.matrix_password.as_ref(),
        "matrix_access_token" => credentials.matrix_access_token.as_ref(),
        "line_channel_access_token" => credentials.line_channel_access_token.as_ref(),
        "line_channel_secret" => credentials.line_channel_secret.as_ref(),
        "irc_password" => credentials.irc_password.as_ref(),
        "mattermost_token" => credentials.mattermost_token.as_ref(),
        "twitch_oauth_token" => credentials.twitch_oauth_token.as_ref(),
        "nostr_secret_key" => credentials.nostr_secret_key.as_ref(),
        "bluebubbles_password" => credentials.bluebubbles_password.as_ref(),
        "keet_topic" => credentials.keet_topic.as_ref(),
        "keet_seed_phrase" => credentials.keet_seed_phrase.as_ref(),
        "keet_bridge_bearer_token" => credentials.keet_bridge_bearer_token.as_ref(),
        "todoist_token" => credentials.todoist_token.as_ref(),
        "google_oauth_client_secret" => credentials.google_oauth_client_secret.as_ref(),
        "google_oauth_refresh_token" => credentials.google_oauth_refresh_token.as_ref(),
        "caldav_password" => credentials.caldav_password.as_ref(),
        "ms_todo_client_secret" => credentials.ms_todo_client_secret.as_ref(),
        "ms_todo_refresh_token" => credentials.ms_todo_refresh_token.as_ref(),
        "cluster_passphrase" => credentials.cluster_passphrase.as_ref(),
        "tududi_api_token" => credentials.tududi_api_token.as_ref(),
        "paperless_token" => credentials.paperless_token.as_ref(),
        _ => panic!("SECRET_FIELD_KEYS contains unhandled field `{field}`"),
    }
}

fn set_secret_field(
    credentials: &mut crate::config::credentials::Credentials,
    field: &str,
    value: Option<SecretString>,
) {
    match field {
        "provider_key" => credentials.provider_key = value,
        "elevenlabs_tts_api_key" => credentials.elevenlabs_tts_api_key = value,
        "azure_tts_api_key" => credentials.azure_tts_api_key = value,
        "telegram_token" => credentials.telegram_token = value,
        "omi_developer_api_key" => credentials.omi_developer_api_key = value,
        "omi_ingest_token" => credentials.omi_ingest_token = value,
        "inference_left_key" => credentials.inference_left_key = value,
        "inference_right_key" => credentials.inference_right_key = value,
        "inference_cerebellum_key" => credentials.inference_cerebellum_key = value,
        "inference_default_slot_key" => credentials.inference_default_slot_key = value,
        "whatsapp_token" => credentials.whatsapp_token = value,
        "whatsapp_verify_token" => credentials.whatsapp_verify_token = value,
        "whatsapp_app_secret" => credentials.whatsapp_app_secret = value,
        "whatsapp_baileys_token" => credentials.whatsapp_baileys_token = value,
        "slack_bot_token" => credentials.slack_bot_token = value,
        "slack_app_token" => credentials.slack_app_token = value,
        "discord_bot_token" => credentials.discord_bot_token = value,
        "matrix_password" => credentials.matrix_password = value,
        "matrix_access_token" => credentials.matrix_access_token = value,
        "line_channel_access_token" => credentials.line_channel_access_token = value,
        "line_channel_secret" => credentials.line_channel_secret = value,
        "irc_password" => credentials.irc_password = value,
        "mattermost_token" => credentials.mattermost_token = value,
        "twitch_oauth_token" => credentials.twitch_oauth_token = value,
        "nostr_secret_key" => credentials.nostr_secret_key = value,
        "bluebubbles_password" => credentials.bluebubbles_password = value,
        "keet_topic" => credentials.keet_topic = value,
        "keet_seed_phrase" => credentials.keet_seed_phrase = value,
        "keet_bridge_bearer_token" => credentials.keet_bridge_bearer_token = value,
        "todoist_token" => credentials.todoist_token = value,
        "google_oauth_client_secret" => credentials.google_oauth_client_secret = value,
        "google_oauth_refresh_token" => credentials.google_oauth_refresh_token = value,
        "caldav_password" => credentials.caldav_password = value,
        "ms_todo_client_secret" => credentials.ms_todo_client_secret = value,
        "ms_todo_refresh_token" => credentials.ms_todo_refresh_token = value,
        "cluster_passphrase" => credentials.cluster_passphrase = value,
        "tududi_api_token" => credentials.tududi_api_token = value,
        "paperless_token" => credentials.paperless_token = value,
        _ => panic!("SECRET_FIELD_KEYS contains unhandled field `{field}`"),
    }
}

/// Canonical field -> legacy OS-store key. Serde aliases cover YAML, but OS
/// credential managers are keyed independently and need an explicit read
/// fallback so upgrading cannot strand an existing secret.
fn legacy_store_key(field: &str) -> Option<&'static str> {
    match field {
        "keet_bridge_bearer_token" => Some("pears_bearer_token"),
        _ => None,
    }
}

fn get_with_legacy_fallback(
    store: &dyn SecretStore,
    field: &str,
) -> Result<(Option<SecretString>, String)> {
    if let Some(secret) = store.get(field)? {
        return Ok((Some(secret), field.to_string()));
    }
    if let Some(legacy) = legacy_store_key(field)
        && let Some(secret) = store.get(legacy)?
    {
        return Ok((Some(secret), legacy.to_string()));
    }
    Ok((None, field.to_string()))
}

/// Namespace prefix prepended to every OS store entry key to avoid collisions
/// with other applications.
const NS: &str = "neoth";

/// Returns the OS-level target/label for a field key.
///
/// Example: `"provider_key"` → `"neoth/provider_key"`.
pub fn store_key(field: &str) -> String {
    format!("{NS}/{field}")
}

// ── trait ────────────────────────────────────────────────────────────────────

/// Abstraction over OS secret stores and test doubles.
///
/// Implementations MUST:
/// - Return `Ok(None)` when a key is absent (never `Err` for "not found").
/// - Return `Err` only for genuine OS-level failures (permission denied,
///   store unavailable, etc.).
/// - Never log or print secret values.
/// - Be `Send + Sync` (the store may be shared across threads).
pub trait SecretStore: Send + Sync {
    /// Retrieve a secret by its NEOTH field key (e.g. `"provider_key"`).
    ///
    /// Returns `Ok(None)` when the key has no entry in the store.
    fn get(&self, key: &str) -> Result<Option<SecretString>>;

    /// Persist a secret. Overwrites any existing value for `key`.
    fn set(&self, key: &str, value: &SecretString) -> Result<()>;

    /// Remove a secret. Returns `Ok(())` even when the key was absent
    /// (idempotent delete).
    fn delete(&self, key: &str) -> Result<()>;

    /// Human-readable backend name for error messages and `--dry-run` output.
    fn backend_name(&self) -> &'static str;
}

// ── in-memory (tests only) ───────────────────────────────────────────────────

/// Test double — stores secrets in a plain `HashMap` without touching the OS.
///
/// Never use this as a production `SecretStore`. Intended exclusively for
/// `#[cfg(test)]` blocks and integration tests.
pub struct InMemorySecretStore {
    data: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl Default for InMemorySecretStore {
    fn default() -> Self {
        Self {
            data: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl SecretStore for InMemorySecretStore {
    fn get(&self, key: &str) -> Result<Option<SecretString>> {
        let map = self.data.lock().expect("InMemorySecretStore lock poisoned");
        Ok(map.get(key).map(|v| SecretString::from(v.clone())))
    }

    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        let mut map = self.data.lock().expect("InMemorySecretStore lock poisoned");
        map.insert(key.to_string(), value.expose().to_string());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut map = self.data.lock().expect("InMemorySecretStore lock poisoned");
        map.remove(key);
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "in-memory (test)"
    }
}

// ── Windows implementation ───────────────────────────────────────────────────

/// Windows Credential Manager backend (CredWriteW / CredReadW / CredDeleteW).
///
/// Each secret is stored as a `CRED_TYPE_GENERIC` credential:
/// - `TargetName`: `"neoth/{field_key}"` (UTF-16, null-terminated)
/// - `UserName`: `"neoth"` (UTF-16, null-terminated)
/// - `CredentialBlob`: UTF-8 bytes of the secret value
/// - `Persist`: `CRED_PERSIST_LOCAL_MACHINE` — survives reboots, no AD roaming
///
/// `CRED_PERSIST_LOCAL_MACHINE` (not `ENTERPRISE`) is chosen deliberately:
/// operator secrets should not silently replicate to AD/Azure cloud sync.
/// Operators who want cross-machine sync can use a password manager instead.
#[cfg(all(windows, feature = "keychain"))]
pub(super) struct WinCredStore;

#[cfg(all(windows, feature = "keychain"))]
impl SecretStore for WinCredStore {
    fn get(&self, key: &str) -> Result<Option<SecretString>> {
        use windows_sys::Win32::Foundation::{
            ERROR_NO_SUCH_LOGON_SESSION, ERROR_NOT_FOUND, GetLastError,
        };
        use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CredFree, CredReadW};

        let target = to_wide(&store_key(key));
        let mut pcred = std::ptr::null_mut();
        // SAFETY: `target` is a valid null-terminated UTF-16 string whose
        // lifetime covers the CredReadW call. `pcred` is an out-parameter;
        // CredReadW sets it to a Credential Manager-allocated CREDENTIALW on
        // success (non-zero return) and leaves it null on failure.
        let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pcred) };
        if ok == 0 {
            // SAFETY: called immediately after a failed Win32 API on the same thread.
            let err = unsafe { GetLastError() };
            // ERROR_NOT_FOUND (1168) — the credential simply does not exist.
            if err == ERROR_NOT_FOUND {
                return Ok(None);
            }
            // ERROR_NO_SUCH_LOGON_SESSION (1312) — the process does not have
            // access to a credential vault (e.g. running as SYSTEM or in a
            // headless service context). This is a real failure, not "not found".
            if err == ERROR_NO_SUCH_LOGON_SESSION {
                anyhow::bail!(
                    "Windows Credential Manager is unavailable for this logon session \
                     (error 1312). This typically occurs when running NEOTH as a service \
                     without an interactive logon session. Set `secrets_backend: file` in \
                     freedom.yaml for non-interactive deployments."
                );
            }
            anyhow::bail!(
                "CredReadW failed for key \"{key}\": Win32 error {err} — \
                 check that the Windows Credential Manager service is running \
                 and the current user has access to their credential vault"
            );
        }
        // SAFETY: CredReadW returned non-zero → `pcred` is non-null and points
        // to a Credential Manager-allocated CREDENTIALW. We copy out the blob
        // bytes before freeing the struct. After CredFree returns, `pcred` and
        // any interior pointers are invalid — only `data` (a heap-owned Vec) is
        // used after this block.
        //
        // Null blob guard: CredentialBlobSize == 0 is legal (empty password) and
        // in that case CredentialBlob MAY be null. from_raw_parts with a null
        // pointer is UB even with length 0, so we special-case it.
        let blob_bytes: Vec<u8> = unsafe {
            let cred = &*pcred;
            let len = cred.CredentialBlobSize as usize;
            let data = if len == 0 {
                Vec::new()
            } else {
                // SAFETY: CredReadW guarantees CredentialBlob is non-null and
                // valid for `len` bytes when CredentialBlobSize > 0. We copy
                // before calling CredFree which invalidates the pointer.
                std::slice::from_raw_parts(cred.CredentialBlob, len).to_vec()
            };
            // SAFETY: pcred was obtained from CredReadW and must be freed
            // exactly once with CredFree (not LocalFree, not HeapFree).
            CredFree(pcred.cast());
            data
        };
        let value = String::from_utf8(blob_bytes)
            .context("Windows Credential Manager blob is not UTF-8")?;
        Ok(Some(SecretString::from(value)))
    }

    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        use windows_sys::Win32::Foundation::{FILETIME, GetLastError};
        use windows_sys::Win32::Security::Credentials::{
            CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
        };

        let target = to_wide(&store_key(key));
        let username = to_wide("neoth");
        let blob = value.expose().as_bytes();
        // SAFETY: We construct the struct with raw pointers into the Vecs above.
        // Both `target` and `username` are null-terminated UTF-16 owned Vecs
        // that outlive the struct and the CredWriteW call. `blob` is borrowed
        // from `value` which also outlives the call.
        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_ptr().cast_mut(),
            Comment: std::ptr::null_mut(),
            // LastWritten is set by the OS on write; zeroed here is correct.
            LastWritten: FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: username.as_ptr().cast_mut(),
        };
        // SAFETY: &cred is a valid CREDENTIALW. All pointer fields inside point
        // to data that lives at least as long as this call. CredWriteW does not
        // retain the pointer after it returns.
        let ok = unsafe { CredWriteW(&cred, 0) };
        if ok == 0 {
            // SAFETY: called immediately after a failed Win32 API.
            let err = unsafe { GetLastError() };
            anyhow::bail!(
                "CredWriteW failed for key \"{key}\": Win32 error {err}. \
                 Verify the Credential Manager service is running and the \
                 credential target name is not exceeding the 512-character limit"
            );
        }
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CredDeleteW};

        let target = to_wide(&store_key(key));
        // SAFETY: target is a valid null-terminated UTF-16 string.
        let ok = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok == 0 {
            // SAFETY: called immediately after a failed Win32 API.
            let err = unsafe { GetLastError() };
            // ERROR_NOT_FOUND (1168) → already absent; idempotent delete is fine.
            if err == 1168 {
                return Ok(());
            }
            anyhow::bail!("CredDeleteW failed for key \"{key}\": Win32 error {err}");
        }
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "Windows Credential Manager"
    }
}

/// Convert a Rust `&str` to a null-terminated UTF-16 `Vec<u16>`.
///
/// Used to produce `LPCWSTR` (`*const u16`) arguments for Win32 functions.
#[cfg(all(windows, feature = "keychain"))]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ── macOS implementation ─────────────────────────────────────────────────────

/// macOS Keychain generic-password backend.
#[cfg(all(target_os = "macos", feature = "keychain"))]
pub(super) struct MacCredStore;

#[cfg(all(target_os = "macos", feature = "keychain"))]
impl SecretStore for MacCredStore {
    fn get(&self, key: &str) -> Result<Option<SecretString>> {
        const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
        match security_framework::passwords::get_generic_password(NS, key) {
            Ok(bytes) => Ok(Some(SecretString::from(
                String::from_utf8(bytes).context("macOS Keychain value is not UTF-8")?,
            ))),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(anyhow::anyhow!(
                "macOS Keychain read failed for key {key:?}: {error}"
            )),
        }
    }

    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        security_framework::passwords::set_generic_password(NS, key, value.expose().as_bytes())
            .with_context(|| format!("macOS Keychain write failed for key {key:?}"))
    }

    fn delete(&self, key: &str) -> Result<()> {
        const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
        match security_framework::passwords::delete_generic_password(NS, key) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(anyhow::anyhow!(
                "macOS Keychain delete failed for key {key:?}: {error}"
            )),
        }
    }

    fn backend_name(&self) -> &'static str {
        "macOS Keychain"
    }
}

// ── Linux implementation ─────────────────────────────────────────────────────

/// Linux freedesktop Secret Service backend.
#[cfg(all(target_os = "linux", feature = "keychain"))]
pub(super) struct LinuxCredStore;

#[cfg(all(target_os = "linux", feature = "keychain"))]
impl SecretStore for LinuxCredStore {
    fn get(&self, key: &str) -> Result<Option<SecretString>> {
        let service = linux_secret_service()?;
        let mut found = service
            .search_items(linux_secret_attributes(key))
            .with_context(|| format!("Linux Secret Service search failed for key {key:?}"))?;
        let count = found.unlocked.len() + found.locked.len();
        if count == 0 {
            return Ok(None);
        }
        if count != 1 {
            anyhow::bail!(
                "Linux Secret Service contains {count} entries for key {key:?}; \
                 remove duplicates before continuing"
            );
        }
        let item = if let Some(item) = found.unlocked.pop() {
            item
        } else {
            let item = found.locked.pop().expect("count checked");
            item.unlock()
                .with_context(|| format!("unlock Linux Secret Service key {key:?}"))?;
            item
        };
        let bytes = item
            .get_secret()
            .with_context(|| format!("read Linux Secret Service key {key:?}"))?;
        Ok(Some(SecretString::from(
            String::from_utf8(bytes).context("Linux Secret Service value is not UTF-8")?,
        )))
    }

    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        let service = linux_secret_service()?;
        let collection = service
            .get_default_collection()
            .or_else(|_| service.get_any_collection())
            .context("open a Linux Secret Service collection")?;
        if collection
            .is_locked()
            .context("query Linux Secret Service collection lock state")?
        {
            collection
                .unlock()
                .context("unlock Linux Secret Service collection")?;
        }
        collection
            .create_item(
                &store_key(key),
                linux_secret_attributes(key),
                value.expose().as_bytes(),
                true,
                "text/plain; charset=utf-8",
            )
            .with_context(|| format!("write Linux Secret Service key {key:?}"))?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let service = linux_secret_service()?;
        let found = service
            .search_items(linux_secret_attributes(key))
            .with_context(|| format!("Linux Secret Service search failed for key {key:?}"))?;
        for item in found.unlocked {
            item.delete()
                .with_context(|| format!("delete Linux Secret Service key {key:?}"))?;
        }
        for item in found.locked {
            item.unlock()
                .with_context(|| format!("unlock Linux Secret Service key {key:?}"))?;
            item.delete()
                .with_context(|| format!("delete Linux Secret Service key {key:?}"))?;
        }
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "Linux Secret Service"
    }
}

#[cfg(all(target_os = "linux", feature = "keychain"))]
fn linux_secret_service() -> Result<secret_service::blocking::SecretService<'static>> {
    secret_service::blocking::SecretService::connect(secret_service::EncryptionType::Dh)
        .context("connect to Linux Secret Service over the session D-Bus")
}

#[cfg(all(target_os = "linux", feature = "keychain"))]
fn linux_secret_attributes(key: &str) -> std::collections::HashMap<&str, &str> {
    let mut attributes = std::collections::HashMap::new();
    attributes.insert("neoth-key", key);
    attributes
}

// ── factory ──────────────────────────────────────────────────────────────────

/// Open the platform-appropriate OS secret store.
///
/// Returns `Err` when:
/// - The `keychain` cargo feature is not compiled in.
/// - The current platform is unsupported.
/// - The OS store is unavailable at runtime (no session, locked vault, etc.).
///
/// The caller should treat `Err` as a signal to degrade gracefully (log at
/// `warn!` and keep using `credentials.yaml`).
pub fn open_store() -> Result<Box<dyn SecretStore>> {
    #[cfg(not(feature = "keychain"))]
    {
        anyhow::bail!(
            "the `keychain` cargo feature was not compiled in — \
             rebuild with `--features keychain` (included in default releases) \
             to enable OS keychain integration"
        )
    }

    #[cfg(all(windows, feature = "keychain"))]
    {
        Ok(Box::new(WinCredStore))
    }

    #[cfg(all(target_os = "macos", feature = "keychain"))]
    {
        Ok(Box::new(MacCredStore))
    }

    #[cfg(all(target_os = "linux", feature = "keychain"))]
    {
        Ok(Box::new(LinuxCredStore))
    }

    #[cfg(all(
        feature = "keychain",
        not(any(windows, target_os = "macos", target_os = "linux"))
    ))]
    {
        anyhow::bail!("OS keychain not supported on this platform")
    }
}

// ── migration ────────────────────────────────────────────────────────────────

/// Direction of a secrets migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MigrationDirection {
    /// Move secrets from `credentials.yaml` into the OS keychain.
    ToKeychain,
    /// Move secrets from the OS keychain back into `credentials.yaml`.
    ToFile,
}

/// Report produced by [`migrate_to_keychain`] or [`migrate_to_file`].
#[derive(Debug)]
pub struct MigrationReport {
    /// Which direction this migration ran.
    pub direction: MigrationDirection,
    /// Field keys successfully moved to the new location.
    pub moved: Vec<String>,
    /// Field keys that had no value in the source (nothing to migrate).
    pub skipped: Vec<String>,
    /// Field keys where the migration step failed, with the error message.
    pub failed: Vec<(String, String)>,
    /// `true` → the report was produced but no writes were performed.
    pub dry_run: bool,
}

impl MigrationReport {
    /// `true` if every attempted key migrated without error.
    pub fn is_clean(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Move all `SecretString` fields from `creds` into `store`.
///
/// On success the returned `Credentials` has those fields blanked (`None`).
/// The caller is responsible for:
/// 1. Writing the blanked `Credentials` back to `credentials.yaml` (via
///    the credential renderer).
/// 2. Publishing that image together with `secrets_backend: keychain` through
///    the crash-recoverable freedom/credential pair transaction. Separate
///    writes can expose a backend pointer whose secret image is not ready.
///
/// When `dry_run` is `true`, no writes to `store` occur and the returned
/// `Credentials` is a clone of the input (unmodified).
pub fn migrate_to_keychain(
    creds: &crate::config::credentials::Credentials,
    store: &dyn SecretStore,
    dry_run: bool,
) -> Result<(crate::config::credentials::Credentials, MigrationReport)> {
    let mut moved = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();
    let mut previous_values = Vec::new();
    let mut blanked = creds.clone();

    for &field in SECRET_FIELD_KEYS {
        match secret_field(creds, field) {
            None => {
                skipped.push(field.to_string());
            }
            Some(secret) => {
                if !dry_run {
                    let previous = match store.get(field) {
                        Ok(previous) => previous,
                        Err(error) => {
                            failed.push((
                                field.to_string(),
                                format!("snapshot existing keychain value: {error}"),
                            ));
                            continue;
                        }
                    };
                    match store.set(field, secret) {
                        Ok(()) => {
                            set_secret_field(&mut blanked, field, None);
                            moved.push(field.to_string());
                            previous_values.push((field.to_string(), previous));
                        }
                        Err(e) => {
                            failed.push((field.to_string(), e.to_string()));
                        }
                    }
                } else {
                    moved.push(field.to_string());
                }
            }
        }
    }

    // Rollback: if any field failed to set, restore the exact values that were
    // present before this attempt. Deleting every successfully-written key is
    // not a rollback when migration overwrote an existing credential: it would
    // destroy that previous value while claiming that nothing was written.
    if !dry_run && !failed.is_empty() && !previous_values.is_empty() {
        let mut rollback_failed = Vec::new();
        for (key, previous) in previous_values.into_iter().rev() {
            let result = match previous {
                Some(previous) => store.set(&key, &previous),
                None => store.delete(&key),
            };
            if let Err(error) = result {
                rollback_failed.push(format!("{key}: {error}"));
            }
        }
        moved.clear();
        if !rollback_failed.is_empty() {
            anyhow::bail!(
                "keychain migration failed and rollback was incomplete for {} entr(y/ies): {}",
                rollback_failed.len(),
                rollback_failed.join("; ")
            );
        }
    }

    // On a clean dry_run the blanked struct is unused; on a clean real run it is
    // written by the caller. On a rolled-back failure the caller aborts and this
    // value is discarded — but recompute it from the (possibly mutated) yaml so
    // it never claims fields were blanked when we rolled their keychain sets back.
    let blanked = if dry_run || !failed.is_empty() {
        creds.clone()
    } else {
        blanked
    };

    let report = MigrationReport {
        direction: MigrationDirection::ToKeychain,
        moved,
        skipped,
        failed,
        dry_run,
    };
    Ok((blanked, report))
}

/// Phase 1 of a `--to file` migration: READ every `SecretString` field from
/// `store` into a `Credentials` struct. **This function performs NO keychain
/// deletes** — deleting a secret before `credentials.yaml` is durably written
/// (or a later read failing after an earlier delete, or a crash in between)
/// would erase the secret from BOTH backends. The keychain is only purged by a
/// SEPARATE [`purge_from_keychain`] call the caller makes AFTER the file is
/// written and verified.
///
/// `report.moved` lists the fields successfully read — i.e. the keys that are
/// now safe to purge from the keychain once the file is on disk. A non-clean
/// report (a `store.get` error) means the caller must abort BEFORE writing;
/// because nothing was deleted, "nothing written" stays truthful.
///
/// The caller is responsible, IN ORDER, for: (1) write the populated
/// `Credentials` to `credentials.yaml` + verify; (2) switch `freedom.yaml`
/// `secrets_backend: file`; (3) [`purge_from_keychain`]`(&report.moved)`.
pub fn migrate_to_file(
    creds: &crate::config::credentials::Credentials,
    store: &dyn SecretStore,
    dry_run: bool,
) -> Result<(crate::config::credentials::Credentials, MigrationReport)> {
    let mut moved = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();

    let mut populated = creds.clone();

    for &field in SECRET_FIELD_KEYS {
        match get_with_legacy_fallback(store, field) {
            Err(e) => {
                failed.push((field.to_string(), e.to_string()));
            }
            Ok((None, _)) => {
                skipped.push(field.to_string());
            }
            Ok((Some(secret), source_key)) => {
                if !dry_run {
                    // Populate the typed file result. NO delete here — the
                    // keychain is purged later, only after the file lands.
                    set_secret_field(&mut populated, field, Some(secret));
                }
                // Purge the actual OS-store key after the file is durable. For
                // upgraded installs this may be the legacy alias.
                moved.push(source_key);
            }
        }
    }

    let populated = if dry_run { creds.clone() } else { populated };

    let report = MigrationReport {
        direction: MigrationDirection::ToFile,
        moved,
        skipped,
        failed,
        dry_run,
    };
    Ok((populated, report))
}

/// Phase 3 of a `--to file` migration: delete `keys` from the OS `store`. Call
/// this ONLY after `credentials.yaml` has been written and verified to hold
/// those secrets — at that point a delete failure is a *cleanup* problem (the
/// secret is safe in the file, merely duplicated in the keychain), NEVER data
/// loss. Returns the `(key, error)` pairs that could not be deleted so the
/// caller can tell the operator which keychain entries to remove manually.
pub fn purge_from_keychain(store: &dyn SecretStore, keys: &[String]) -> Vec<(String, String)> {
    let mut failed = Vec::new();
    for key in keys {
        if let Err(e) = store.delete(key) {
            failed.push((key.clone(), e.to_string()));
        }
    }
    failed
}

/// Supplement a partially-populated `Credentials` with values from the OS
/// store.
///
/// Called by `config::load_from_path` when `secrets_backend: keychain`.
/// For every `SecretString` field that is `None` in `creds` (either absent
/// from `credentials.yaml` or explicitly blank), the keychain is queried and
/// the value filled in if found.
///
/// Fields that are already `Some` in `creds` (set in the YAML) are **not**
/// overwritten — the YAML value takes precedence (allows emergency override).
///
/// Individual key lookup errors are logged at `warn!` level but do NOT abort
/// the supplement: successful lookups must not be discarded because one
/// field fails (e.g. a single corrupted credential entry). The caller
/// (`load_from_path`) already logs at `warn!` on any `Err` returned here; for
/// a partial OS-error during supplement, logging per-field is more actionable.
pub fn supplement_from_store(
    creds: &mut crate::config::credentials::Credentials,
    store: &dyn SecretStore,
) -> Result<()> {
    for &field in SECRET_FIELD_KEYS {
        if secret_field(creds, field).is_some() {
            continue;
        }
        match get_with_legacy_fallback(store, field) {
            Ok((None, _)) => {} // not in store either — leave as None
            Ok((Some(secret), _)) => {
                set_secret_field(creds, field, Some(secret));
            }
            Err(e) => {
                // Log the error per-field and continue so the remaining 31
                // fields are still loaded. A single corrupt or inaccessible
                // entry must not prevent the daemon from starting.
                tracing::warn!(
                    field = field,
                    err = %e,
                    "keychain lookup failed for credential field; falling back to YAML value"
                );
            }
        }
    }
    Ok(())
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credentials::Credentials;
    use crate::secret::SecretString;

    fn make_creds(provider_key: Option<&str>, telegram_token: Option<&str>) -> Credentials {
        Credentials {
            provider_key: provider_key.map(|s| SecretString::from(s.to_string())),
            telegram_token: telegram_token.map(|s| SecretString::from(s.to_string())),
            ..Default::default()
        }
    }

    struct FailOnSetStore {
        inner: InMemorySecretStore,
        fail_key: &'static str,
    }

    impl SecretStore for FailOnSetStore {
        fn get(&self, key: &str) -> Result<Option<SecretString>> {
            self.inner.get(key)
        }

        fn set(&self, key: &str, value: &SecretString) -> Result<()> {
            if key == self.fail_key {
                anyhow::bail!("injected keychain write failure");
            }
            self.inner.set(key, value)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }

        fn backend_name(&self) -> &'static str {
            "failing test store"
        }
    }

    // ── InMemorySecretStore ───────────────────────────────────────────────

    #[test]
    fn in_memory_store_get_missing_returns_none() {
        let store = InMemorySecretStore::default();
        assert!(store.get("provider_key").unwrap().is_none());
    }

    #[test]
    fn in_memory_store_set_then_get_round_trips() {
        let store = InMemorySecretStore::default();
        let secret = SecretString::from("sk-test-123".to_string());
        store.set("provider_key", &secret).unwrap();
        let got = store.get("provider_key").unwrap().unwrap();
        assert_eq!(got.expose(), "sk-test-123");
    }

    #[test]
    fn in_memory_store_delete_idempotent() {
        let store = InMemorySecretStore::default();
        // Delete a key that was never set — must not error.
        store.delete("nonexistent").unwrap();
        // Set then delete.
        store
            .set("telegram_token", &SecretString::from("bot-abc".to_string()))
            .unwrap();
        store.delete("telegram_token").unwrap();
        assert!(store.get("telegram_token").unwrap().is_none());
    }

    // ── migrate_to_keychain ───────────────────────────────────────────────

    #[test]
    fn migrate_to_keychain_moves_set_fields_and_blanks_them() {
        let store = InMemorySecretStore::default();
        let creds = make_creds(Some("sk-secret"), Some("bot-token"));

        let (blanked, report) = migrate_to_keychain(&creds, &store, false).unwrap();

        // Both fields must appear in `moved`.
        assert!(report.moved.contains(&"provider_key".to_string()));
        assert!(report.moved.contains(&"telegram_token".to_string()));
        assert!(report.is_clean(), "no failures expected");
        assert!(!report.dry_run);

        // Blanked credentials must have both fields as None.
        assert!(blanked.provider_key.is_none());
        assert!(blanked.telegram_token.is_none());

        // Store must now hold the values.
        assert_eq!(
            store.get("provider_key").unwrap().unwrap().expose(),
            "sk-secret"
        );
        assert_eq!(
            store.get("telegram_token").unwrap().unwrap().expose(),
            "bot-token"
        );
    }

    #[test]
    fn migrate_to_keychain_failure_restores_preexisting_values() {
        let store = FailOnSetStore {
            inner: InMemorySecretStore::default(),
            fail_key: "telegram_token",
        };
        store
            .set("provider_key", &SecretString::from("previous-provider"))
            .unwrap();

        let creds = make_creds(Some("replacement-provider"), Some("bot-token"));
        let (unchanged, report) = migrate_to_keychain(&creds, &store, false).unwrap();

        assert!(!report.is_clean());
        assert!(report.moved.is_empty());
        assert_eq!(
            unchanged.provider_key.as_ref().unwrap().expose(),
            "replacement-provider"
        );
        assert_eq!(
            store.get("provider_key").unwrap().unwrap().expose(),
            "previous-provider",
            "rollback must restore an overwritten key instead of deleting it"
        );
        assert!(store.get("telegram_token").unwrap().is_none());
    }

    #[test]
    fn migrate_to_keychain_dry_run_writes_nothing() {
        let store = InMemorySecretStore::default();
        let creds = make_creds(Some("sk-dryrun"), None);

        let (_returned, report) = migrate_to_keychain(&creds, &store, true).unwrap();

        assert!(report.dry_run);
        // Store must still be empty.
        assert!(store.get("provider_key").unwrap().is_none());
        // Report must still list the field as "would move".
        assert!(report.moved.contains(&"provider_key".to_string()));
    }

    #[test]
    fn migrate_to_keychain_skips_unset_fields() {
        let store = InMemorySecretStore::default();
        let creds = make_creds(Some("sk-x"), None); // telegram_token is None

        let (_, report) = migrate_to_keychain(&creds, &store, false).unwrap();

        assert!(report.skipped.contains(&"telegram_token".to_string()));
        assert!(!report.moved.contains(&"telegram_token".to_string()));
    }

    // ── migrate_to_file ───────────────────────────────────────────────────

    #[test]
    fn migrate_to_file_restores_values_then_purge_empties_store() {
        let store = InMemorySecretStore::default();
        store
            .set(
                "provider_key",
                &SecretString::from("sk-restored".to_string()),
            )
            .unwrap();
        store
            .set(
                "telegram_token",
                &SecretString::from("bot-restored".to_string()),
            )
            .unwrap();

        let empty_creds = Credentials::default();
        let (populated, report) = migrate_to_file(&empty_creds, &store, false).unwrap();

        assert!(report.moved.contains(&"provider_key".to_string()));
        assert!(report.moved.contains(&"telegram_token".to_string()));
        assert!(report.is_clean());

        // Values must be in the returned Credentials.
        assert_eq!(
            populated.provider_key.as_ref().unwrap().expose(),
            "sk-restored"
        );
        assert_eq!(
            populated.telegram_token.as_ref().unwrap().expose(),
            "bot-restored"
        );

        // Phase 1 (migrate_to_file) is a pure read — it must NOT delete, so the
        // secret survives a crash before credentials.yaml is durably written.
        assert!(store.get("provider_key").unwrap().is_some());
        assert!(store.get("telegram_token").unwrap().is_some());

        // Phase 3: only after the file lands does the caller purge the keychain.
        let purge_failures = purge_from_keychain(&store, &report.moved);
        assert!(purge_failures.is_empty());
        assert!(store.get("provider_key").unwrap().is_none());
        assert!(store.get("telegram_token").unwrap().is_none());
    }

    #[test]
    fn migrate_to_file_dry_run_skips_delete() {
        let store = InMemorySecretStore::default();
        store
            .set(
                "cluster_passphrase",
                &SecretString::from("pass123".to_string()),
            )
            .unwrap();

        let (_, report) = migrate_to_file(&Credentials::default(), &store, true).unwrap();

        assert!(report.dry_run);
        // Store must still hold the value.
        assert!(store.get("cluster_passphrase").unwrap().is_some());
        assert!(report.moved.contains(&"cluster_passphrase".to_string()));
    }

    // ── supplement_from_store ─────────────────────────────────────────────

    #[test]
    fn supplement_from_store_fills_none_fields_from_store() {
        let store = InMemorySecretStore::default();
        store
            .set(
                "provider_key",
                &SecretString::from("sk-from-store".to_string()),
            )
            .unwrap();

        let mut creds = Credentials::default();
        supplement_from_store(&mut creds, &store).unwrap();

        assert_eq!(
            creds.provider_key.as_ref().unwrap().expose(),
            "sk-from-store"
        );
    }

    #[test]
    fn supplement_from_store_yaml_value_wins_over_store() {
        // A field already set in YAML must NOT be overwritten by the store.
        let store = InMemorySecretStore::default();
        store
            .set("provider_key", &SecretString::from("sk-store".to_string()))
            .unwrap();

        let mut creds = make_creds(Some("sk-yaml-wins"), None);
        supplement_from_store(&mut creds, &store).unwrap();

        assert_eq!(
            creds.provider_key.as_ref().unwrap().expose(),
            "sk-yaml-wins",
            "YAML value must take precedence over store"
        );
    }

    #[test]
    fn supplement_from_store_missing_store_key_leaves_field_none() {
        let store = InMemorySecretStore::default();
        let mut creds = Credentials::default();
        supplement_from_store(&mut creds, &store).unwrap();
        assert!(creds.provider_key.is_none());
    }

    /// Store that always returns Err on `get` — used to verify partial-success
    /// behaviour: if one field lookup errors, the others still succeed.
    struct ErrorOnFieldStore {
        /// Field name that will return Err; all others delegate to `inner`.
        fail_field: &'static str,
        inner: InMemorySecretStore,
    }
    impl SecretStore for ErrorOnFieldStore {
        fn get(&self, key: &str) -> Result<Option<SecretString>> {
            if key == self.fail_field {
                anyhow::bail!("injected error for field {key}")
            }
            self.inner.get(key)
        }
        fn set(&self, key: &str, value: &SecretString) -> Result<()> {
            self.inner.set(key, value)
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }
        fn backend_name(&self) -> &'static str {
            "error-on-field (test)"
        }
    }

    #[test]
    fn supplement_from_store_partial_error_still_loads_other_fields() {
        // telegram_token errors; provider_key should still be loaded.
        let inner = InMemorySecretStore::default();
        inner
            .set(
                "provider_key",
                &SecretString::from("sk-partial".to_string()),
            )
            .unwrap();
        inner
            .set(
                "telegram_token",
                &SecretString::from("bot-should-fail".to_string()),
            )
            .unwrap();
        let store = ErrorOnFieldStore {
            fail_field: "telegram_token",
            inner,
        };

        let mut creds = Credentials::default();
        // Must return Ok despite the telegram_token error.
        supplement_from_store(&mut creds, &store).unwrap();

        // provider_key loaded from store.
        assert_eq!(creds.provider_key.as_ref().unwrap().expose(), "sk-partial");
        // telegram_token not loaded (store returned Err for it).
        assert!(creds.telegram_token.is_none());
    }

    // ── serde default / round-trip ────────────────────────────────────────

    #[test]
    fn migration_round_trip_file_to_keychain_to_file_preserves_values() {
        let store = InMemorySecretStore::default();
        let original = make_creds(Some("sk-roundtrip"), Some("bot-roundtrip"));

        // file → keychain
        let (blanked, r1) = migrate_to_keychain(&original, &store, false).unwrap();
        assert!(r1.is_clean());
        assert!(blanked.provider_key.is_none());

        // keychain → file (phase 1: pure read, no delete)
        let (restored, r2) = migrate_to_file(&blanked, &store, false).unwrap();
        assert!(r2.is_clean());
        assert_eq!(
            restored.provider_key.as_ref().unwrap().expose(),
            "sk-roundtrip"
        );
        assert_eq!(
            restored.telegram_token.as_ref().unwrap().expose(),
            "bot-roundtrip"
        );

        // Phase 3: caller purges the keychain only after the file is durable.
        assert!(purge_from_keychain(&store, &r2.moved).is_empty());
        assert!(store.get("provider_key").unwrap().is_none());
    }

    #[test]
    fn omi_secrets_are_managed_by_every_keychain_path() {
        assert!(SECRET_FIELD_KEYS.contains(&"elevenlabs_tts_api_key"));
        assert!(SECRET_FIELD_KEYS.contains(&"azure_tts_api_key"));
        assert!(SECRET_FIELD_KEYS.contains(&"omi_developer_api_key"));
        assert!(SECRET_FIELD_KEYS.contains(&"omi_ingest_token"));
        assert!(SECRET_FIELD_KEYS.contains(&"keet_topic"));
        assert!(SECRET_FIELD_KEYS.contains(&"keet_bridge_bearer_token"));
        assert!(!SECRET_FIELD_KEYS.contains(&"pears_bearer_token"));
        let unique = SECRET_FIELD_KEYS
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            unique.len(),
            SECRET_FIELD_KEYS.len(),
            "keychain field names must stay unique"
        );
        let empty = Credentials::default();
        for &field in SECRET_FIELD_KEYS {
            assert!(
                secret_field(&empty, field).is_none(),
                "default credential field {field} must be empty"
            );
        }

        let store = InMemorySecretStore::default();
        let original = Credentials {
            omi_developer_api_key: Some(SecretString::from("omi_dev_keychain_secret")),
            omi_ingest_token: Some(SecretString::from("omi-keychain-secret")),
            ..Default::default()
        };
        let (blanked, to_keychain) = migrate_to_keychain(&original, &store, false).unwrap();
        assert!(to_keychain.is_clean());
        assert!(
            to_keychain
                .moved
                .contains(&"omi_developer_api_key".to_string())
        );
        assert!(to_keychain.moved.contains(&"omi_ingest_token".to_string()));
        assert!(blanked.omi_developer_api_key.is_none());
        assert!(blanked.omi_ingest_token.is_none());
        assert_eq!(
            store
                .get("omi_developer_api_key")
                .unwrap()
                .unwrap()
                .expose(),
            "omi_dev_keychain_secret"
        );
        assert_eq!(
            store.get("omi_ingest_token").unwrap().unwrap().expose(),
            "omi-keychain-secret"
        );

        let mut supplemented = Credentials::default();
        supplement_from_store(&mut supplemented, &store).unwrap();
        assert_eq!(
            supplemented
                .omi_developer_api_key
                .as_ref()
                .unwrap()
                .expose(),
            "omi_dev_keychain_secret"
        );
        assert_eq!(
            supplemented.omi_ingest_token.as_ref().unwrap().expose(),
            "omi-keychain-secret"
        );

        let (restored, to_file) = migrate_to_file(&blanked, &store, false).unwrap();
        assert!(to_file.is_clean());
        assert_eq!(
            restored.omi_developer_api_key.as_ref().unwrap().expose(),
            "omi_dev_keychain_secret"
        );
        assert_eq!(
            restored.omi_ingest_token.as_ref().unwrap().expose(),
            "omi-keychain-secret"
        );
        assert!(purge_from_keychain(&store, &to_file.moved).is_empty());
        assert!(store.get("omi_developer_api_key").unwrap().is_none());
        assert!(store.get("omi_ingest_token").unwrap().is_none());
    }

    #[test]
    fn keet_capability_and_bearer_use_canonical_keychain_keys() {
        let store = InMemorySecretStore::default();
        let original = Credentials {
            keet_topic: Some(SecretString::from(
                "nk1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )),
            keet_bridge_bearer_token: Some(SecretString::from("0123456789abcdef0123456789abcdef")),
            ..Default::default()
        };
        let (blanked, report) = migrate_to_keychain(&original, &store, false).unwrap();
        assert!(report.is_clean());
        assert!(blanked.keet_topic.is_none());
        assert!(blanked.keet_bridge_bearer_token.is_none());
        assert!(store.get("keet_topic").unwrap().is_some());
        assert!(store.get("keet_bridge_bearer_token").unwrap().is_some());
        assert!(store.get("pears_bearer_token").unwrap().is_none());
    }

    #[test]
    fn legacy_pear_keychain_entry_loads_and_migrates_without_loss() {
        let store = InMemorySecretStore::default();
        store
            .set(
                "pears_bearer_token",
                &SecretString::from("legacy-bridge-bearer"),
            )
            .unwrap();

        let mut supplemented = Credentials::default();
        supplement_from_store(&mut supplemented, &store).unwrap();
        assert_eq!(
            supplemented
                .keet_bridge_bearer_token
                .as_ref()
                .map(SecretString::expose),
            Some("legacy-bridge-bearer")
        );

        let (restored, report) = migrate_to_file(&Credentials::default(), &store, false).unwrap();
        assert!(report.is_clean());
        assert!(report.moved.contains(&"pears_bearer_token".to_string()));
        assert_eq!(
            restored
                .keet_bridge_bearer_token
                .as_ref()
                .map(SecretString::expose),
            Some("legacy-bridge-bearer")
        );
        assert!(purge_from_keychain(&store, &report.moved).is_empty());
        assert!(store.get("pears_bearer_token").unwrap().is_none());
    }
}
