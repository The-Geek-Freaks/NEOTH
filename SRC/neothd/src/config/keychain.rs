//! D003-KEYCHAIN-01 — OS keychain integration for secrets at rest.
//!
//! # Dependency decision: windows-sys direct (no `keyring` crate)
//!
//! **Chosen**: `windows-sys 0.59` (`Win32_Security_Credentials` feature) for
//! Windows, with macOS and Linux wired as design notes for follow-on commits.
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
//! # macOS implementation (design note)
//!
//! `security-framework 3` is already in
//! `[target.'cfg(target_os = "macos")'.dependencies]`. Wire with:
//! ```ignore
//! use security_framework::passwords::{
//!     get_generic_password, set_generic_password, delete_generic_password,
//! };
//! // "not found" → errSecItemNotFound = -25300 → Ok(None)
//! fn get(key: &str) -> Result<Option<SecretString>> {
//!     match get_generic_password("neoth", key) {
//!         Ok(bytes) => Ok(Some(SecretString::from(String::from_utf8(bytes)?))),
//!         Err(e) if e.code() == -25300 => Ok(None),
//!         Err(e) => Err(anyhow::anyhow!("Keychain error: {e}")),
//!     }
//! }
//! ```
//!
//! # Linux implementation (design note)
//!
//! `secret-service 4` (rt-tokio-crypto-rust) is in
//! `[target.'cfg(target_os = "linux")'.dependencies]`. Wire with async +
//! a `block_in_place` bridge:
//! ```ignore
//! use secret_service::{EncryptionType, SecretService};
//! // bridge: tokio::task::block_in_place(|| handle.block_on(async { ... }))
//! // "not found" → `secret_service::Error::LockedItem` or empty list → Ok(None)
//! ```
//! Verify that the daemon's systemd unit sets `KeyringMode=inherit` (or
//! similar) so the D-Bus session keyring is reachable from the service context.
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
    "telegram_token",
    "inference_left_key",
    "inference_right_key",
    "inference_cerebellum_key",
    "inference_default_slot_key",
    "whatsapp_token",
    "whatsapp_verify_token",
    "whatsapp_app_secret",
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
    "keet_seed_phrase",
    "pears_bearer_token",
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
        let map = self
            .data
            .lock()
            .expect("InMemorySecretStore lock poisoned");
        Ok(map.get(key).map(|v| SecretString::from(v.clone())))
    }

    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        let mut map = self
            .data
            .lock()
            .expect("InMemorySecretStore lock poisoned");
        map.insert(key.to_string(), value.expose().to_string());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut map = self
            .data
            .lock()
            .expect("InMemorySecretStore lock poisoned");
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
            GetLastError, ERROR_NOT_FOUND, ERROR_NO_SUCH_LOGON_SESSION,
        };
        use windows_sys::Win32::Security::Credentials::{CredFree, CredReadW, CRED_TYPE_GENERIC};

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
        let value =
            String::from_utf8(blob_bytes).context("Windows Credential Manager blob is not UTF-8")?;
        Ok(Some(SecretString::from(value)))
    }

    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        use windows_sys::Win32::Foundation::{GetLastError, FILETIME};
        use windows_sys::Win32::Security::Credentials::{
            CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
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
        use windows_sys::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};

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
            anyhow::bail!(
                "CredDeleteW failed for key \"{key}\": Win32 error {err}"
            );
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

// ── macOS stub ───────────────────────────────────────────────────────────────

/// macOS Keychain placeholder — see module-level doc for the wiring plan.
#[cfg(all(target_os = "macos", feature = "keychain"))]
pub(super) struct MacCredStore;

#[cfg(all(target_os = "macos", feature = "keychain"))]
impl SecretStore for MacCredStore {
    fn get(&self, _key: &str) -> Result<Option<SecretString>> {
        anyhow::bail!(
            "macOS Keychain not yet wired (D003 follow-on). \
             Use `neoth credential migrate --to file` to restore plaintext mode, \
             or build NEOTH from source once the macOS implementation is merged."
        )
    }

    fn set(&self, _key: &str, _value: &SecretString) -> Result<()> {
        self.get("").map(|_| ())
    }

    fn delete(&self, _key: &str) -> Result<()> {
        self.get("").map(|_| ())
    }

    fn backend_name(&self) -> &'static str {
        "macOS Keychain (not yet wired)"
    }
}

// ── Linux stub ───────────────────────────────────────────────────────────────

/// Linux Secret Service placeholder — see module-level doc for the wiring plan.
#[cfg(all(target_os = "linux", feature = "keychain"))]
pub(super) struct LinuxCredStore;

#[cfg(all(target_os = "linux", feature = "keychain"))]
impl SecretStore for LinuxCredStore {
    fn get(&self, _key: &str) -> Result<Option<SecretString>> {
        anyhow::bail!(
            "Linux Secret Service not yet wired (D003 follow-on). \
             Ensure `secret-service` D-Bus session is available and the \
             `keychain` cargo feature is enabled, then rebuild once the \
             async bridge is merged."
        )
    }

    fn set(&self, _key: &str, _value: &SecretString) -> Result<()> {
        self.get("").map(|_| ())
    }

    fn delete(&self, _key: &str) -> Result<()> {
        self.get("").map(|_| ())
    }

    fn backend_name(&self) -> &'static str {
        "Linux Secret Service (not yet wired)"
    }
}

// ── factory ──────────────────────────────────────────────────────────────────

/// Open the platform-appropriate OS secret store.
///
/// Returns `Err` when:
/// - The `keychain` cargo feature is not compiled in.
/// - The current platform has no wired implementation yet (macOS, Linux stubs).
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
///    [`Credentials::write`]).
/// 2. Persisting `secrets_backend: keychain` into `freedom.yaml` (via
///    [`FreedomConfig::save_public_to_default_path`]).
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

    // Serialize to a YAML value so we can access fields by name without
    // exhaustive pattern matching.  The transparent SecretString serialisation
    // produces plain YAML strings — we re-wrap them as SecretString on write.
    let mut yaml_val =
        serde_yaml::to_value(creds).context("serialize Credentials for migration")?;

    let mapping = yaml_val
        .as_mapping_mut()
        .context("Credentials serialised to a non-mapping value")?;

    for &field in SECRET_FIELD_KEYS {
        let yaml_key = serde_yaml::Value::String(field.to_string());
        match mapping.get(&yaml_key).and_then(|v| v.as_str()) {
            None => {
                skipped.push(field.to_string());
            }
            Some(raw) => {
                let secret = SecretString::from(raw.to_string());
                if !dry_run {
                    match store.set(field, &secret) {
                        Ok(()) => {
                            // Blank the field in the mapping so the returned
                            // Credentials omits it from credentials.yaml.
                            mapping.insert(yaml_key, serde_yaml::Value::Null);
                            moved.push(field.to_string());
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

    // Rollback: if any field failed to set, undo the sets we DID make this run
    // so the keychain returns to its pre-migration state. Without this a late
    // failure leaves a partial keychain write while the caller (on
    // !is_clean()) skips the credentials.yaml write — an inconsistent dual
    // state where the secret sits in BOTH backends yet the CLI reports "nothing
    // written". After rollback that message is truthful again.
    if !dry_run && !failed.is_empty() && !moved.is_empty() {
        for key in &moved {
            let _ = store.delete(key); // best-effort; nothing better to do on a failed rollback
        }
        moved.clear();
    }

    // On a clean dry_run the blanked struct is unused; on a clean real run it is
    // written by the caller. On a rolled-back failure the caller aborts and this
    // value is discarded — but recompute it from the (possibly mutated) yaml so
    // it never claims fields were blanked when we rolled their keychain sets back.
    let blanked: crate::config::credentials::Credentials = if dry_run || !failed.is_empty() {
        creds.clone()
    } else {
        serde_yaml::from_value(yaml_val).context("deserialize blanked Credentials")?
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

    let mut yaml_val =
        serde_yaml::to_value(creds).context("serialize Credentials for reverse migration")?;
    let mapping = yaml_val
        .as_mapping_mut()
        .context("Credentials serialised to a non-mapping value")?;

    for &field in SECRET_FIELD_KEYS {
        match store.get(field) {
            Err(e) => {
                failed.push((field.to_string(), e.to_string()));
            }
            Ok(None) => {
                skipped.push(field.to_string());
            }
            Ok(Some(secret)) => {
                if !dry_run {
                    // Populate the field in the file result. NO delete here —
                    // the keychain is purged later, only after the file lands.
                    let yaml_key = serde_yaml::Value::String(field.to_string());
                    mapping.insert(
                        yaml_key,
                        serde_yaml::Value::String(secret.expose().to_string()),
                    );
                }
                moved.push(field.to_string());
            }
        }
    }

    let populated: crate::config::credentials::Credentials = if dry_run {
        creds.clone()
    } else {
        serde_yaml::from_value(yaml_val).context("deserialize populated Credentials")?
    };

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
/// the supplement: the 31 successful lookups must not be discarded because 1
/// field fails (e.g. a single corrupted credential entry). The caller
/// (`load_from_path`) already logs at `warn!` on any `Err` returned here; for
/// a partial OS-error during supplement, logging per-field is more actionable.
pub fn supplement_from_store(
    creds: &mut crate::config::credentials::Credentials,
    store: &dyn SecretStore,
) -> Result<()> {
    let mut yaml_val =
        serde_yaml::to_value(&*creds).context("serialize Credentials for keychain supplement")?;
    let mapping = yaml_val
        .as_mapping_mut()
        .context("Credentials serialised to a non-mapping value")?;

    for &field in SECRET_FIELD_KEYS {
        let yaml_key = serde_yaml::Value::String(field.to_string());
        // Only fill fields that are absent or null in the YAML load.
        let already_set = mapping
            .get(&yaml_key)
            .map(|v| !v.is_null())
            .unwrap_or(false);
        if already_set {
            continue;
        }
        match store.get(field) {
            Ok(None) => {} // not in store either — leave as None
            Ok(Some(secret)) => {
                mapping.insert(
                    yaml_key,
                    serde_yaml::Value::String(secret.expose().to_string()),
                );
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

    *creds =
        serde_yaml::from_value(yaml_val).context("deserialize keychain-supplemented Credentials")?;
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
    fn migrate_to_file_restores_values_and_deletes_from_store() {
        let store = InMemorySecretStore::default();
        store
            .set("provider_key", &SecretString::from("sk-restored".to_string()))
            .unwrap();
        store
            .set("telegram_token", &SecretString::from("bot-restored".to_string()))
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

        // Store must now be empty for those keys.
        assert!(store.get("provider_key").unwrap().is_none());
        assert!(store.get("telegram_token").unwrap().is_none());
    }

    #[test]
    fn migrate_to_file_dry_run_skips_delete() {
        let store = InMemorySecretStore::default();
        store
            .set("cluster_passphrase", &SecretString::from("pass123".to_string()))
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
            .set("provider_key", &SecretString::from("sk-from-store".to_string()))
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
            .set("provider_key", &SecretString::from("sk-partial".to_string()))
            .unwrap();
        inner
            .set("telegram_token", &SecretString::from("bot-should-fail".to_string()))
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

        // keychain → file
        let (restored, r2) = migrate_to_file(&blanked, &store, false).unwrap();
        assert!(r2.is_clean());
        assert_eq!(restored.provider_key.as_ref().unwrap().expose(), "sk-roundtrip");
        assert_eq!(
            restored.telegram_token.as_ref().unwrap().expose(),
            "bot-roundtrip"
        );

        // Store is now empty.
        assert!(store.get("provider_key").unwrap().is_none());
    }
}
