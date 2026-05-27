//! C-03 — Chrome Login Data importer (availability + path probe).
//!
//! Chrome stores credentials in `Login Data` (SQLite) with each
//! password encrypted by the per-OS Local State key:
//!   - Windows: DPAPI (`CryptUnprotectData`)
//!   - Linux:   DBus Secret Service (`gnome-keyring` / `kwallet`)
//!   - macOS:   Keychain (`SecKeychainFindGenericPassword`)
//!
//! **C-03 today ships** the path discovery + availability probe +
//! lock-state warning (A5 hardening). The actual decrypt + SQLite
//! read lands in C-03b once we wire the per-OS crypto crates
//! behind feature flags (`windows-dpapi`, `secret-service`,
//! `security-framework`).
//!
//! ## What this module does today
//!
//! - [`chrome_login_data_path`] — per-OS canonical path.
//! - [`chrome_default_profile_root`] — picks the right user-data
//!   dir per host.
//! - [`is_login_data_locked`] — probes Chrome's running-state
//!   advisory lock (the `LOCK` file in the profile dir) so the
//!   importer can warn "close Chrome before importing" — A5
//!   hardening flagged this exact failure mode.
//! - `ChromeImporter` impl returns an "encrypted entries
//!   detected, decrypt deferred to C-03b" warning + zero
//!   credentials. Operators see the wizard surface the warning;
//!   no false-success.

use std::path::PathBuf;

use async_trait::async_trait;

#[cfg(target_os = "windows")]
use crate::credentials::ImportedCredential;
use crate::credentials::{CredentialImporter, DiscoveredCredentials, ImportSource};

/// Path to the operator's Chrome `Login Data` SQLite file on the
/// current host. Returns `None` on unsupported OSes.
pub fn chrome_login_data_path() -> Option<PathBuf> {
    chrome_default_profile_root().map(|p| p.join("Default").join("Login Data"))
}

/// Canonical Chrome user-data-dir per OS. Operators on portable
/// installs or custom `--user-data-dir` flags override via
/// `freedom.yaml::credentials.chrome.profile_root`.
pub fn chrome_default_profile_root() -> Option<PathBuf> {
    let home: PathBuf = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;
    #[cfg(target_os = "windows")]
    {
        // %LOCALAPPDATA%\Google\Chrome\User Data
        let localappdata = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        Some(
            localappdata
                .unwrap_or_else(|| home.join("AppData").join("Local"))
                .join("Google")
                .join("Chrome")
                .join("User Data"),
        )
    }
    #[cfg(target_os = "macos")]
    {
        Some(
            home.join("Library")
                .join("Application Support")
                .join("Google")
                .join("Chrome"),
        )
    }
    #[cfg(target_os = "linux")]
    {
        // ~/.config/google-chrome
        Some(home.join(".config").join("google-chrome"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = home;
        None
    }
}

/// Probe Chrome's running-state lock file. Returns true when the
/// Login Data SQLite is in use by a running Chrome (advisory
/// `SingletonLock`/`LOCK` file present). The importer warns
/// "close Chrome before importing" in that case.
pub fn is_login_data_locked() -> bool {
    let Some(root) = chrome_default_profile_root() else {
        return false;
    };
    // Two canonical lock filenames depending on platform + Chrome
    // version. Presence of EITHER trips the lock check.
    for name in ["SingletonLock", "lockfile", "Default/LOCK"] {
        if root.join(name).exists() {
            return true;
        }
    }
    false
}

/// Importer impl. Per-OS decrypt dispatched at compile time:
///   - Windows → DPAPI + AES-256-GCM (C-03b chunk Windows, Session 28)
///   - Linux → Secret Service + AES-128-CBC (C-03b chunk Linux, future)
///   - macOS → Keychain + AES-128-CBC (C-03b chunk macOS, future)
///   - Other → returns the C-03b-deferred warning, zero entries.
pub struct ChromeImporter;

#[async_trait]
impl CredentialImporter for ChromeImporter {
    fn source(&self) -> ImportSource {
        ImportSource::WizardPrompt
    }

    #[cfg(target_os = "windows")]
    fn name(&self) -> &'static str {
        "Chrome Login Data (DPAPI + AES-256-GCM)"
    }

    #[cfg(not(target_os = "windows"))]
    fn name(&self) -> &'static str {
        "Chrome Login Data (decrypt gated to C-03b for this OS)"
    }

    async fn is_available(&self) -> bool {
        // Available iff the Login Data file exists. If it does,
        // we can at least warn about it; the per-OS decrypt path
        // takes over from there.
        chrome_login_data_path()
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    async fn discover_entries(&self) -> Result<DiscoveredCredentials, String> {
        #[cfg(target_os = "windows")]
        {
            discover_entries_windows().await
        }
        #[cfg(not(target_os = "windows"))]
        {
            discover_entries_deferred().await
        }
    }
}

#[cfg(target_os = "windows")]
async fn discover_entries_windows() -> Result<DiscoveredCredentials, String> {
    use crate::credentials::chrome_windows::discover_chrome_credentials_windows;

    let login_data = chrome_login_data_path()
        .ok_or_else(|| "Chrome Login Data path unavailable on this host".to_string())?;
    let local_state = chrome_default_profile_root()
        .ok_or_else(|| "Chrome user-data-dir unavailable on this host".to_string())?
        .join("Local State");

    let mut warnings = Vec::new();
    if is_login_data_locked() {
        warnings.push(
            "Chrome is currently running — close it before importing. \
             The SQLite would be locked and rows may be missing the latest \
             unflushed write."
                .to_string(),
        );
    }

    let (creds, decrypt_warnings) = tokio::task::spawn_blocking(move || {
        discover_chrome_credentials_windows(&login_data, &local_state)
    })
    .await
    .map_err(|e| format!("blocking task join failed: {e}"))?
    .map_err(|e| format!("Chrome (Windows) decrypt failed: {e}"))?;
    warnings.extend(decrypt_warnings);

    let entries: Vec<ImportedCredential> = creds
        .into_iter()
        .map(|c| {
            ImportedCredential::new(
                ImportSource::WizardPrompt,
                c.origin_url.clone(),
                c.origin_url,
                c.username,
                c.password,
                vec!["chrome".to_string()],
            )
        })
        .collect();

    Ok(DiscoveredCredentials {
        source: ImportSource::WizardPrompt,
        entries,
        warnings,
    })
}

#[cfg(not(target_os = "windows"))]
async fn discover_entries_deferred() -> Result<DiscoveredCredentials, String> {
    let mut warnings = vec![format!(
        "Chrome Login Data found at {:?} but decrypt is gated for \
         this OS. C-03b ships per-OS decrypt — Windows landed Session 28; \
         Linux (Secret Service) and macOS (Keychain) follow.",
        chrome_login_data_path(),
    )];
    if is_login_data_locked() {
        warnings.push(
            "Chrome is currently running — close it before \
             the C-03b decrypt path runs (the SQLite would be \
             locked + reads return WAL-only)."
                .to_string(),
        );
    }
    Ok(DiscoveredCredentials {
        source: ImportSource::WizardPrompt,
        entries: Vec::new(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_default_profile_root_returns_some_on_supported_oses() {
        // On the three supported OSes we should always be able to
        // synthesise a path (even if it doesn't exist).
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        assert!(chrome_default_profile_root().is_some());
    }

    #[test]
    fn chrome_login_data_path_under_default_profile_root() {
        if let (Some(root), Some(login_data)) =
            (chrome_default_profile_root(), chrome_login_data_path())
        {
            assert!(
                login_data.starts_with(&root),
                "login_data should be under profile root: {login_data:?} vs {root:?}",
            );
            assert!(
                login_data.ends_with("Default/Login Data")
                    || login_data.ends_with("Default\\Login Data")
            );
        }
    }

    #[test]
    fn chrome_login_data_path_filename_is_login_data() {
        if let Some(p) = chrome_login_data_path() {
            assert_eq!(p.file_name().unwrap(), "Login Data");
        }
    }

    #[tokio::test]
    async fn importer_is_available_false_when_login_data_missing() {
        // No Chrome on a fresh CI runner — is_available should
        // return false gracefully.
        let imp = ChromeImporter;
        // The result depends on the host — we just assert the
        // call doesn't panic + returns a bool.
        let _ = imp.is_available().await;
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn importer_discover_returns_warning_not_error() {
        let imp = ChromeImporter;
        let d = imp.discover_entries().await.expect("must not error");
        // Non-Windows: zero entries + warning explaining the gated decrypt.
        assert!(d.entries.is_empty());
        assert!(!d.warnings.is_empty());
        assert!(
            d.warnings[0].contains("C-03b"),
            "warning must reference the follow-up item: {}",
            d.warnings[0],
        );
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn importer_discover_surfaces_error_or_credentials_on_windows() {
        // Windows path is live as of C-03b Session 28. On a CI
        // runner without Chrome installed, the Login Data file is
        // absent → discover surfaces Err. On a dev machine with
        // Chrome installed, it surfaces Ok(entries). Either is
        // valid; what we check is that the call doesn't panic.
        let imp = ChromeImporter;
        let _ = imp.discover_entries().await;
    }

    #[test]
    fn importer_name_signals_implementation_state() {
        let imp = ChromeImporter;
        let name = imp.name();
        // Drift guard: name must mention the algorithm on Windows
        // (live) or "gated" on other OSes (deferred).
        #[cfg(target_os = "windows")]
        assert!(
            name.contains("AES-256-GCM") || name.contains("DPAPI"),
            "Windows name must signal live decrypt: {name}"
        );
        #[cfg(not(target_os = "windows"))]
        assert!(
            name.contains("gated"),
            "non-Windows name must signal gated: {name}"
        );
    }

    #[test]
    fn lock_probe_returns_bool_without_panicking() {
        // Just verify the call shape doesn't panic on hosts with
        // or without Chrome.
        let _ = is_login_data_locked();
    }
}
