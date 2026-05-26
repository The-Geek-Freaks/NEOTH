//! C-04 — Firefox `logins.json` + `key4.db` importer
//! (availability + path probe).
//!
//! Firefox stores credentials in:
//!   - `logins.json` (per-profile, encrypted blobs)
//!   - `key4.db` (SQLite holding the AES-256-GCM master key
//!     derived from the operator's primary password)
//!
//! Decrypt requires NSS (`certutil -d <profile> -K` to unlock the
//! master key, then PBKDF2-derive + decrypt). NEOTH spawns
//! `certutil` as a subprocess in C-04b. **Today** this module
//! ships path discovery + availability probe + profile-picker
//! primitives.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::credentials::{CredentialImporter, DiscoveredCredentials, ImportSource};

/// Per-OS Firefox profile-root directory.
pub fn firefox_profile_root() -> Option<PathBuf> {
    let home: PathBuf = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var_os("APPDATA").map(PathBuf::from);
        Some(
            appdata
                .unwrap_or_else(|| home.join("AppData").join("Roaming"))
                .join("Mozilla")
                .join("Firefox"),
        )
    }
    #[cfg(target_os = "macos")]
    {
        Some(
            home.join("Library")
                .join("Application Support")
                .join("Firefox"),
        )
    }
    #[cfg(target_os = "linux")]
    {
        Some(home.join(".mozilla").join("firefox"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = home;
        None
    }
}

/// Path to the operator's `profiles.ini` index file.
pub fn profiles_ini_path() -> Option<PathBuf> {
    firefox_profile_root().map(|r| r.join("profiles.ini"))
}

/// Parse the `Path=` lines from a `profiles.ini` body. Returns
/// the relative path per profile (caller joins with
/// `firefox_profile_root()`).
pub fn parse_profiles_ini(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|l| {
            let trimmed = l.trim();
            trimmed.strip_prefix("Path=").map(|p| p.trim().to_string())
        })
        .filter(|p| !p.is_empty())
        .collect()
}

/// Pick the operator's default profile from a `profiles.ini`
/// body. Looks for the `Default=1` flag; falls back to the first
/// profile when none is marked default.
pub fn pick_default_profile(body: &str) -> Option<String> {
    // Walk sections — when a section has Default=1, return its
    // Path. INI parsing is intentionally tiny + permissive.
    let mut current_path: Option<String> = None;
    let mut current_default = false;
    let mut found: Option<String> = None;
    let mut first: Option<String> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            // New section — commit prior + reset.
            if current_default {
                if let Some(p) = current_path.clone() {
                    found = Some(p);
                }
            }
            current_path = None;
            current_default = false;
            continue;
        }
        if let Some(p) = trimmed.strip_prefix("Path=") {
            let p = p.trim().to_string();
            if first.is_none() {
                first = Some(p.clone());
            }
            current_path = Some(p);
        } else if trimmed == "Default=1" {
            current_default = true;
        }
    }
    // Trailing section.
    if current_default {
        if let Some(p) = current_path {
            found = Some(p);
        }
    }
    found.or(first)
}

/// Importer impl. C-04b ships the NSS subprocess + key4.db read.
pub struct FirefoxImporter;

#[async_trait]
impl CredentialImporter for FirefoxImporter {
    fn source(&self) -> ImportSource {
        ImportSource::WizardPrompt
    }

    fn name(&self) -> &'static str {
        "Firefox logins.json + key4.db (decrypt gated to C-04b)"
    }

    async fn is_available(&self) -> bool {
        profiles_ini_path().map(|p| p.exists()).unwrap_or(false)
    }

    async fn discover_entries(&self) -> Result<DiscoveredCredentials, String> {
        let mut warnings = vec![format!(
            "Firefox profile root found at {:?} but NSS decrypt is gated. \
             C-04b ships the certutil subprocess + key4.db read; today the \
             importer returns zero credentials so operators see the surface \
             without false-success.",
            firefox_profile_root(),
        )];
        // Attempt to read profiles.ini to surface profile count.
        if let Some(ini_path) = profiles_ini_path() {
            if let Ok(body) = tokio::fs::read_to_string(&ini_path).await {
                let profiles = parse_profiles_ini(&body);
                warnings.push(format!("found {} Firefox profile(s)", profiles.len()));
                if let Some(default) = pick_default_profile(&body) {
                    warnings.push(format!("default profile: {default}"));
                }
            }
        }
        Ok(DiscoveredCredentials {
            source: ImportSource::WizardPrompt,
            entries: Vec::new(),
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firefox_profile_root_some_on_supported_os() {
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        assert!(firefox_profile_root().is_some());
    }

    #[test]
    fn profiles_ini_path_under_profile_root() {
        if let (Some(root), Some(ini)) = (firefox_profile_root(), profiles_ini_path()) {
            assert!(ini.starts_with(&root));
            assert!(ini.ends_with("profiles.ini"));
        }
    }

    // ── parse_profiles_ini ────────────────────────────────────────

    #[test]
    fn parse_extracts_path_lines() {
        let body = "[Profile0]\nName=default\nPath=abc123.default\nIsRelative=1\n\
                    [Profile1]\nName=work\nPath=xyz789.work\nIsRelative=1\n";
        let paths = parse_profiles_ini(body);
        assert_eq!(paths, vec!["abc123.default", "xyz789.work"]);
    }

    #[test]
    fn parse_skips_empty_path_lines() {
        let body = "Path=\nPath=real-profile.default\n";
        let paths = parse_profiles_ini(body);
        assert_eq!(paths, vec!["real-profile.default"]);
    }

    #[test]
    fn parse_empty_body_returns_empty() {
        assert!(parse_profiles_ini("").is_empty());
    }

    #[test]
    fn parse_handles_windows_crlf() {
        let body = "[Profile0]\r\nPath=abc.default\r\n";
        let paths = parse_profiles_ini(body);
        assert_eq!(paths, vec!["abc.default"]);
    }

    // ── pick_default_profile ──────────────────────────────────────

    #[test]
    fn pick_default_returns_marked_profile() {
        let body = "[Profile0]\nName=other\nPath=other.profile\n\
                    [Profile1]\nName=default\nPath=default.profile\nDefault=1\n";
        assert_eq!(
            pick_default_profile(body),
            Some("default.profile".to_string())
        );
    }

    #[test]
    fn pick_default_falls_back_to_first_when_none_marked() {
        let body = "[Profile0]\nPath=first.profile\n\
                    [Profile1]\nPath=second.profile\n";
        assert_eq!(
            pick_default_profile(body),
            Some("first.profile".to_string())
        );
    }

    #[test]
    fn pick_default_empty_body_returns_none() {
        assert!(pick_default_profile("").is_none());
    }

    #[test]
    fn pick_default_when_default_is_last_section() {
        // Default=1 in the LAST section — make sure the
        // commit-on-section-boundary logic catches it.
        let body = "[Profile0]\nPath=a.profile\n\
                    [Profile1]\nPath=b.profile\nDefault=1\n";
        assert_eq!(pick_default_profile(body), Some("b.profile".to_string()));
    }

    // ── importer trait ────────────────────────────────────────────

    #[tokio::test]
    async fn importer_is_available_returns_bool_without_panic() {
        let imp = FirefoxImporter;
        let _ = imp.is_available().await;
    }

    #[tokio::test]
    async fn importer_discover_returns_warning_not_error() {
        let imp = FirefoxImporter;
        let d = imp.discover_entries().await.expect("must not error");
        assert!(d.entries.is_empty());
        assert!(!d.warnings.is_empty());
        assert!(d.warnings[0].contains("C-04b"));
    }

    #[test]
    fn importer_name_mentions_gated_decrypt() {
        let imp = FirefoxImporter;
        assert!(imp.name().contains("gated"));
    }
}
