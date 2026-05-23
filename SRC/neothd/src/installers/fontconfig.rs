//! NOOB-UX-6 sub-gap (4) — Linux fontconfig install hint primitive.
//!
//! Slint GUI text rendering depends on fontconfig (libfontconfig1) on
//! Linux. macOS gets CoreText for free; Windows ships GDI+DirectWrite.
//! Some minimal Linux distros (Alpine, slim Docker images, certain
//! server-flavour Debian / Fedora) don't ship the fontconfig package
//! by default — Slint then crashes at first text render with
//! "Couldn't load default font" instead of a clear "install
//! libfontconfig1" message.
//!
//! This module ships the **distro-hint primitive** the wizard
//! consults BEFORE spawning the GUI binary. Pure-fn surface; the
//! actual install is the operator's call per the AGENTER "operator
//! GO per command" rule.

use std::time::Duration;

use tokio::process::Command;

/// One of the fontconfig install paths. Pinned: only Linux is
/// addressable here; macOS + Windows skip the gate entirely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FontconfigStatus {
    /// fontconfig already installed (detected via `fc-list` succeeding).
    AlreadyInstalled,
    /// Linux host without fontconfig — wizard surfaces the install
    /// hint with per-distro commands.
    MissingOnLinux,
    /// Non-Linux host — Windows GDI / macOS CoreText handle it.
    NotApplicable,
}

impl FontconfigStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlreadyInstalled => "already_installed",
            Self::MissingOnLinux => "missing_on_linux",
            Self::NotApplicable => "not_applicable",
        }
    }

    /// Operator-facing one-line description.
    pub fn description(self) -> &'static str {
        match self {
            Self::AlreadyInstalled => "fontconfig already installed — Slint GUI text will render",
            Self::MissingOnLinux => {
                "fontconfig missing — Slint GUI text won't render. Install before launching `neoth gui`."
            }
            Self::NotApplicable => {
                "fontconfig not needed on this OS (Windows uses GDI / macOS uses CoreText)"
            }
        }
    }
}

/// Build the distro install hint. Pure-fn so the wizard renders
/// the exact command to the operator before they run sudo.
/// `AlreadyInstalled` + `NotApplicable` return empty since no
/// install is needed.
pub fn install_hint(status: FontconfigStatus) -> Vec<String> {
    match status {
        FontconfigStatus::AlreadyInstalled | FontconfigStatus::NotApplicable => Vec::new(),
        FontconfigStatus::MissingOnLinux => vec![
            "echo".into(),
            "Operator: install fontconfig — \
             Ubuntu/Debian → `sudo apt install libfontconfig1`, \
             Fedora → `sudo dnf install fontconfig`, \
             Arch → `sudo pacman -S fontconfig`, \
             Alpine → `sudo apk add fontconfig ttf-dejavu`, \
             openSUSE → `sudo zypper install fontconfig`. \
             Verify with `fc-list | head` (should print font paths)."
                .into(),
        ],
    }
}

/// Probe `fc-list` (the canonical fontconfig binary). Returns
/// `Some(version-like-string)` when fontconfig is installed + the
/// font-cache has at least one entry. On non-Linux OS we
/// short-circuit to `Some(_)` representing "OS provides fonts
/// natively" so the wizard doesn't false-flag macOS/Windows.
pub async fn detect_fontconfig() -> FontconfigStatus {
    if cfg!(target_os = "windows") || cfg!(target_os = "macos") {
        return FontconfigStatus::NotApplicable;
    }
    // Linux path: probe fc-list. Empty output (no fonts cached) is
    // technically "fontconfig installed but no fonts" — treat as
    // installed for the wizard's purpose since the operator can
    // still install fonts separately. Missing binary → not installed.
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        Command::new("fc-list")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status(),
    )
    .await;
    match result {
        Ok(Ok(status)) if status.success() => FontconfigStatus::AlreadyInstalled,
        _ => FontconfigStatus::MissingOnLinux,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_as_str_pinned() {
        assert_eq!(
            FontconfigStatus::AlreadyInstalled.as_str(),
            "already_installed"
        );
        assert_eq!(
            FontconfigStatus::MissingOnLinux.as_str(),
            "missing_on_linux"
        );
        assert_eq!(FontconfigStatus::NotApplicable.as_str(), "not_applicable");
    }

    #[test]
    fn descriptions_distinct_per_status() {
        let descs = [
            FontconfigStatus::AlreadyInstalled.description(),
            FontconfigStatus::MissingOnLinux.description(),
            FontconfigStatus::NotApplicable.description(),
        ];
        let unique: std::collections::HashSet<_> = descs.iter().collect();
        assert_eq!(descs.len(), unique.len());
    }

    #[test]
    fn install_hint_for_already_installed_is_empty() {
        assert!(install_hint(FontconfigStatus::AlreadyInstalled).is_empty());
    }

    #[test]
    fn install_hint_for_not_applicable_is_empty() {
        // Windows/macOS operators never see this hint.
        assert!(install_hint(FontconfigStatus::NotApplicable).is_empty());
    }

    #[test]
    fn install_hint_for_linux_lists_4plus_distros() {
        // Drift guard — Alpine is the operator-painful one (slim
        // Docker images). Pin all 5 distros so a copy edit can't
        // silently drop coverage.
        let hint = install_hint(FontconfigStatus::MissingOnLinux);
        assert!(!hint.is_empty());
        let joined = hint.join(" ").to_lowercase();
        assert!(joined.contains("apt"));
        assert!(joined.contains("dnf"));
        assert!(joined.contains("pacman"));
        assert!(joined.contains("apk"));
        assert!(joined.contains("zypper"));
        // The verification command must also appear so the operator
        // knows the install landed.
        assert!(joined.contains("fc-list"));
    }

    #[tokio::test]
    async fn detect_fontconfig_returns_not_applicable_on_windows_or_macos() {
        if cfg!(target_os = "windows") || cfg!(target_os = "macos") {
            assert_eq!(detect_fontconfig().await, FontconfigStatus::NotApplicable);
        }
    }

    #[tokio::test]
    async fn detect_fontconfig_returns_definite_status_on_linux() {
        if !cfg!(target_os = "windows") && !cfg!(target_os = "macos") {
            let status = detect_fontconfig().await;
            // Whatever the operator's host state, the function must
            // return AlreadyInstalled or MissingOnLinux — never
            // NotApplicable on Linux.
            assert_ne!(status, FontconfigStatus::NotApplicable);
        }
    }
}
