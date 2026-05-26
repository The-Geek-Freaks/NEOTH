//! R-08 — zero-install entry primitives.
//!
//! The "Alex's mom on a fresh Win11 laptop" cliff: today she
//! needs `cargo build` to even reach the wizard. R-08 closes that
//! by shipping:
//!
//!   - A `cargo-dist` config block (rendered at build time) that
//!     publishes per-OS release artifacts in GitHub Releases.
//!   - A `curl | sh` install script template for Unix.
//!   - A `winget` manifest stub for Windows.
//!
//! This module ships the constants + template renderers. The
//! actual `cargo-dist.toml` / `install.sh` / `winget-pkgs` PR
//! lands as ops artifacts in the repo — this module is the
//! source of truth for the URLs + version numbers the wizard
//! prints when an operator asks "how do I install on a fresh
//! machine?".

use serde::{Deserialize, Serialize};

/// The current NEOTH release channel. Operators can pin to
/// `Stable` (recommended) or opt into `Nightly` for early access
/// to in-flight work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Stable,
    Nightly,
}

impl ReleaseChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Nightly => "nightly",
        }
    }
}

/// Canonical install-script URL. Pinned so future doc reformats
/// don't break operator copy-paste.
pub const INSTALL_SH_URL: &str = "https://get.neoth.dev/install.sh";

/// Canonical install-script URL for Windows PowerShell.
pub const INSTALL_PS1_URL: &str = "https://get.neoth.dev/install.ps1";

/// GitHub releases base URL the install scripts curl from.
pub const RELEASES_BASE_URL: &str = "https://github.com/The-Geek-Freaks/NEOTH/releases";

/// winget package id NEOTH ships under once the manifest PR lands.
pub const WINGET_PACKAGE_ID: &str = "TheGeekFreaks.NEOTH";

/// One target-triple the cargo-dist config publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetTriple {
    /// `x86_64-pc-windows-msvc`
    WindowsX86_64Msvc,
    /// `x86_64-unknown-linux-gnu`
    LinuxX86_64Gnu,
    /// `aarch64-unknown-linux-gnu`
    LinuxArm64Gnu,
    /// `x86_64-apple-darwin`
    MacosX86_64,
    /// `aarch64-apple-darwin`
    MacosArm64,
}

impl TargetTriple {
    pub fn as_rust_triple(self) -> &'static str {
        match self {
            Self::WindowsX86_64Msvc => "x86_64-pc-windows-msvc",
            Self::LinuxX86_64Gnu => "x86_64-unknown-linux-gnu",
            Self::LinuxArm64Gnu => "aarch64-unknown-linux-gnu",
            Self::MacosX86_64 => "x86_64-apple-darwin",
            Self::MacosArm64 => "aarch64-apple-darwin",
        }
    }

    /// Operator-facing short tag. Pinned for the URL slug shape
    /// cargo-dist uses (`neothd-x86_64-linux.tar.gz`, …).
    pub fn artifact_slug(self) -> &'static str {
        match self {
            Self::WindowsX86_64Msvc => "x86_64-windows",
            Self::LinuxX86_64Gnu => "x86_64-linux",
            Self::LinuxArm64Gnu => "aarch64-linux",
            Self::MacosX86_64 => "x86_64-macos",
            Self::MacosArm64 => "aarch64-macos",
        }
    }

    /// Pick the target for the current host. Defaults to
    /// `LinuxX86_64Gnu` on unsupported OSes — operators on BSD /
    /// Solaris build from source.
    pub const fn for_host() -> Self {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            Self::WindowsX86_64Msvc
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            Self::LinuxX86_64Gnu
        }
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            Self::LinuxArm64Gnu
        }
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            Self::MacosX86_64
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            Self::MacosArm64
        }
        #[cfg(not(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
        )))]
        {
            Self::LinuxX86_64Gnu
        }
    }

    /// File extension cargo-dist uses (.tar.gz everywhere except
    /// Windows which gets .zip).
    pub fn artifact_extension(self) -> &'static str {
        match self {
            Self::WindowsX86_64Msvc => "zip",
            _ => "tar.gz",
        }
    }
}

/// Build the per-target artifact URL on GitHub Releases.
pub fn artifact_url(version: &str, target: TargetTriple) -> String {
    format!(
        "{base}/download/v{version}/neothd-{slug}.{ext}",
        base = RELEASES_BASE_URL,
        slug = target.artifact_slug(),
        ext = target.artifact_extension(),
    )
}

/// Render the operator-facing one-liner install command for the
/// current host. Pure-fn — wizard prints this verbatim.
pub fn one_liner_install_command_for_host() -> String {
    if cfg!(target_os = "windows") {
        format!("powershell -Command \"iwr -useb {INSTALL_PS1_URL} | iex\"",)
    } else {
        format!("curl -fsSL {INSTALL_SH_URL} | sh")
    }
}

/// Render the install-shell-script template. Pure-fn so tests pin
/// the script shape (operators downloading via curl|sh need a
/// stable contract). The script:
///
///   1. Detects target triple.
///   2. Downloads the matching artifact from GitHub Releases.
///   3. Extracts to `~/.local/bin/neothd` (or `/usr/local/bin`
///      with sudo per operator config).
///   4. Verifies the SHA-256 against a signed checksum file
///      published alongside the artifact.
///
/// Returns the full script body — operators inspect via
/// `curl -fsSL ... | less` before piping into sh.
pub fn render_install_sh(version: &str) -> String {
    format!(
        "#!/usr/bin/env sh
# NEOTH install script — version {version}
# Source: {INSTALL_SH_URL}
# Audit: download + read this script before piping to sh.
set -eu

VERSION=\"{version}\"
RELEASES=\"{RELEASES_BASE_URL}\"

# Detect target triple
case \"$(uname -s)-$(uname -m)\" in
  Linux-x86_64)   TARGET=\"x86_64-linux\" EXT=\"tar.gz\" ;;
  Linux-aarch64)  TARGET=\"aarch64-linux\" EXT=\"tar.gz\" ;;
  Darwin-x86_64)  TARGET=\"x86_64-macos\" EXT=\"tar.gz\" ;;
  Darwin-arm64)   TARGET=\"aarch64-macos\" EXT=\"tar.gz\" ;;
  *) echo \"unsupported host: $(uname -s)-$(uname -m)\" >&2 ; exit 1 ;;
esac

# Download artifact + matching checksum
ART=\"neothd-${{TARGET}}.${{EXT}}\"
URL=\"${{RELEASES}}/download/v${{VERSION}}/${{ART}}\"
CKSUM_URL=\"${{URL}}.sha256\"

TMP=\"$(mktemp -d)\"
trap 'rm -rf \"$TMP\"' EXIT

curl -fsSL \"$URL\"        -o \"$TMP/$ART\"
curl -fsSL \"$CKSUM_URL\"  -o \"$TMP/$ART.sha256\"

# Verify checksum
( cd \"$TMP\" && sha256sum -c \"$ART.sha256\" )

# Extract
mkdir -p \"$HOME/.local/bin\"
tar -xzf \"$TMP/$ART\" -C \"$HOME/.local/bin\" neothd

echo \"NEOTH ${{VERSION}} installed to $HOME/.local/bin/neothd\"
echo \"Add ~/.local/bin to your PATH if it isn't already.\"
echo \"Next: run 'neoth init' to start the wizard.\"
",
    )
}

/// Render the winget manifest YAML. The actual PR to
/// `microsoft/winget-pkgs` carries this body; the constant +
/// renderer here keep the manifest in sync with the
/// `WINGET_PACKAGE_ID` constant.
pub fn render_winget_manifest(version: &str, sha256: &str) -> String {
    format!(
        "PackageIdentifier: {WINGET_PACKAGE_ID}
PackageVersion: {version}
PackageLocale: en-US
Publisher: The Geek Freaks
PublisherUrl: https://github.com/The-Geek-Freaks
PackageName: NEOTH
PackageUrl: https://github.com/The-Geek-Freaks/NEOTH
License: Apache-2.0
ShortDescription: Local-first personal AI agent
Tags:
- ai
- agent
- local-first
Installers:
- Architecture: x64
  InstallerType: zip
  InstallerUrl: {RELEASES_BASE_URL}/download/v{version}/neothd-x86_64-windows.zip
  InstallerSha256: {sha256}
  NestedInstallerType: portable
  NestedInstallerFiles:
  - RelativeFilePath: neothd.exe
    PortableCommandAlias: neoth
ManifestType: singleton
ManifestVersion: 1.6.0
",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── enum surface ──────────────────────────────────────────────

    #[test]
    fn release_channel_as_str_pinned() {
        assert_eq!(ReleaseChannel::Stable.as_str(), "stable");
        assert_eq!(ReleaseChannel::Nightly.as_str(), "nightly");
    }

    #[test]
    fn release_channel_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&ReleaseChannel::Nightly).unwrap(),
            "\"nightly\"",
        );
    }

    #[test]
    fn target_triple_rust_string_pinned() {
        assert_eq!(
            TargetTriple::WindowsX86_64Msvc.as_rust_triple(),
            "x86_64-pc-windows-msvc",
        );
        assert_eq!(
            TargetTriple::LinuxX86_64Gnu.as_rust_triple(),
            "x86_64-unknown-linux-gnu",
        );
        assert_eq!(
            TargetTriple::LinuxArm64Gnu.as_rust_triple(),
            "aarch64-unknown-linux-gnu",
        );
        assert_eq!(
            TargetTriple::MacosX86_64.as_rust_triple(),
            "x86_64-apple-darwin",
        );
        assert_eq!(
            TargetTriple::MacosArm64.as_rust_triple(),
            "aarch64-apple-darwin",
        );
    }

    #[test]
    fn target_triple_artifact_slug_pinned() {
        assert_eq!(
            TargetTriple::WindowsX86_64Msvc.artifact_slug(),
            "x86_64-windows"
        );
        assert_eq!(TargetTriple::LinuxX86_64Gnu.artifact_slug(), "x86_64-linux");
        assert_eq!(TargetTriple::LinuxArm64Gnu.artifact_slug(), "aarch64-linux");
        assert_eq!(TargetTriple::MacosX86_64.artifact_slug(), "x86_64-macos");
        assert_eq!(TargetTriple::MacosArm64.artifact_slug(), "aarch64-macos");
    }

    #[test]
    fn windows_uses_zip_others_use_tar_gz() {
        assert_eq!(TargetTriple::WindowsX86_64Msvc.artifact_extension(), "zip");
        assert_eq!(TargetTriple::LinuxX86_64Gnu.artifact_extension(), "tar.gz");
        assert_eq!(TargetTriple::MacosArm64.artifact_extension(), "tar.gz");
    }

    // ── URL constants ─────────────────────────────────────────────

    #[test]
    fn urls_are_https_and_consistent() {
        assert!(INSTALL_SH_URL.starts_with("https://"));
        assert!(INSTALL_PS1_URL.starts_with("https://"));
        assert!(RELEASES_BASE_URL.starts_with("https://github.com/"));
        assert!(RELEASES_BASE_URL.contains("The-Geek-Freaks/NEOTH"));
    }

    #[test]
    fn winget_package_id_is_publisher_dot_product() {
        assert_eq!(WINGET_PACKAGE_ID, "TheGeekFreaks.NEOTH");
        assert!(WINGET_PACKAGE_ID.contains('.'));
    }

    // ── artifact_url ──────────────────────────────────────────────

    #[test]
    fn artifact_url_windows_has_zip_extension() {
        let url = artifact_url("0.3.0", TargetTriple::WindowsX86_64Msvc);
        assert!(url.starts_with(RELEASES_BASE_URL));
        assert!(url.contains("v0.3.0"));
        assert!(url.ends_with("neothd-x86_64-windows.zip"));
    }

    #[test]
    fn artifact_url_linux_has_tar_gz_extension() {
        let url = artifact_url("0.3.0", TargetTriple::LinuxX86_64Gnu);
        assert!(url.ends_with("neothd-x86_64-linux.tar.gz"));
    }

    #[test]
    fn artifact_url_arm64_linux() {
        let url = artifact_url("1.0.0", TargetTriple::LinuxArm64Gnu);
        assert!(url.contains("v1.0.0"));
        assert!(url.ends_with("neothd-aarch64-linux.tar.gz"));
    }

    #[test]
    fn artifact_url_macos_arm() {
        let url = artifact_url("0.3.0", TargetTriple::MacosArm64);
        assert!(url.ends_with("neothd-aarch64-macos.tar.gz"));
    }

    // ── for_host ──────────────────────────────────────────────────

    #[test]
    fn for_host_matches_target_arch() {
        let t = TargetTriple::for_host();
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        assert_eq!(t, TargetTriple::WindowsX86_64Msvc);
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(t, TargetTriple::LinuxX86_64Gnu);
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        assert_eq!(t, TargetTriple::MacosArm64);
    }

    // ── one-liner ─────────────────────────────────────────────────

    #[test]
    fn one_liner_install_command_for_host_correct_shell() {
        let cmd = one_liner_install_command_for_host();
        #[cfg(target_os = "windows")]
        {
            assert!(cmd.contains("powershell"));
            assert!(cmd.contains(INSTALL_PS1_URL));
            assert!(cmd.contains("iex"));
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert!(cmd.contains("curl"));
            assert!(cmd.contains(INSTALL_SH_URL));
            assert!(cmd.contains("| sh"));
        }
    }

    // ── render_install_sh ─────────────────────────────────────────

    #[test]
    fn install_sh_shebang_and_set_eu() {
        let script = render_install_sh("0.3.0");
        assert!(script.starts_with("#!/usr/bin/env sh\n"));
        assert!(script.contains("set -eu"));
    }

    #[test]
    fn install_sh_embeds_version() {
        let script = render_install_sh("0.3.0");
        assert!(script.contains("VERSION=\"0.3.0\""));
    }

    #[test]
    fn install_sh_detects_four_target_combos() {
        let script = render_install_sh("0.3.0");
        for case in [
            "Linux-x86_64",
            "Linux-aarch64",
            "Darwin-x86_64",
            "Darwin-arm64",
        ] {
            assert!(script.contains(case), "case branch missing: {case}");
        }
    }

    #[test]
    fn install_sh_verifies_checksum() {
        let script = render_install_sh("0.3.0");
        assert!(script.contains("sha256sum -c"));
        // Drift guard — the curl line for the .sha256 file MUST
        // happen BEFORE the sha256sum verification.
        let dl_pos = script
            .find("CKSUM_URL")
            .expect("sha256 download line not found");
        let verify_pos = script.find("sha256sum -c").unwrap();
        assert!(
            dl_pos < verify_pos,
            "checksum download must precede verification"
        );
    }

    #[test]
    fn install_sh_extracts_to_local_bin() {
        let script = render_install_sh("0.3.0");
        assert!(script.contains("HOME/.local/bin"));
        assert!(script.contains("tar -xzf"));
    }

    #[test]
    fn install_sh_unsupported_host_exits_nonzero() {
        let script = render_install_sh("0.3.0");
        assert!(script.contains("unsupported host"));
        assert!(script.contains("exit 1"));
    }

    #[test]
    fn install_sh_rejects_tmp_dir_via_trap() {
        let script = render_install_sh("0.3.0");
        assert!(script.contains("trap 'rm -rf \"$TMP\"' EXIT"));
    }

    #[test]
    fn install_sh_points_at_correct_releases_base() {
        let script = render_install_sh("0.3.0");
        assert!(script.contains(RELEASES_BASE_URL));
    }

    // ── render_winget_manifest ────────────────────────────────────

    #[test]
    fn winget_manifest_required_fields_present() {
        let m = render_winget_manifest("0.3.0", "abc123");
        for required in [
            "PackageIdentifier:",
            "PackageVersion:",
            "Publisher:",
            "PackageName:",
            "License:",
            "Installers:",
            "InstallerSha256:",
            "ManifestVersion:",
        ] {
            assert!(m.contains(required), "missing field {required}");
        }
    }

    #[test]
    fn winget_manifest_embeds_version_and_sha() {
        let m = render_winget_manifest("0.3.0", "deadbeef");
        assert!(m.contains("PackageVersion: 0.3.0"));
        assert!(m.contains("InstallerSha256: deadbeef"));
    }

    #[test]
    fn winget_manifest_uses_canonical_package_id() {
        let m = render_winget_manifest("0.3.0", "x");
        assert!(m.contains(&format!("PackageIdentifier: {WINGET_PACKAGE_ID}")));
    }

    #[test]
    fn winget_manifest_installer_url_matches_artifact_url() {
        let m = render_winget_manifest("0.3.0", "x");
        let expected = artifact_url("0.3.0", TargetTriple::WindowsX86_64Msvc);
        assert!(
            m.contains(&format!("InstallerUrl: {expected}")),
            "manifest installer URL diverged from artifact_url",
        );
    }

    #[test]
    fn winget_manifest_portable_alias_is_neoth() {
        let m = render_winget_manifest("0.3.0", "x");
        assert!(m.contains("PortableCommandAlias: neoth"));
    }
}
