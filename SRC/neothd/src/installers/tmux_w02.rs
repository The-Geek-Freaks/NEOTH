//! W-02 — tmux extensions complementing the existing
//! [`super::tmux`] surface.
//!
//! The base module ships the install-path picker + recommend
//! logic. W-02 adds:
//!
//!   - [`LinuxDistro`] + [`pick_linux_install_command`] so the
//!     `PackageManagerLinux` variant resolves to a concrete
//!     `sudo apt install tmux` (or equivalent) — the operator
//!     no longer has to read the help text + retype the command.
//!   - [`parse_tmux_version`] — extracts the `3.4` from
//!     `tmux 3.4` output so the wizard can check minimum
//!     version (3.0+ for the warm-session features NEOTH uses).
//!   - [`version_meets_minimum`] — pure-fn comparator.

use serde::{Deserialize, Serialize};

/// One Linux distro family. Pinned exhaustively so adding a new
/// distro gets caught at PR review (matches W-05's
/// `winget → choco / apt / dnf / pacman / brew` chain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxDistro {
    /// Debian / Ubuntu / Mint / Pop — apt.
    DebianFamily,
    /// Fedora / RHEL / CentOS Stream / Rocky — dnf.
    FedoraFamily,
    /// Arch / Manjaro / EndeavourOS — pacman.
    ArchFamily,
    /// openSUSE Tumbleweed/Leap — zypper.
    SuseFamily,
    /// Couldn't classify — wizard renders the generic help text.
    Unknown,
}

impl LinuxDistro {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DebianFamily => "debian_family",
            Self::FedoraFamily => "fedora_family",
            Self::ArchFamily => "arch_family",
            Self::SuseFamily => "suse_family",
            Self::Unknown => "unknown",
        }
    }

    /// Classify from `/etc/os-release`'s `ID` and `ID_LIKE`
    /// fields. Pure-fn — caller does the file-read. Lowercase
    /// match.
    pub fn from_os_release_ids(id: &str, id_like: &str) -> Self {
        let candidates: Vec<&str> = std::iter::once(id)
            .chain(id_like.split_whitespace())
            .collect();
        for c in &candidates {
            let lc = c.to_lowercase();
            if matches!(lc.as_str(), "debian" | "ubuntu" | "linuxmint" | "pop" | "raspbian") {
                return Self::DebianFamily;
            }
            if matches!(lc.as_str(), "fedora" | "rhel" | "centos" | "rocky" | "alma") {
                return Self::FedoraFamily;
            }
            if matches!(lc.as_str(), "arch" | "manjaro" | "endeavouros" | "garuda") {
                return Self::ArchFamily;
            }
            if matches!(lc.as_str(), "opensuse-tumbleweed" | "opensuse-leap" | "suse" | "opensuse") {
                return Self::SuseFamily;
            }
        }
        Self::Unknown
    }
}

/// Build the actual install command for `distro`. Returns empty
/// when distro is `Unknown` — wizard falls back to the existing
/// text hint in `super::tmux::install_command`.
pub fn pick_linux_install_command(distro: LinuxDistro) -> Vec<String> {
    match distro {
        LinuxDistro::DebianFamily => vec![
            "sudo".into(),
            "apt".into(),
            "install".into(),
            "-y".into(),
            "tmux".into(),
        ],
        LinuxDistro::FedoraFamily => vec![
            "sudo".into(),
            "dnf".into(),
            "install".into(),
            "-y".into(),
            "tmux".into(),
        ],
        LinuxDistro::ArchFamily => vec![
            "sudo".into(),
            "pacman".into(),
            "-S".into(),
            "--noconfirm".into(),
            "tmux".into(),
        ],
        LinuxDistro::SuseFamily => vec![
            "sudo".into(),
            "zypper".into(),
            "install".into(),
            "-y".into(),
            "tmux".into(),
        ],
        LinuxDistro::Unknown => Vec::new(),
    }
}

/// Parse `tmux -V` output. Accepts both the bare `tmux 3.4` and
/// the verbose `tmux 3.4-rc1` shapes. Returns the `(major, minor)`
/// tuple on success.
pub fn parse_tmux_version(stdout: &str) -> Option<(u32, u32)> {
    let line = stdout.lines().next()?.trim();
    let rest = line.strip_prefix("tmux ")?;
    let major_minor = rest
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()?;
    let mut parts = major_minor.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

/// True when the parsed version is `>= min`. NEOTH's warm-session
/// claude-cli adapter needs tmux 3.0+ for `set -g remain-on-exit
/// failed` support — below that the operator sees claude-cli
/// crashes leave the pane empty.
pub fn version_meets_minimum(actual: (u32, u32), min: (u32, u32)) -> bool {
    (actual.0, actual.1) >= (min.0, min.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_distro_as_str_pinned() {
        assert_eq!(LinuxDistro::DebianFamily.as_str(), "debian_family");
        assert_eq!(LinuxDistro::FedoraFamily.as_str(), "fedora_family");
        assert_eq!(LinuxDistro::ArchFamily.as_str(), "arch_family");
        assert_eq!(LinuxDistro::SuseFamily.as_str(), "suse_family");
        assert_eq!(LinuxDistro::Unknown.as_str(), "unknown");
    }

    #[test]
    fn from_os_release_ubuntu() {
        assert_eq!(
            LinuxDistro::from_os_release_ids("ubuntu", "debian"),
            LinuxDistro::DebianFamily,
        );
    }

    #[test]
    fn from_os_release_pure_debian() {
        assert_eq!(
            LinuxDistro::from_os_release_ids("debian", ""),
            LinuxDistro::DebianFamily,
        );
    }

    #[test]
    fn from_os_release_pop_os() {
        assert_eq!(
            LinuxDistro::from_os_release_ids("pop", "ubuntu debian"),
            LinuxDistro::DebianFamily,
        );
    }

    #[test]
    fn from_os_release_fedora() {
        assert_eq!(
            LinuxDistro::from_os_release_ids("fedora", ""),
            LinuxDistro::FedoraFamily,
        );
    }

    #[test]
    fn from_os_release_rocky() {
        assert_eq!(
            LinuxDistro::from_os_release_ids("rocky", "rhel centos fedora"),
            LinuxDistro::FedoraFamily,
        );
    }

    #[test]
    fn from_os_release_arch() {
        assert_eq!(
            LinuxDistro::from_os_release_ids("arch", ""),
            LinuxDistro::ArchFamily,
        );
    }

    #[test]
    fn from_os_release_manjaro() {
        assert_eq!(
            LinuxDistro::from_os_release_ids("manjaro", "arch"),
            LinuxDistro::ArchFamily,
        );
    }

    #[test]
    fn from_os_release_suse() {
        assert_eq!(
            LinuxDistro::from_os_release_ids("opensuse-tumbleweed", ""),
            LinuxDistro::SuseFamily,
        );
    }

    #[test]
    fn from_os_release_unknown_returns_unknown() {
        assert_eq!(
            LinuxDistro::from_os_release_ids("nixos", ""),
            LinuxDistro::Unknown,
        );
    }

    #[test]
    fn from_os_release_case_insensitive() {
        assert_eq!(
            LinuxDistro::from_os_release_ids("FEDORA", ""),
            LinuxDistro::FedoraFamily,
        );
    }

    // ── install commands ──────────────────────────────────────────

    #[test]
    fn pick_command_debian_uses_apt() {
        let cmd = pick_linux_install_command(LinuxDistro::DebianFamily);
        assert_eq!(cmd, vec!["sudo", "apt", "install", "-y", "tmux"]);
    }

    #[test]
    fn pick_command_fedora_uses_dnf() {
        let cmd = pick_linux_install_command(LinuxDistro::FedoraFamily);
        assert_eq!(cmd, vec!["sudo", "dnf", "install", "-y", "tmux"]);
    }

    #[test]
    fn pick_command_arch_uses_pacman_noconfirm() {
        let cmd = pick_linux_install_command(LinuxDistro::ArchFamily);
        assert_eq!(cmd, vec!["sudo", "pacman", "-S", "--noconfirm", "tmux"]);
    }

    #[test]
    fn pick_command_suse_uses_zypper() {
        let cmd = pick_linux_install_command(LinuxDistro::SuseFamily);
        assert_eq!(cmd, vec!["sudo", "zypper", "install", "-y", "tmux"]);
    }

    #[test]
    fn pick_command_unknown_returns_empty() {
        assert!(pick_linux_install_command(LinuxDistro::Unknown).is_empty());
    }

    // ── version parser ────────────────────────────────────────────

    #[test]
    fn parse_tmux_version_canonical() {
        assert_eq!(parse_tmux_version("tmux 3.4\n"), Some((3, 4)));
    }

    #[test]
    fn parse_tmux_version_rc_suffix() {
        assert_eq!(parse_tmux_version("tmux 3.4-rc1\n"), Some((3, 4)));
    }

    #[test]
    fn parse_tmux_version_major_only_defaults_minor_zero() {
        assert_eq!(parse_tmux_version("tmux 4 something\n"), Some((4, 0)));
    }

    #[test]
    fn parse_tmux_version_missing_prefix_returns_none() {
        assert!(parse_tmux_version("not tmux\n").is_none());
    }

    #[test]
    fn parse_tmux_version_empty_returns_none() {
        assert!(parse_tmux_version("").is_none());
    }

    // ── minimum comparator ───────────────────────────────────────

    #[test]
    fn version_meets_minimum_equal_is_ok() {
        assert!(version_meets_minimum((3, 0), (3, 0)));
    }

    #[test]
    fn version_meets_minimum_above_is_ok() {
        assert!(version_meets_minimum((3, 4), (3, 0)));
        assert!(version_meets_minimum((4, 0), (3, 9)));
    }

    #[test]
    fn version_meets_minimum_below_fails() {
        assert!(!version_meets_minimum((2, 9), (3, 0)));
        assert!(!version_meets_minimum((3, 0), (3, 1)));
    }

    #[test]
    fn snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&LinuxDistro::DebianFamily).unwrap(),
            "\"debian_family\"",
        );
    }
}
