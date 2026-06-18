//! GOLD-ADOPT-28 — wizard environment probe: server-vs-local heuristic.
//!
//! Pure-fn over environment-variable signals + optional DMI product name.
//! No subprocesses, no async, no filesystem I/O beyond what the caller
//! has already resolved — keeps the wizard step synchronous and testable.
//!
//! ## Signals (in priority order)
//!
//! 1. `CI`/`GITHUB_ACTIONS`/`GITLAB_CI`/`CIRCLECI` env vars → `Ci`.
//! 2. `SSH_CLIENT` or `SSH_TTY` env vars present → `Server`.
//! 3. `DISPLAY` env var absent (Linux/macOS) *and* platform is not Windows
//!    → `Server`.
//! 4. DMI product name contains known cloud/hypervisor keyword → `Server`.
//! 5. Fallback → `Unknown`.
//!
//! `Desktop` is returned only when `has_display == Some(true)` AND none of
//! the Server signals fired.
//!
//! ## Usage in the wizard
//!
//! Step 1b (`step1b_detect_environment` in `cli::init`) probes the live env
//! vars + reads `/sys/class/dmi/id/product_name` (Linux only, best-effort),
//! then calls [`classify`] to get an [`EnvironmentClass`]. The class is stored
//! in [`DetectStepInputs`] / [`DetectReport`] and used by the GUI/CLI mode
//! prompt (step 1a) to auto-select `--cli` on Server/Ci environments, skipping
//! the GUI/cookie install steps that have no value on a headless server.

use serde::{Deserialize, Serialize};

/// Coarse classification of the environment NEOTH is running in.
///
/// Determines which wizard steps to surface:
/// - `Desktop` — full wizard including GUI install / browser prompts.
/// - `Server`  — skip GUI/cookie steps; surface daemon/channel/API prompts.
/// - `Ci`      — ultra-minimal; auto-accept defaults, no interactive prompts.
/// - `Unknown` — insufficient signal; show all steps + let operator choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentClass {
    Desktop,
    Server,
    Ci,
    Unknown,
}

impl EnvironmentClass {
    /// Short machine-readable tag used in the wizard summary line and
    /// the W-04 `DetectReport` field.
    pub fn as_str(self) -> &'static str {
        match self {
            EnvironmentClass::Desktop => "desktop",
            EnvironmentClass::Server => "server",
            EnvironmentClass::Ci => "ci",
            EnvironmentClass::Unknown => "unknown",
        }
    }

    /// True for `Server` and `Ci` — environments where a graphical
    /// display is absent or irrelevant. The wizard uses this to skip
    /// GUI install steps and browser-based OAuth flows.
    pub fn is_headless(self) -> bool {
        matches!(self, EnvironmentClass::Server | EnvironmentClass::Ci)
    }
}

impl std::fmt::Display for EnvironmentClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classify the current environment from pre-collected probe results.
///
/// All parameters are `Option<T>` so partial probe results (one probe
/// failed or was skipped) still produce a best-effort answer. The
/// caller is responsible for collecting the values — this function is
/// a pure mapping step with no side effects.
///
/// | Parameter | Probe source |
/// |-----------|-------------|
/// | `ssh_session` | `SSH_CLIENT` or `SSH_TTY` env var non-empty |
/// | `has_display` | `DISPLAY` env var non-empty (Linux/macOS only) |
/// | `dmi_product_name` | `/sys/class/dmi/id/product_name` (Linux only) |
/// | `ci_env` | `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, or `CIRCLECI` env var set |
pub fn classify(
    ssh_session: Option<bool>,
    has_display: Option<bool>,
    dmi_product_name: Option<&str>,
    ci_env: Option<bool>,
) -> EnvironmentClass {
    // Highest priority: explicit CI markers.
    if ci_env == Some(true) {
        return EnvironmentClass::Ci;
    }

    // SSH session → unambiguously server.
    if ssh_session == Some(true) {
        return EnvironmentClass::Server;
    }

    // DMI product name contains a known cloud / hypervisor keyword → server.
    if let Some(name) = dmi_product_name {
        if is_server_dmi(name) {
            return EnvironmentClass::Server;
        }
    }

    // No DISPLAY on a non-Windows platform → headless → server.
    if has_display == Some(false) && !cfg!(target_os = "windows") {
        return EnvironmentClass::Server;
    }

    // Display present → desktop.
    if has_display == Some(true) {
        return EnvironmentClass::Desktop;
    }

    // On Windows we can't rely on DISPLAY absence as a server signal.
    // If no other signal fired, fall through to Unknown.
    EnvironmentClass::Unknown
}

/// Probe the live process environment and return a [`EnvironmentClass`].
///
/// This is the production entry point called from the wizard step. It
/// reads the actual environment variables and (on Linux) the DMI file.
/// For tests, prefer [`classify`] directly with explicit inputs.
pub fn probe_and_classify() -> EnvironmentClass {
    let ssh_session = probe_ssh_session();
    let has_display = probe_has_display();
    let dmi = probe_dmi_product_name();
    let ci_env = probe_ci_env();
    classify(ssh_session, has_display, dmi.as_deref(), ci_env)
}

/// Probe whether the current process is running inside an SSH session.
/// Returns `Some(true)` if `SSH_CLIENT` or `SSH_TTY` is set and non-empty.
pub fn probe_ssh_session() -> Option<bool> {
    let client = std::env::var("SSH_CLIENT").unwrap_or_default();
    let tty = std::env::var("SSH_TTY").unwrap_or_default();
    if !client.trim().is_empty() || !tty.trim().is_empty() {
        Some(true)
    } else {
        Some(false)
    }
}

/// Probe whether a graphical display is available.
/// On Linux/macOS: returns `Some(true)` iff `DISPLAY` is non-empty.
/// On Windows: always returns `Some(true)` (no DISPLAY concept).
pub fn probe_has_display() -> Option<bool> {
    if cfg!(target_os = "windows") {
        return Some(true);
    }
    let display = std::env::var("DISPLAY").unwrap_or_default();
    Some(!display.trim().is_empty())
}

/// Probe whether CI environment variables are set.
/// Checks `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`.
pub fn probe_ci_env() -> Option<bool> {
    for var in &["CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI"] {
        let val = std::env::var(var).unwrap_or_default();
        if !val.trim().is_empty() && val.trim() != "false" && val.trim() != "0" {
            return Some(true);
        }
    }
    Some(false)
}

/// Read `/sys/class/dmi/id/product_name` (Linux only). Returns `None`
/// on any error (non-Linux, permission denied, file absent).
pub fn probe_dmi_product_name() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/sys/class/dmi/id/product_name")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// True when the DMI product name string signals a known cloud provider
/// or hypervisor environment. Case-insensitive.
fn is_server_dmi(name: &str) -> bool {
    let lower = name.to_lowercase();
    // Cloud provider markers.
    let cloud_keywords = [
        "amazon ec2",
        "google compute engine",
        "google",                // GCE often just says "Google"
        "microsoft corporation", // Azure VMs
        "azure",
        "vmware",
        "virtualbox",
        "kvm",
        "qemu",
        "xen",
        "hvm",
        "standard pc", // QEMU default
        "bochs",
        "digital ocean",
        "linode",
        "ovhcloud",
        "hetzner",
    ];
    cloud_keywords.iter().any(|kw| lower.contains(kw))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify() unit tests ────────────────────────────────────────────

    #[test]
    fn ci_env_classifies_as_ci() {
        let cls = classify(None, None, None, Some(true));
        assert_eq!(cls, EnvironmentClass::Ci);
        assert_eq!(cls.as_str(), "ci");
        assert!(cls.is_headless());
    }

    #[test]
    fn ci_beats_ssh_session() {
        // CI takes priority over SSH (e.g. CI runner started via SSH).
        let cls = classify(Some(true), Some(false), None, Some(true));
        assert_eq!(cls, EnvironmentClass::Ci);
    }

    #[test]
    fn ssh_client_env_classifies_as_server() {
        let cls = classify(Some(true), None, None, Some(false));
        assert_eq!(cls, EnvironmentClass::Server);
        assert_eq!(cls.as_str(), "server");
        assert!(cls.is_headless());
    }

    #[test]
    fn ssh_false_with_display_classifies_as_desktop() {
        let cls = classify(Some(false), Some(true), None, Some(false));
        assert_eq!(cls, EnvironmentClass::Desktop);
        assert!(!cls.is_headless());
    }

    #[test]
    fn no_display_on_linux_classifies_as_server() {
        // Simulate a Linux box with no DISPLAY and no SSH.
        // has_display=Some(false) + non-Windows → Server.
        // We can only run this path on non-Windows; on Windows the
        // cfg gate returns Desktop for has_display=Some(true).
        #[cfg(not(target_os = "windows"))]
        {
            let cls = classify(Some(false), Some(false), None, Some(false));
            assert_eq!(cls, EnvironmentClass::Server);
        }
        #[cfg(target_os = "windows")]
        {
            // On Windows no-display doesn't mean server — we get Unknown.
            let cls = classify(Some(false), None, None, Some(false));
            assert_eq!(cls, EnvironmentClass::Unknown);
        }
    }

    #[test]
    fn dmi_amazon_classifies_as_server() {
        let cls = classify(Some(false), Some(false), Some("Amazon EC2"), Some(false));
        assert_eq!(cls, EnvironmentClass::Server);
    }

    #[test]
    fn dmi_google_compute_engine_classifies_as_server() {
        let cls = classify(
            Some(false),
            None,
            Some("Google Compute Engine"),
            Some(false),
        );
        assert_eq!(cls, EnvironmentClass::Server);
    }

    #[test]
    fn dmi_vmware_classifies_as_server() {
        let cls = classify(
            Some(false),
            Some(true),
            Some("VMware Virtual Platform"),
            Some(false),
        );
        // VMware takes priority even if DISPLAY is set (VM on laptop is
        // still "server-class" for the wizard's purposes).
        assert_eq!(cls, EnvironmentClass::Server);
    }

    #[test]
    fn dmi_standard_pc_qemu_classifies_as_server() {
        let cls = classify(
            Some(false),
            Some(false),
            Some("Standard PC (Q35 + ICH9, 2009)"),
            Some(false),
        );
        assert_eq!(cls, EnvironmentClass::Server);
    }

    #[test]
    fn unknown_when_all_none() {
        let cls = classify(None, None, None, None);
        assert_eq!(cls, EnvironmentClass::Unknown);
    }

    #[test]
    fn unknown_when_all_false_and_windows_or_no_display_signal() {
        // ssh=false, ci=false, dmi=None, has_display=None → Unknown
        let cls = classify(Some(false), None, None, Some(false));
        assert_eq!(cls, EnvironmentClass::Unknown);
    }

    #[test]
    fn display_true_no_ssh_no_dmi_is_desktop() {
        let cls = classify(Some(false), Some(true), None, Some(false));
        assert_eq!(cls, EnvironmentClass::Desktop);
    }

    #[test]
    fn is_headless_covers_server_and_ci() {
        assert!(EnvironmentClass::Server.is_headless());
        assert!(EnvironmentClass::Ci.is_headless());
        assert!(!EnvironmentClass::Desktop.is_headless());
        assert!(!EnvironmentClass::Unknown.is_headless());
    }

    #[test]
    fn as_str_and_display_agree() {
        for cls in [
            EnvironmentClass::Desktop,
            EnvironmentClass::Server,
            EnvironmentClass::Ci,
            EnvironmentClass::Unknown,
        ] {
            assert_eq!(cls.as_str(), cls.to_string());
        }
    }

    #[test]
    fn serde_round_trips_all_variants() {
        for cls in [
            EnvironmentClass::Desktop,
            EnvironmentClass::Server,
            EnvironmentClass::Ci,
            EnvironmentClass::Unknown,
        ] {
            let json = serde_json::to_string(&cls).unwrap();
            let back: EnvironmentClass = serde_json::from_str(&json).unwrap();
            assert_eq!(cls, back, "serde round-trip failed for {cls}");
        }
    }

    // ── is_server_dmi() tests ────────────────────────────────────────────

    #[test]
    fn is_server_dmi_case_insensitive() {
        assert!(is_server_dmi("AMAZON EC2"));
        assert!(is_server_dmi("amazon ec2"));
        assert!(is_server_dmi("Amazon EC2"));
    }

    #[test]
    fn is_server_dmi_real_desktop_returns_false() {
        assert!(!is_server_dmi("System Product Name"));
        assert!(!is_server_dmi("MacBookPro18,1"));
        assert!(!is_server_dmi("ThinkPad X1 Carbon Gen 9"));
        assert!(!is_server_dmi("Dell XPS 15 9500"));
    }

    #[test]
    fn is_server_dmi_known_hypervisors() {
        for name in [
            "VMware Virtual Platform",
            "VirtualBox",
            "KVM",
            "QEMU Standard PC",
            "Xen HVM domU",
            "Bochs",
            "Standard PC (i440FX + PIIX, 1996)",
        ] {
            assert!(is_server_dmi(name), "expected server DMI for: {name}");
        }
    }
}
