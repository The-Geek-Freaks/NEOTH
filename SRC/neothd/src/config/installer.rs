//! Python pip-gate helpers for Python-backed optional NEOTH skills.
//!
//! Probes whether a Python package is importable on the operator's host.
//! Used by `neoth doctor` to surface install hints for skills that delegate
//! work to Python libraries (ppt_master → python-pptx).
//!
//! The skills ALWAYS route and load; this gate is ADVISORY only. When the
//! gate check fails (python-pptx absent), the skill's `system_prompt` itself
//! instructs the LLM to ask the operator to install it before generating code.
//!
//! ## Pattern
//!
//! Identical shape to `crate::self_improve::is_installed()` / `python_bin()` —
//! a self-contained probe module that checks importability via a subprocess.
//! The probe runs the operator's Python binary with `-c "import <pkg>"` and
//! treats exit-0 as "installed". No persistent state, no side effects.
//!
//! ## GOLD-ADAPT-DOC-01 (2026-06-23)
//!
//! Added for the `ppt_master` bundled skill (python-pptx gate). Future
//! Python-backed skills (e.g. GOLD-ADAPT-GRAPH-04 graphify) add their own
//! constant + probe function here in the same shape.

/// `pip install python-pptx` install hint surfaced by `neoth doctor` for the
/// `ppt_master` skill when python-pptx is not importable.
pub const PPTMASTER_INSTALL_CMD: &str = "pip install python-pptx";

/// Python binary name: `python` on Windows, `python3` on Unix/macOS.
///
/// Mirrors `crate::self_improve::python_bin()` — kept local so this module
/// has no cross-module dependency on `self_improve`.
fn python_bin() -> &'static str {
    if cfg!(target_os = "windows") {
        "python"
    } else {
        "python3"
    }
}

/// Returns `true` iff `python -c "import pptx"` exits 0 — meaning
/// python-pptx is importable in the operator's Python environment.
///
/// Returns `false` on any error (Python not on PATH, python-pptx not
/// installed, subprocess spawn failure). Never panics.
pub fn is_pptmaster_installed() -> bool {
    std::process::Command::new(python_bin())
        .args(["-c", "import pptx"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// `pip install graphifyy` install hint surfaced by `neoth doctor` for the
/// `graphify` skill when graphifyy is not importable.
///
/// ## GOLD-ADAPT-GRAPH-04 (2026-06-27)
///
/// Added for the `graphify` bundled skill (graphifyy pip gate). Ships enabled;
/// gate is advisory — the skill routes even when graphifyy is absent and the
/// system_prompt instructs the LLM to surface the install hint.
pub const GRAPHIFY_INSTALL_CMD: &str = "pip install graphifyy";

/// Returns `true` iff `python -m graphifyy --version` exits 0 — meaning
/// graphifyy is importable in the operator's Python environment.
///
/// Returns `false` on any error (Python not on PATH, graphifyy not installed,
/// subprocess spawn failure). Never panics.
///
/// ## Sync vs async
///
/// `daemon/self_map_task::check_graphify_available` is the async equivalent
/// used in the daemon cron path. This sync version mirrors the same argv but
/// uses `std::process::Command` for the doctor's synchronous check surface.
pub fn is_graphify_installed() -> bool {
    std::process::Command::new(python_bin())
        .args(["-m", "graphifyy", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Install URL for the officecli binary, surfaced by `neoth doctor` when the
/// binary is absent. Operators download officecli from this URL and place it
/// on their PATH before enabling the `officecli_*` skill family.
///
/// ## GOLD-ADAPT-DOC-04 (2026-06-23)
///
/// Added for the 11 `officecli_*` bundled skills (binary-gated, Apache-2.0).
/// Identical advisory pattern to PPTMASTER_INSTALL_CMD (DOC-01).
pub const OFFICECLI_INSTALL_URL: &str = "https://d.officecli.ai";

/// Returns `true` iff `officecli --version` exits 0 — meaning the officecli
/// binary is present on the operator's PATH.
///
/// Returns `false` on any error (binary not on PATH, non-zero exit, spawn
/// failure). Never panics.
///
/// ## Advisory gate
///
/// This probe is used by `neoth doctor` (advisory only). The `officecli_*`
/// skills ship `enabled: false` and are never activated by the router until
/// the operator explicitly enables them via `freedom.yaml::skills.enabled`.
/// The probe does NOT suppress routing — it only surfaces the install hint.
pub fn is_officecli_installed() -> bool {
    std::process::Command::new("officecli")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke: the probe either returns true (python-pptx present) or false
    /// (absent / python missing). Neither outcome should panic. We do not
    /// assert the value because CI runners may or may not have python-pptx.
    #[test]
    fn pptmaster_probe_does_not_panic() {
        let _ = is_pptmaster_installed();
    }

    #[test]
    fn pptmaster_install_cmd_is_pip() {
        assert!(
            PPTMASTER_INSTALL_CMD.starts_with("pip install"),
            "PPTMASTER_INSTALL_CMD must be a pip install command, got: {PPTMASTER_INSTALL_CMD}"
        );
    }

    #[test]
    fn python_bin_is_platform_appropriate() {
        let bin = python_bin();
        assert!(
            bin == "python" || bin == "python3",
            "python_bin() must return 'python' or 'python3', got: {bin}"
        );
        // On Windows specifically: must be "python" (not python3 — missing on stock Win)
        #[cfg(target_os = "windows")]
        assert_eq!(bin, "python");
        // On non-Windows: must be "python3"
        #[cfg(not(target_os = "windows"))]
        assert_eq!(bin, "python3");
    }

    /// GOLD-ADAPT-GRAPH-04: graphifyy probe must not panic regardless of
    /// whether graphifyy is on PATH. CI runners may not have it.
    #[test]
    fn graphify_probe_does_not_panic() {
        let _ = is_graphify_installed();
    }

    /// GOLD-ADAPT-GRAPH-04: the install command must be a pip install command.
    #[test]
    fn graphify_install_cmd_is_pip() {
        assert!(
            GRAPHIFY_INSTALL_CMD.starts_with("pip install"),
            "GRAPHIFY_INSTALL_CMD must be a pip install command, got: {GRAPHIFY_INSTALL_CMD}"
        );
    }

    /// GOLD-ADAPT-DOC-04: officecli probe must not panic regardless of
    /// whether the binary is on PATH. CI runners won't have officecli.
    #[test]
    fn officecli_probe_does_not_panic() {
        let _ = is_officecli_installed();
    }

    /// GOLD-ADAPT-DOC-04: the install URL must point to the documented
    /// officecli distribution site.
    #[test]
    fn officecli_install_url_points_to_d_officecli_ai() {
        assert!(
            OFFICECLI_INSTALL_URL.contains("d.officecli.ai"),
            "OFFICECLI_INSTALL_URL must reference d.officecli.ai, got: {OFFICECLI_INSTALL_URL}"
        );
    }
}
