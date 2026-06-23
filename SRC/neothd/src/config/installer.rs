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
}
