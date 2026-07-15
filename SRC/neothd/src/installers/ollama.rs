//! W-02 — ollama installer primitive.
//!
//! Ollama is the optional local-model runtime NEOTH wizard offers
//! when the operator's GPU/RAM can host one. Same pattern as
//! [`super::n8n`] + [`super::paperless`]: probe binary + endpoint,
//! recommend install path, render commands for operator GO/STOP.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::Command;

/// Default Ollama HTTP port. Pinned — operators copy/pasting from
/// upstream docs hit the canonical value.
pub const DEFAULT_OLLAMA_PORT: u16 = 11_434;

/// Upstream install docs URL the wizard renders for unsupported
/// platforms / manual installs.
pub const OLLAMA_DOWNLOAD_URL: &str = "https://ollama.com/download";

/// One-line install script Ollama publishes for Linux/macOS.
pub const OLLAMA_INSTALL_SCRIPT_URL: &str = "https://ollama.com/install.sh";

/// OH-05 — direct Windows installer URL (VERYSILENT / CURRENTUSER).
pub const OLLAMA_SETUP_EXE_URL: &str = "https://ollama.com/download/OllamaSetup.exe";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPath {
    /// `curl -fsSL https://ollama.com/install.sh | sh` — official
    /// Linux/macOS installer.
    UpstreamScript,
    /// `winget install Ollama.Ollama` — Microsoft-managed pkg mgr.
    Winget,
    /// OH-05 — PowerShell silent install: Invoke-WebRequest OllamaSetup.exe +
    /// `/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /CURRENTUSER`.
    /// Installs to `%LOCALAPPDATA%\Programs\Ollama\` (no admin required).
    /// Sentinel: `install_command()` returns `[]`; `install_for_host()` routes
    /// to [`silent_install_windows`] instead of `run_command`.
    #[serde(rename = "windows_silent")]
    WindowsSilent,
    /// `brew install ollama` — macOS Homebrew alternative.
    Brew,
    /// Manual download from [`OLLAMA_DOWNLOAD_URL`].
    Manual,
}

impl InstallPath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamScript => "upstream_script",
            Self::Winget => "winget",
            Self::WindowsSilent => "windows_silent",
            Self::Brew => "brew",
            Self::Manual => "manual",
        }
    }

    pub fn install_command(self) -> Vec<String> {
        match self {
            Self::UpstreamScript => vec![
                "sh".into(),
                "-c".into(),
                format!("curl -fsSL {OLLAMA_INSTALL_SCRIPT_URL} | sh"),
            ],
            Self::Winget => vec!["winget".into(), "install".into(), "Ollama.Ollama".into()],
            // OH-05 sentinel — `install_for_host` routes to `silent_install_windows()`
            // instead of `run_command`; this must stay empty so the sentinel check holds.
            Self::WindowsSilent => Vec::new(),
            Self::Brew => vec!["brew".into(), "install".into(), "ollama".into()],
            Self::Manual => Vec::new(),
        }
    }

    /// GR-086 — the exact shell command the operator is about to run, for the
    /// install-confirm prompt. `as_str()` returns a terse tag (`upstream_script`)
    /// that HIDES the fact that the operator is consenting to a `curl … | sh`
    /// pipe-to-shell; this spells it out so consent is informed.
    pub fn display_command(self) -> String {
        match self {
            Self::UpstreamScript => format!("curl -fsSL {OLLAMA_INSTALL_SCRIPT_URL} | sh"),
            Self::Winget => "winget install Ollama.Ollama".to_string(),
            Self::WindowsSilent => format!(
                "PowerShell: Invoke-WebRequest {OLLAMA_SETUP_EXE_URL} + /VERYSILENT /CURRENTUSER (no admin required)"
            ),
            Self::Brew => "brew install ollama".to_string(),
            Self::Manual => format!("manual download from {OLLAMA_DOWNLOAD_URL}"),
        }
    }

    pub const fn for_host() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::WindowsSilent
        }
        #[cfg(target_os = "macos")]
        {
            Self::Brew
        }
        #[cfg(target_os = "linux")]
        {
            Self::UpstreamScript
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            Self::Manual
        }
    }
}

/// OH-05 — multi-path Ollama binary probe.
///
/// Search order (porting OH `find_system_ollama_binary`):
/// 1. `OLLAMA_BIN` env override (path must resolve to an existing file).
/// 2. `ollama` / `ollama.exe` on `PATH` via `which`-style scan.
/// 3. Platform-specific known install locations:
///    - Windows: `%LOCALAPPDATA%\Programs\Ollama\ollama.exe`,
///      `%LOCALAPPDATA%\Ollama\ollama.exe`, `%ProgramFiles%\Ollama\ollama.exe`.
///    - macOS: `/usr/local/bin/ollama`, `/opt/homebrew/bin/ollama`,
///      `~/Applications/Ollama.app/Contents/MacOS/ollama`,
///      `/Applications/Ollama.app/Contents/MacOS/ollama`.
///    - Linux: `/usr/local/bin/ollama`, `/usr/bin/ollama`.
///
/// This is the CRITICAL fix for `/CURRENTUSER` silent installs: the binary
/// lands in `%LOCALAPPDATA%\Programs\Ollama\` which is NOT on PATH until the
/// next shell restart, so a bare `ollama --version` call fails immediately
/// after the installer exits. Calling this function instead of bare PATH lookup
/// finds the binary in the known post-install location.
pub fn find_ollama_binary() -> Option<std::path::PathBuf> {
    // 1. Explicit env override — caller MUST point at a real file.
    if let Ok(val) = std::env::var("OLLAMA_BIN") {
        let p = std::path::PathBuf::from(&val);
        if p.is_file() {
            return Some(p);
        }
        // env set but path doesn't exist → fall through (don't return None here
        // so the other probes still have a chance).
    }

    // 2. PATH scan — works if the shell already has the binary on PATH.
    let bin_name = if cfg!(windows) {
        "ollama.exe"
    } else {
        "ollama"
    };
    if let Ok(path_var) = std::env::var("PATH") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for dir in path_var.split(sep) {
            let candidate = std::path::Path::new(dir).join(bin_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    // 3. Platform-specific known locations.
    #[cfg(target_os = "windows")]
    {
        let known: &[&str] = &[r"Programs\Ollama\ollama.exe", r"Ollama\ollama.exe"];
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            for rel in known {
                let p = std::path::Path::new(&local).join(rel);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        if let Ok(pf) = std::env::var("PROGRAMFILES") {
            let p = std::path::Path::new(&pf).join("Ollama").join("ollama.exe");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let fixed: &[&str] = &["/usr/local/bin/ollama", "/opt/homebrew/bin/ollama"];
        for path in fixed {
            let p = std::path::Path::new(path);
            if p.is_file() {
                return Some(p.to_path_buf());
            }
        }
        // App bundle paths — user ~/Applications first, then system.
        let bundle_rel = "Ollama.app/Contents/MacOS/ollama";
        if let Ok(home) = std::env::var("HOME") {
            let p = std::path::Path::new(&home)
                .join("Applications")
                .join(bundle_rel);
            if p.is_file() {
                return Some(p);
            }
        }
        let sys_p = std::path::Path::new("/Applications").join(bundle_rel);
        if sys_p.is_file() {
            return Some(sys_p);
        }
    }
    #[cfg(target_os = "linux")]
    {
        for path in &["/usr/local/bin/ollama", "/usr/bin/ollama"] {
            let p = std::path::Path::new(path);
            if p.is_file() {
                return Some(p.to_path_buf());
            }
        }
    }

    None
}

/// OH-05 — Windows PowerShell silent install.
///
/// Downloads `OllamaSetup.exe` from `OLLAMA_SETUP_EXE_URL` via
/// `Invoke-WebRequest` and runs it with `/VERYSILENT /NORESTART
/// /SUPPRESSMSGBOXES /CURRENTUSER`. No admin rights required.
/// Installs to `%LOCALAPPDATA%\Programs\Ollama\`.
///
/// `$ProgressPreference = 'SilentlyContinue'` is mandatory — without it
/// `Invoke-WebRequest` fills the operator's terminal with a progress bar
/// that breaks any structured output above/below.
///
/// Returns `Err` on non-Windows platforms immediately.
pub async fn silent_install_windows() -> anyhow::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        anyhow::bail!("silent_install_windows is only supported on Windows");
    }
    #[cfg(target_os = "windows")]
    {
        use anyhow::Context;
        let ps_block = format!(
            r#"$ProgressPreference = 'SilentlyContinue'; \
$dest = "$env:TEMP\OllamaSetup.exe"; \
Invoke-WebRequest -Uri '{url}' -OutFile $dest; \
$proc = Start-Process -FilePath $dest -ArgumentList '/VERYSILENT', '/NORESTART', '/SUPPRESSMSGBOXES', '/CURRENTUSER' -PassThru -Wait; \
Remove-Item -Force $dest -ErrorAction SilentlyContinue; \
exit $proc.ExitCode"#,
            url = OLLAMA_SETUP_EXE_URL,
        );
        let status = Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &ps_block,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .await
            .context("spawn powershell for Ollama silent install")?;
        if !status.success() {
            anyhow::bail!(
                "Ollama silent install failed (PowerShell exit {:?}). \
                 Try installing manually from {OLLAMA_DOWNLOAD_URL}",
                status.code()
            );
        }
        Ok(())
    }
}

pub async fn check_ollama_available() -> Option<String> {
    // OH-05 — try the multi-path probe FIRST so a /CURRENTUSER install that
    // landed in %LOCALAPPDATA% (not yet on PATH) is detected correctly.
    let binary = find_ollama_binary();
    let mut cmd = if let Some(ref bin) = binary {
        let mut c = Command::new(bin);
        c.arg("--version");
        c
    } else if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg("ollama").arg("--version");
        c
    } else {
        let mut c = Command::new("ollama");
        c.arg("--version");
        c
    };
    let output = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    Reachable,
    PortClosed,
    Timeout,
}

impl ProbeOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::PortClosed => "port_closed",
            Self::Timeout => "timeout",
        }
    }
}

pub async fn probe_endpoint(port: u16) -> ProbeOutcome {
    use tokio::net::TcpStream;
    let addr = format!("127.0.0.1:{port}");
    match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => ProbeOutcome::Reachable,
        Ok(Err(_)) => ProbeOutcome::PortClosed,
        Err(_) => ProbeOutcome::Timeout,
    }
}

/// The OpenAI-compatible base URL Ollama serves. Wire this into
/// `freedom.yaml::provider_model` + the `OpenAiCompat` adapter (no new
/// provider type needed) to run a pulled GGUF as a NEOTH hemisphere. Ollama
/// exposes `/v1` for OpenAI compat. GOLD-ADOPT-13.
pub fn openai_compat_endpoint(port: u16) -> String {
    format!("http://127.0.0.1:{port}/v1")
}

/// Ollama can pull a quantized GGUF DIRECTLY from a HuggingFace repo:
/// `ollama pull hf.co/<owner>/<repo>:<QUANT>` (e.g. `Q4_K_M`, `Q8_0`). This is
/// the bridge from a GOLD-ADOPT-11 abliterated/unsloth GGUF pick to a runnable
/// local model — Ollama handles the GGUF + quant + VRAM offload; no manual
/// safetensors download, no candle GGUF loader. GOLD-ADOPT-13.
pub fn hf_gguf_ref(hf_repo: &str, quant_tag: &str) -> String {
    format!("hf.co/{}:{quant_tag}", hf_repo.trim_start_matches('/'))
}

/// `ollama pull <model_ref>` — `model_ref` is either a library tag
/// (`qwen2.5:7b-instruct-q4_K_M`) or an `hf.co/...` ref from [`hf_gguf_ref`].
pub fn pull_command(model_ref: &str) -> Vec<String> {
    vec!["ollama".into(), "pull".into(), model_ref.into()]
}

/// Run an argv (install or pull), streaming the child's stdout/stderr to the
/// operator's terminal. Errors on an empty argv or a non-zero exit. GOLD-ADOPT-13.
pub async fn run_command(argv: &[String]) -> anyhow::Result<()> {
    use anyhow::Context;
    let (prog, rest) = argv.split_first().context("empty command")?;
    let status = Command::new(prog)
        .args(rest)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .with_context(|| format!("spawn `{}`", argv.join(" ")))?;
    if !status.success() {
        anyhow::bail!("`{}` failed (exit {:?})", argv.join(" "), status.code());
    }
    Ok(())
}

/// OH-05 — like `run_command` but uses an explicit binary path as argv[0].
///
/// Required for `ollama pull` calls AFTER a `/CURRENTUSER` silent install:
/// the binary is in `%LOCALAPPDATA%\Programs\Ollama\` which is NOT on PATH
/// until the shell restarts. `find_ollama_binary()` returns the absolute path;
/// this function drives it directly so pulls work in the same wizard session
/// without asking the operator to restart their shell.
pub async fn run_command_at(binary: &std::path::Path, rest: &[String]) -> anyhow::Result<()> {
    use anyhow::Context;
    let status = Command::new(binary)
        .args(rest)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .with_context(|| format!("spawn `{} {}`", binary.display(), rest.join(" ")))?;
    if !status.success() {
        anyhow::bail!(
            "`{} {}` failed (exit {:?})",
            binary.display(),
            rest.join(" "),
            status.code()
        );
    }
    Ok(())
}

/// Install Ollama for this host via the platform's [`InstallPath`].
///
/// On Windows, routes to [`silent_install_windows`] (OH-05: PowerShell
/// `/VERYSILENT /CURRENTUSER`) instead of `run_command`. The `Manual` platform
/// has no automatic command → returns an error pointing at the download page.
/// GOLD-ADOPT-13 (wizard-installed runtime).
pub async fn install_for_host() -> anyhow::Result<()> {
    // OH-05: WindowsSilent is the sentinel path — install_command() returns []
    // so the standard run_command path would bail "no automatic installer".
    // Route to the dedicated PowerShell installer instead.
    if matches!(InstallPath::for_host(), InstallPath::WindowsSilent) {
        return silent_install_windows().await;
    }
    let cmd = InstallPath::for_host().install_command();
    if cmd.is_empty() {
        anyhow::bail!(
            "no automatic Ollama installer for this platform — download from {OLLAMA_DOWNLOAD_URL}"
        );
    }
    run_command(&cmd).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_pinned() {
        assert_eq!(DEFAULT_OLLAMA_PORT, 11_434);
    }

    #[test]
    fn openai_compat_endpoint_is_v1() {
        assert_eq!(openai_compat_endpoint(11434), "http://127.0.0.1:11434/v1");
        assert_eq!(
            openai_compat_endpoint(DEFAULT_OLLAMA_PORT),
            "http://127.0.0.1:11434/v1"
        );
    }

    #[test]
    fn hf_gguf_ref_builds_ollama_direct_hf_pull() {
        assert_eq!(
            hf_gguf_ref("huihui-ai/Qwen2.5-7B-Instruct-abliterated-GGUF", "Q4_K_M"),
            "hf.co/huihui-ai/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M"
        );
        // A leading slash is tolerated.
        assert_eq!(
            hf_gguf_ref("/unsloth/X-GGUF", "Q8_0"),
            "hf.co/unsloth/X-GGUF:Q8_0"
        );
    }

    #[tokio::test]
    async fn run_command_rejects_empty_argv() {
        let err = run_command(&[]).await.unwrap_err();
        assert!(err.to_string().contains("empty command"));
    }

    #[test]
    fn pull_command_wraps_ollama_pull() {
        let cmd = pull_command(&hf_gguf_ref("unsloth/Qwen2.5-14B-Instruct-GGUF", "Q8_0"));
        assert_eq!(
            cmd,
            vec![
                "ollama",
                "pull",
                "hf.co/unsloth/Qwen2.5-14B-Instruct-GGUF:Q8_0"
            ]
        );
    }

    #[test]
    fn urls_are_official_https() {
        assert!(OLLAMA_DOWNLOAD_URL.starts_with("https://ollama.com/"));
        assert!(OLLAMA_INSTALL_SCRIPT_URL.starts_with("https://ollama.com/"));
        assert!(OLLAMA_INSTALL_SCRIPT_URL.ends_with(".sh"));
    }

    #[test]
    fn install_path_as_str_pinned() {
        assert_eq!(InstallPath::UpstreamScript.as_str(), "upstream_script");
        assert_eq!(InstallPath::Winget.as_str(), "winget");
        assert_eq!(InstallPath::Brew.as_str(), "brew");
        assert_eq!(InstallPath::Manual.as_str(), "manual");
    }

    #[test]
    fn upstream_script_command_pipes_curl_to_sh() {
        let cmd = InstallPath::UpstreamScript.install_command();
        assert_eq!(cmd[0], "sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("curl"));
        assert!(cmd[2].contains(OLLAMA_INSTALL_SCRIPT_URL));
        assert!(cmd[2].contains("| sh"));
    }

    #[test]
    fn display_command_spells_out_the_real_command_gr086() {
        // GR-086 — the confirm prompt shows the ACTUAL command, not the terse tag.
        let up = InstallPath::UpstreamScript.display_command();
        assert!(up.contains("curl"), "{up}");
        assert!(up.contains(OLLAMA_INSTALL_SCRIPT_URL), "{up}");
        assert!(up.contains("| sh"), "{up}");
        assert_ne!(
            up,
            InstallPath::UpstreamScript.as_str(),
            "must not be the bare tag"
        );
        assert_eq!(
            InstallPath::Winget.display_command(),
            "winget install Ollama.Ollama"
        );
        assert_eq!(InstallPath::Brew.display_command(), "brew install ollama");
        assert!(
            InstallPath::Manual
                .display_command()
                .contains(OLLAMA_DOWNLOAD_URL)
        );
    }

    #[test]
    fn winget_command_uses_canonical_package_id() {
        let cmd = InstallPath::Winget.install_command();
        assert_eq!(cmd, vec!["winget", "install", "Ollama.Ollama"]);
    }

    #[test]
    fn brew_command_shape() {
        assert_eq!(
            InstallPath::Brew.install_command(),
            vec!["brew", "install", "ollama"],
        );
    }

    #[test]
    fn manual_install_command_is_empty() {
        assert!(InstallPath::Manual.install_command().is_empty());
    }

    #[test]
    fn probe_outcome_as_str_pinned() {
        assert_eq!(ProbeOutcome::Reachable.as_str(), "reachable");
        assert_eq!(ProbeOutcome::PortClosed.as_str(), "port_closed");
        assert_eq!(ProbeOutcome::Timeout.as_str(), "timeout");
    }

    #[tokio::test]
    async fn probe_unbound_port_returns_closed_or_timeout() {
        // High random port unlikely to be bound.
        let outcome = probe_endpoint(58_421).await;
        assert!(matches!(
            outcome,
            ProbeOutcome::PortClosed | ProbeOutcome::Timeout
        ));
    }

    #[tokio::test]
    async fn check_ollama_available_returns_option_gracefully() {
        let _ = check_ollama_available().await;
    }

    #[test]
    fn snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&InstallPath::UpstreamScript).unwrap(),
            "\"upstream_script\"",
        );
    }

    // OH-05 tests -----------------------------------------------------------

    #[test]
    fn snake_case_serde_covers_windows_silent() {
        assert_eq!(
            serde_json::to_string(&InstallPath::WindowsSilent).unwrap(),
            "\"windows_silent\"",
        );
    }

    #[test]
    fn windows_silent_install_path_install_command_is_empty_sentinel() {
        assert!(InstallPath::WindowsSilent.install_command().is_empty());
    }

    #[test]
    fn windows_silent_install_path_display_command_names_powershell() {
        let dc = InstallPath::WindowsSilent.display_command();
        assert!(
            dc.contains("OllamaSetup.exe"),
            "display_command must name the EXE: {dc}"
        );
        assert!(
            dc.contains("/VERYSILENT"),
            "display_command must show /VERYSILENT flag: {dc}"
        );
    }

    #[test]
    fn windows_silent_as_str_pinned() {
        assert_eq!(InstallPath::WindowsSilent.as_str(), "windows_silent");
    }

    #[test]
    fn setup_exe_url_is_official_https() {
        assert!(
            OLLAMA_SETUP_EXE_URL.starts_with("https://ollama.com/"),
            "URL must be https://ollama.com/: {OLLAMA_SETUP_EXE_URL}"
        );
        assert!(
            OLLAMA_SETUP_EXE_URL.ends_with(".exe"),
            "URL must end with .exe: {OLLAMA_SETUP_EXE_URL}"
        );
    }

    #[test]
    fn find_ollama_binary_respects_ollama_bin_env_override_when_file_exists() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let stub = dir.join("ollama_stub_oh05_test.exe");
        // Create a real (empty) file so is_file() returns true.
        std::fs::File::create(&stub)
            .unwrap()
            .write_all(b"")
            .unwrap();
        // SAFETY: test-only env mutation — unique env key (OLLAMA_BIN with
        // distinctive stub name) minimises cross-test races in the test harness.
        unsafe {
            std::env::set_var("OLLAMA_BIN", stub.to_str().unwrap());
        }
        let result = find_ollama_binary();
        unsafe {
            std::env::remove_var("OLLAMA_BIN");
        }
        std::fs::remove_file(&stub).ok();
        assert_eq!(
            result.as_deref(),
            Some(stub.as_path()),
            "OLLAMA_BIN pointing at a real file must be returned"
        );
    }

    #[test]
    fn find_ollama_binary_ignores_env_override_when_file_missing() {
        // Point OLLAMA_BIN at a path that definitely doesn't exist.
        // SAFETY: test-only env mutation.
        unsafe {
            std::env::set_var("OLLAMA_BIN", "/nonexistent/ollama_oh05_missing");
        }
        let result = find_ollama_binary();
        unsafe {
            std::env::remove_var("OLLAMA_BIN");
        }
        // The stub name must NOT appear in whatever was returned (if anything).
        if let Some(ref p) = result {
            assert!(
                !p.to_string_lossy().contains("ollama_oh05_missing"),
                "must not return the missing OLLAMA_BIN stub path: {p:?}"
            );
        }
        // Not asserting Some/None — on a machine that has Ollama installed via
        // PATH or known location it may return Some with the real binary, which
        // is correct behaviour.
    }

    #[test]
    fn find_ollama_binary_finds_binary_via_path() {
        use std::io::Write;
        // Write a stub binary to a temp dir, prepend to PATH, assert probe finds it.
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_name = if cfg!(windows) {
            "ollama.exe"
        } else {
            "ollama"
        };
        let stub = dir.path().join(bin_name);
        std::fs::File::create(&stub)
            .unwrap()
            .write_all(b"#!/bin/sh\n")
            .unwrap();
        // is_file() only checks existence, not executable bit — fine for our probe.

        let orig_path = std::env::var("PATH").unwrap_or_default();
        let sep = if cfg!(windows) { ";" } else { ":" };
        let new_path = format!("{}{sep}{orig_path}", dir.path().display());
        // SAFETY: test-only env mutation.
        unsafe {
            // Clear OLLAMA_BIN so the env-override step doesn't short-circuit.
            std::env::remove_var("OLLAMA_BIN");
            std::env::set_var("PATH", &new_path);
        }
        let result = find_ollama_binary();
        unsafe {
            std::env::set_var("PATH", orig_path);
        }

        assert!(
            result.is_some(),
            "find_ollama_binary must find stub on PATH"
        );
        let found = result.unwrap();
        assert_eq!(
            found.file_name().and_then(|n| n.to_str()),
            Some(bin_name),
            "found binary name mismatch: {found:?}"
        );
    }
}
