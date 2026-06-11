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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPath {
    /// `curl -fsSL https://ollama.com/install.sh | sh` — official
    /// Linux/macOS installer.
    UpstreamScript,
    /// `winget install Ollama.Ollama` — Microsoft-managed pkg mgr.
    Winget,
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
            Self::Brew => "brew install ollama".to_string(),
            Self::Manual => format!("manual download from {OLLAMA_DOWNLOAD_URL}"),
        }
    }

    pub const fn for_host() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Winget
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

pub async fn check_ollama_available() -> Option<String> {
    let mut cmd = if cfg!(windows) {
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

/// Install Ollama for this host via the platform's [`InstallPath`]. The `Manual`
/// platform has no automatic command → returns an error pointing at the download
/// page. GOLD-ADOPT-13 (wizard-installed runtime).
pub async fn install_for_host() -> anyhow::Result<()> {
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
        assert_eq!(openai_compat_endpoint(DEFAULT_OLLAMA_PORT), "http://127.0.0.1:11434/v1");
    }

    #[test]
    fn hf_gguf_ref_builds_ollama_direct_hf_pull() {
        assert_eq!(
            hf_gguf_ref("huihui-ai/Qwen2.5-7B-Instruct-abliterated-GGUF", "Q4_K_M"),
            "hf.co/huihui-ai/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M"
        );
        // A leading slash is tolerated.
        assert_eq!(hf_gguf_ref("/unsloth/X-GGUF", "Q8_0"), "hf.co/unsloth/X-GGUF:Q8_0");
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
            vec!["ollama", "pull", "hf.co/unsloth/Qwen2.5-14B-Instruct-GGUF:Q8_0"]
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
        assert_ne!(up, InstallPath::UpstreamScript.as_str(), "must not be the bare tag");
        assert_eq!(InstallPath::Winget.display_command(), "winget install Ollama.Ollama");
        assert_eq!(InstallPath::Brew.display_command(), "brew install ollama");
        assert!(InstallPath::Manual.display_command().contains(OLLAMA_DOWNLOAD_URL));
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
}
