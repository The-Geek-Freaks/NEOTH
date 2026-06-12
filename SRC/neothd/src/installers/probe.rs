//! Shared CLI version-probe helper (GOLD-ARCH-14, origin D-35).
//!
//! Six installer modules (`node`/`obsidian`/`obs`/`pears`/`n8n`/`paperless`)
//! each carried a byte-near-identical `cli_version` that wrapped a binary
//! through `cmd /C` on Windows (so npm/docker shell-script shims like
//! `claude.cmd`/`docker.cmd` resolve the same way as a real `.exe`) and parsed
//! the trimmed stdout. This is the single shared implementation; a 5s wall-clock
//! cap is now applied uniformly (the `n8n`/`paperless` variants previously had
//! none — an unbounded `--version` could hang the wizard; the cap is a safe
//! hardening, not a behaviour change for the success path).

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

/// Probe `<binary> <args...>` and return the trimmed stdout on success.
///
/// On Windows the call is wrapped through `cmd /C` so shell-script shims
/// resolve like a real `.exe`. `timeout` caps the wall-clock; `None` waits
/// indefinitely. Returns `None` on spawn failure, a non-zero exit, a timeout,
/// or empty output (an empty version string is treated as "not found").
pub async fn cli_version_args(
    binary: &str,
    args: &[&str],
    timeout: Option<Duration>,
) -> Option<String> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(binary).args(args);
        c
    } else {
        let mut c = Command::new(binary);
        c.args(args);
        c
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = match timeout {
        Some(d) => tokio::time::timeout(d, cmd.output()).await.ok()?.ok()?,
        None => cmd.output().await.ok()?,
    };
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Convenience: `<binary> --version`, 5s cap. The common case for the six
/// installer probes.
pub async fn cli_version(binary: &str) -> Option<String> {
    cli_version_args(binary, &["--version"], Some(Duration::from_secs(5))).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_binary_yields_none() {
        // A binary that cannot possibly exist must probe to None, not panic.
        assert!(cli_version("neoth-definitely-not-a-real-binary-xyz").await.is_none());
        assert!(
            cli_version_args("neoth-definitely-not-a-real-binary-xyz", &["--version"], None)
                .await
                .is_none()
        );
    }
}
