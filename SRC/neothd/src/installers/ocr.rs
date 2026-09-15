//! GOLD-ADOPT-15 — OpenCodeReview (`ocr`) installer + runner primitive.
//!
//! [alibaba/open-code-review](https://github.com/alibaba/open-code-review) is an
//! AI code-review CLI (npm `@alibaba-group/open-code-review`, binary `ocr`).
//! `neoth review` wraps it the same way NEOTH wraps the claude/codex/gemini CLIs:
//! detect the binary, offer the npm install when absent, then shell out with the
//! mapped flags. OCR keeps its own LLM config under `~/.opencodereview/config.json`
//! (model + auth) — NEOTH never reads or logs that token; it only invokes the CLI.

use std::time::Duration;

use anyhow::{Context, Result};

use super::{build_cmd, cli_version_async};

/// npm package id for `npm install -g`.
pub const OCR_NPM_PACKAGE: &str = "@alibaba-group/open-code-review";

/// PATH binary name (npm installs `ocr` / `ocr.cmd`).
pub const OCR_BIN: &str = "ocr";

/// Upstream project URL rendered in the not-installed hint.
pub const OCR_GITHUB: &str = "https://github.com/alibaba/open-code-review";

const OCR_NO_UPDATE_ENV: (&str, &str) = ("OCR_NO_UPDATE", "1");

/// `ocr --version` string when installed, else `None`. Reuses the shared
/// Windows-`cmd /C`-aware prober so the `ocr.cmd` npm shim resolves.
pub async fn check_available() -> Option<String> {
    cli_version_async(OCR_BIN).await
}

/// Probe the impact-context runner without allowing the OCR launcher to
/// self-update. The flag is scoped to this one bounded child process only.
pub(crate) async fn check_available_without_update() -> Option<String> {
    crate::installers::probe::cli_version_args_with_env(
        OCR_BIN,
        &["--version"],
        Some(Duration::from_secs(5)),
        &[OCR_NO_UPDATE_ENV],
    )
    .await
}

/// The `npm install -g <pkg>` argv the not-installed hint prints.
pub fn install_command() -> Vec<String> {
    vec![
        "npm".into(),
        "install".into(),
        "-g".into(),
        OCR_NPM_PACKAGE.into(),
    ]
}

/// Run `ocr <args>` inheriting the terminal (so the operator sees the review
/// stream / progress), erroring on a non-zero exit. Windows-shim-aware via
/// [`build_cmd`].
pub async fn run(args: &[String]) -> Result<()> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut child = build_cmd(OCR_BIN, &refs)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn `ocr {}`", args.join(" ")))?;
    let status = child
        .wait()
        .await
        .with_context(|| format!("await `ocr {}`", args.join(" ")))?;
    if !status.success() {
        anyhow::bail!("`ocr {}` failed (exit {:?})", args.join(" "), status.code());
    }
    Ok(())
}

/// Run an already prepared impact-context review without allowing the OCR
/// launcher to mutate itself between the receipt and the provider action.
pub(crate) async fn run_without_update_status(
    args: Vec<String>,
) -> Result<crate::cli::review::ReviewExecution> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut command = build_cmd(OCR_BIN, &refs);
    command.env(OCR_NO_UPDATE_ENV.0, OCR_NO_UPDATE_ENV.1);
    // The review background is owned by the awaiting impact-context future.
    // Cancellation therefore kills this child before that owner can be dropped.
    command.kill_on_drop(true);
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn `ocr {}`", args.join(" ")))?;
    let status = child
        .wait()
        .await
        .with_context(|| format!("await `ocr {}`", args.join(" ")))?;
    Ok(crate::cli::review::ReviewExecution {
        exit_code: status.code(),
        succeeded: status.success(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_command_is_global_npm_for_the_alibaba_package() {
        assert_eq!(
            install_command(),
            vec!["npm", "install", "-g", "@alibaba-group/open-code-review"]
        );
    }

    #[test]
    fn constants_pinned() {
        assert_eq!(OCR_BIN, "ocr");
        assert!(OCR_GITHUB.starts_with("https://github.com/alibaba/"));
    }

    #[test]
    fn impact_version_probe_injects_no_update_into_its_child_only() {
        let command = crate::installers::probe::cli_version_command(
            OCR_BIN,
            &["--version"],
            &[OCR_NO_UPDATE_ENV],
        );
        let injected = command
            .as_std()
            .get_envs()
            .find(|(key, _)| *key == std::ffi::OsStr::new(OCR_NO_UPDATE_ENV.0))
            .and_then(|(_, value)| value);
        assert_eq!(injected, Some(std::ffi::OsStr::new(OCR_NO_UPDATE_ENV.1)));
    }
}
