//! GOLD-ADOPT-15 — OpenCodeReview (`ocr`) installer + runner primitive.
//!
//! [alibaba/open-code-review](https://github.com/alibaba/open-code-review) is an
//! AI code-review CLI (npm `@alibaba-group/open-code-review`, binary `ocr`).
//! `neoth review` wraps it the same way NEOTH wraps the claude/codex/gemini CLIs:
//! detect the binary, offer the npm install when absent, then shell out with the
//! mapped flags. OCR keeps its own LLM config under `~/.opencodereview/config.json`
//! (model + auth) — NEOTH never reads or logs that token; it only invokes the CLI.

use anyhow::{Context, Result};

use super::{build_cmd, cli_version_async};

/// npm package id for `npm install -g`.
pub const OCR_NPM_PACKAGE: &str = "@alibaba-group/open-code-review";

/// PATH binary name (npm installs `ocr` / `ocr.cmd`).
pub const OCR_BIN: &str = "ocr";

/// Upstream project URL rendered in the not-installed hint.
pub const OCR_GITHUB: &str = "https://github.com/alibaba/open-code-review";

/// `ocr --version` string when installed, else `None`. Reuses the shared
/// Windows-`cmd /C`-aware prober so the `ocr.cmd` npm shim resolves.
pub async fn check_available() -> Option<String> {
    cli_version_async(OCR_BIN).await
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

    #[tokio::test]
    async fn check_available_returns_option_gracefully() {
        // Just must not panic whether or not `ocr` is on PATH.
        let _ = check_available().await;
    }
}
