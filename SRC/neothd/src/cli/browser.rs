//! `neoth browser` — narrow operator surface for the reviewed managed-browser
//! artifact. This module never launches a browser, opens CDP, navigates a URL,
//! updates an installed generation, or falls back to an ambient browser.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context as _, Result, ensure};
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::tools::external_http::ExternalHttpAuthorizer;
use crate::tools::managed_browser::{
    ManagedBrowserConfig, ManagedBrowserPlatform, ManagedBrowserRuntimeResolver,
    install_reviewed_managed_browser,
};

#[derive(Args, Debug, Clone)]
pub struct BrowserArgs {
    #[command(subcommand)]
    pub action: BrowserAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BrowserAction {
    /// Verify the local reviewed artifact. This reports artifact integrity only;
    /// it does not report browser process or CDP runtime readiness.
    Status,
    /// Install the compiled-in reviewed artifact for this platform. Requires
    /// `managed_browser.enabled: true`; never launches the installed browser.
    Install,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct BrowserArtifactView {
    platform: &'static str,
    enabled: bool,
    artifact_status: &'static str,
    executable: Option<String>,
    version: Option<String>,
    revision: Option<String>,
    archive_sha256: Option<String>,
    detail: Option<String>,
}

pub async fn run_browser(args: BrowserArgs, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let config_path = FreedomConfig::default_path();
    let public_config = load_browser_config_read_only_at(&config_path)?;
    match args.action {
        BrowserAction::Status => {
            let platform = current_platform()?;
            render_status(&home, platform, &public_config, output)
        }
        BrowserAction::Install if !public_config.enabled => {
            anyhow::bail!(
                "managed browser install is disabled by freedom.yaml::managed_browser.enabled"
            )
        }
        BrowserAction::Install => {
            // Active installation is the only browser path allowed to enter
            // the full runtime config/credential transaction. The second gate
            // below protects a concurrent policy change back to default-off.
            let runtime_config = FreedomConfig::load_from_default_path_or_default()?;
            run_install(&home, current_platform()?, &runtime_config, output).await
        }
    }
}

/// Parse only the public `freedom.yaml` bytes without taking the credential
/// transaction lock or running legacy credential migration. Browser status and
/// a default-off install must be observational reads of operator state.
fn load_browser_config_read_only_at(path: &std::path::Path) -> Result<ManagedBrowserConfig> {
    let body = match std::fs::read(path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ManagedBrowserConfig::default());
        }
        Err(error) => Err(error)
            .with_context(|| format!("read public browser configuration at {}", path.display()))?,
    };
    let value: serde_yaml::Value = serde_yaml::from_slice(&body)
        .with_context(|| format!("parse public browser configuration at {}", path.display()))?;
    let serde_yaml::Value::Mapping(mapping) = value else {
        anyhow::bail!(
            "public browser configuration at {} must be a YAML mapping",
            path.display()
        );
    };
    let key = serde_yaml::Value::String("managed_browser".to_owned());
    match mapping.get(&key) {
        Some(value) => serde_yaml::from_value(value.clone()).with_context(|| {
            format!(
                "parse public managed_browser configuration at {}",
                path.display()
            )
        }),
        None => Ok(ManagedBrowserConfig::default()),
    }
}

#[cfg(test)]
async fn run_browser_at(
    home: &std::path::Path,
    freedom: &FreedomConfig,
    args: BrowserArgs,
    output: OutputFormat,
) -> Result<()> {
    let platform = current_platform()?;
    match args.action {
        BrowserAction::Status => render_status(home, platform, &freedom.managed_browser, output),
        BrowserAction::Install => run_install(home, platform, freedom, output).await,
    }
}

fn current_platform() -> Result<ManagedBrowserPlatform> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        Ok(ManagedBrowserPlatform::Win64)
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok(ManagedBrowserPlatform::Linux64)
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        Ok(ManagedBrowserPlatform::MacX64)
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Ok(ManagedBrowserPlatform::MacArm64)
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
    )))]
    {
        anyhow::bail!("managed browser has no reviewed artifact for this platform")
    }
}

fn status_at(
    home: &std::path::Path,
    platform: ManagedBrowserPlatform,
    config: &ManagedBrowserConfig,
) -> BrowserArtifactView {
    if !config.enabled {
        return BrowserArtifactView {
            platform: platform.as_str(),
            enabled: false,
            artifact_status: "disabled",
            executable: None,
            version: None,
            revision: None,
            archive_sha256: None,
            detail: Some(
                "managed browser is disabled by configuration; local artifact was not inspected"
                    .into(),
            ),
        };
    }

    let canonical_home = match home.canonicalize() {
        Ok(home) => home,
        Err(error) => {
            return BrowserArtifactView {
                platform: platform.as_str(),
                enabled: true,
                artifact_status: "unverified",
                executable: None,
                version: None,
                revision: None,
                archive_sha256: None,
                detail: Some(format!("cannot canonicalize NEOTH home: {error}")),
            };
        }
    };
    match ManagedBrowserRuntimeResolver::new(&canonical_home, platform, config).resolve() {
        Ok(resolved) => BrowserArtifactView {
            platform: platform.as_str(),
            enabled: true,
            artifact_status: "verified",
            executable: Some(resolved.executable().display().to_string()),
            version: Some(resolved.version().to_owned()),
            revision: Some(resolved.revision().to_owned()),
            archive_sha256: Some(resolved.archive_sha256().to_owned()),
            detail: None,
        },
        Err(error) => BrowserArtifactView {
            platform: platform.as_str(),
            enabled: true,
            artifact_status: "unverified",
            executable: None,
            version: None,
            revision: None,
            archive_sha256: None,
            detail: Some(error.to_string()),
        },
    }
}

fn render_status(
    home: &std::path::Path,
    platform: ManagedBrowserPlatform,
    config: &ManagedBrowserConfig,
    output: OutputFormat,
) -> Result<()> {
    let status = status_at(home, platform, config);
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&status)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&status)?),
        OutputFormat::Table => {
            println!("managed browser artifact");
            println!("  platform: {0}", status.platform);
            println!(
                "  config:   {0}",
                if status.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("  artifact: {0}", status.artifact_status);
            if let Some(executable) = status.executable {
                println!("  executable: {executable}");
            }
            if let Some(version) = status.version {
                println!("  version: {version}");
            }
            if let Some(revision) = status.revision {
                println!("  revision: {revision}");
            }
            if let Some(detail) = status.detail {
                println!("  detail: {detail}");
            }
            println!("  note: artifact verification only; browser runtime is not checked");
        }
    }
    Ok(())
}

async fn run_install(
    home: &std::path::Path,
    platform: ManagedBrowserPlatform,
    freedom: &FreedomConfig,
    output: OutputFormat,
) -> Result<()> {
    // This gate stays ahead of authorizer construction, which is what makes a
    // default-off config prove no network request and no installer mutation.
    ensure!(
        freedom.managed_browser.enabled,
        "managed browser install is disabled by freedom.yaml::managed_browser.enabled"
    );
    let canonical_home = home
        .canonicalize()
        .context("canonicalize NEOTH home before managed-browser installation")?;
    let http = ExternalHttpAuthorizer::interactive_at(&canonical_home, freedom.autonomy_policy())?;
    let cancelled = AtomicBool::new(false);
    let install = run_install_with_authorizer(
        &canonical_home,
        platform,
        &freedom.managed_browser,
        &http,
        &cancelled,
        output,
    );
    tokio::pin!(install);
    tokio::select! {
        result = &mut install => result,
        signal = tokio::signal::ctrl_c() => {
            signal.context("register managed-browser Ctrl-C cancellation")?;
            cancelled.store(true, Ordering::Release);
            install.await
        }
    }
}

async fn run_install_with_authorizer(
    home: &std::path::Path,
    platform: ManagedBrowserPlatform,
    config: &ManagedBrowserConfig,
    http: &ExternalHttpAuthorizer,
    cancelled: &AtomicBool,
    output: OutputFormat,
) -> Result<()> {
    let result = install_reviewed_managed_browser(home, platform, config, http, cancelled).await?;
    let resolved = result.resolved();
    let receipt = serde_json::json!({
        "platform": resolved.platform().as_str(),
        "installed": result.installed(),
        "artifact_status": "verified",
        "executable": resolved.executable().display().to_string(),
        "version": resolved.version(),
        "revision": resolved.revision(),
        "archive_sha256": resolved.archive_sha256(),
    });
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&receipt)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&receipt)?),
        OutputFormat::Table => println!(
            "managed browser {} and verified: {} ({})",
            if result.installed() {
                "installed"
            } else {
                "already installed"
            },
            resolved.version(),
            resolved.platform().as_str(),
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn browser_parser_accepts_exact_status_and_install_actions() {
        assert!(matches!(
            crate::cli::Cli::try_parse_from(["neoth", "browser", "status"])
                .unwrap()
                .command,
            crate::cli::Commands::Browser(BrowserArgs {
                action: BrowserAction::Status
            })
        ));
        assert!(matches!(
            crate::cli::Cli::try_parse_from(["neoth", "browser", "install"])
                .unwrap()
                .command,
            crate::cli::Commands::Browser(BrowserArgs {
                action: BrowserAction::Install
            })
        ));
    }

    #[test]
    fn disabled_status_does_not_inspect_or_claim_runtime_readiness() {
        let view = status_at(
            std::path::Path::new("missing-managed-browser-home"),
            ManagedBrowserPlatform::Win64,
            &ManagedBrowserConfig::default(),
        );
        assert!(!view.enabled);
        assert_eq!(view.artifact_status, "disabled");
        assert!(view.executable.is_none());
        assert!(view.detail.unwrap().contains("not inspected"));
    }

    #[test]
    fn enabled_status_reports_unverified_artifact_without_starting_a_browser() {
        let home = tempfile::tempdir().unwrap();
        let missing = home.path().join("missing-managed-browser-home");
        let view = status_at(
            &missing,
            ManagedBrowserPlatform::Win64,
            &ManagedBrowserConfig { enabled: true },
        );
        assert!(view.enabled);
        assert_eq!(view.artifact_status, "unverified");
        assert!(view.executable.is_none());
        assert!(view.detail.unwrap().contains("canonicalize NEOTH home"));
    }

    #[test]
    fn read_only_policy_loader_uses_defaults_for_a_missing_file_without_lock_artifacts() {
        let home = tempfile::tempdir().unwrap();
        let config_path = home.path().join("freedom.yaml");
        let config = load_browser_config_read_only_at(&config_path).unwrap();
        assert!(!config.enabled);
        assert!(!home.path().join("credentials.lock").exists());
        assert!(!home.path().join("freedom.yaml.lock").exists());
    }

    #[test]
    fn read_only_policy_loader_preserves_existing_legacy_credential_source_without_locks() {
        let home = tempfile::tempdir().unwrap();
        let config_path = home.path().join("freedom.yaml");
        let source = b"provider_key: legacy-inline-sentinel\nmanaged_browser:\n  enabled: false\n";
        std::fs::write(&config_path, source).unwrap();

        let config = load_browser_config_read_only_at(&config_path).unwrap();

        assert!(!config.enabled);
        assert_eq!(std::fs::read(&config_path).unwrap(), source);
        assert!(!home.path().join("credentials.lock").exists());
        assert!(!home.path().join("freedom.yaml.lock").exists());
        assert!(
            !home
                .path()
                .join(".freedom-credentials.transaction.lock")
                .exists()
        );
    }

    #[tokio::test]
    async fn disabled_install_fails_before_authorizer_or_installer_delegation() {
        let home = tempfile::tempdir().unwrap();
        let freedom = FreedomConfig::default();
        let error = run_browser_at(
            home.path(),
            &freedom,
            BrowserArgs {
                action: BrowserAction::Install,
            },
            OutputFormat::Json,
        )
        .await
        .expect_err("default-off install must stop before HTTP/WAL setup");
        assert!(error.to_string().contains("managed_browser.enabled"));
        assert!(!home.path().join("managed-browser").exists());
    }

    #[tokio::test]
    async fn cancelled_enabled_install_reaches_real_explicit_home_wal_authorizer_then_stops() {
        let home = tempfile::tempdir().unwrap();
        let canonical_home = home.path().canonicalize().unwrap();
        let config = ManagedBrowserConfig { enabled: true };
        let policy = FreedomConfig::default().autonomy_policy();
        let http = ExternalHttpAuthorizer::interactive_at(&canonical_home, policy).unwrap();
        let cancelled = AtomicBool::new(true);

        let error = run_install_with_authorizer(
            &canonical_home,
            ManagedBrowserPlatform::Win64,
            &config,
            &http,
            &cancelled,
            OutputFormat::Json,
        )
        .await
        .expect_err("cancelled install must stop at the real installer before transport");
        assert!(error.to_string().contains("cancelled"));
        assert!(canonical_home.join("wal").is_dir());
        assert!(!canonical_home.join("managed-browser").exists());
    }
}
