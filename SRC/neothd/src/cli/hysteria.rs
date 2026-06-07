//! `neoth hysteria` — inspect + test the Hysteria transport config.
//!
//! No `start`/`stop` subcommands today: the supervisor is spawned by
//! `neothd serve` from `freedom.yaml::hysteria` so there's only one
//! authoritative start path. This CLI lets operators verify the binary
//! is reachable, the config renders, and the SOCKS5 port is up while
//! the daemon is running.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::transport::hysteria::{locate_binary, probe_socks_port, render_yaml_config};

#[derive(Args, Debug, Clone)]
pub struct HysteriaArgs {
    #[command(subcommand)]
    pub action: HysteriaAction,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum HysteriaAction {
    /// Print the current config + binary location + a SOCKS5 probe
    /// result. Operator-facing summary.
    Status,
    /// Render `~/.neoth/freedom.yaml::hysteria` as the YAML the
    /// subprocess would receive on disk. No spawn, no probe — pure
    /// preview so operators can verify before `neothd serve`.
    RenderConfig,
    /// TCP-probe the SOCKS5 port from freedom.yaml. Exits non-zero if
    /// the probe fails, so it composes in shell scripts:
    /// `neoth hysteria test && echo ok`.
    Test,
}

pub async fn run_hysteria(args: HysteriaArgs) -> Result<()> {
    match args.action {
        HysteriaAction::Status => run_status(&args.output),
        HysteriaAction::RenderConfig => run_render_config(),
        HysteriaAction::Test => run_test().await,
    }
}

fn run_status(output: &OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().ok();
    let hysteria = cfg.as_ref().and_then(|c| c.hysteria.clone());
    let binary = locate_binary().ok().map(|p| p.display().to_string());
    let configured = hysteria
        .as_ref()
        .map(|h| !h.server.is_empty())
        .unwrap_or(false);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "configured": configured,
                "binary": binary,
                "server": hysteria.as_ref().map(|h| h.server.clone()),
                "local_socks_port": hysteria.as_ref().map(|h| h.local_socks_port),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Hysteria transport status");
            println!("  configured        : {configured}");
            println!(
                "  binary            : {}",
                binary.as_deref().unwrap_or("(not found)")
            );
            if let Some(h) = &hysteria {
                println!(
                    "  server            : {}",
                    if h.server.is_empty() {
                        "(unset)".to_string()
                    } else {
                        h.server.clone()
                    }
                );
                println!("  local_socks_port  : {}", h.local_socks_port);
            }
            if !configured {
                println!();
                println!("  configure via freedom.yaml::hysteria, then restart `neothd serve`.");
            }
        }
    }
    Ok(())
}

fn run_render_config() -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()?;
    // Intentional fallback to empty default when freedom.yaml has no
    // hysteria section — preview command should show the template shape
    // an operator would fill in, not bail.
    let hcfg = cfg.hysteria.clone().unwrap_or_default();
    let rendered = render_yaml_config(&hcfg);
    // CLI output goes to stdout / shell scrollback / piped logs. Auth
    // tokens at rest in the daemon's spawn path are protected (mode-
    // 0600 temp file, deleted on drop) — the CLI render is a different
    // surface and must redact. Operators who need the real secret read
    // freedom.yaml / credentials.yaml directly.
    let safe = redact_auth_line(&rendered, hcfg.auth.expose());
    print!("{safe}");
    Ok(())
}

/// Replace the literal `auth: <value>` line with `auth: <redacted>` for
/// terminal output. Acts only on the exact value the caller passed so
/// a config that genuinely has `auth: ` as a substring elsewhere isn't
/// over-redacted.
fn redact_auth_line(yaml: &str, auth: &str) -> String {
    if auth.is_empty() {
        return yaml.to_string();
    }
    yaml.replace(&format!("auth: {auth}"), "auth: <redacted>")
}

async fn run_test() -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()?;
    let port = cfg
        .hysteria
        .as_ref()
        .map(|h| h.local_socks_port)
        .ok_or_else(|| {
            anyhow::anyhow!("freedom.yaml::hysteria not set; nothing to test. Configure it first.")
        })?;
    probe_socks_port(port).await?;
    println!("hysteria SOCKS5 port {port} reachable");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::hysteria::HysteriaConfig;

    #[test]
    fn render_yaml_includes_listener() {
        // We can call the underlying renderer directly without setting
        // up `~/.neoth/`. This is a smoke test for the CLI's plumbing
        // path.
        let cfg = HysteriaConfig {
            server: "vps:443".into(),
            auth: "tok".into(),
            local_socks_port: 1080,
        };
        let body = render_yaml_config(&cfg);
        // GOLD-SEC-35 / A-69: scalars are emitted as double-quoted YAML,
        // so the server line is `server: "vps:443"` (the bare-form
        // assertion this test shipped with went stale when quoting landed).
        assert!(body.contains("server: \"vps:443\""), "got: {body}");
        assert!(body.contains("listen: 127.0.0.1:1080"), "got: {body}");
    }

    #[test]
    fn redact_auth_replaces_only_exact_line() {
        let yaml = "server: vps:443\nauth: super-secret-token\nsocks5:\n  listen: 127.0.0.1:1080\n";
        let safe = redact_auth_line(yaml, "super-secret-token");
        assert!(!safe.contains("super-secret-token"));
        assert!(safe.contains("auth: <redacted>"));
        // Other fields stay intact.
        assert!(safe.contains("server: vps:443"));
        assert!(safe.contains("listen: 127.0.0.1:1080"));
    }

    #[test]
    fn redact_auth_noop_on_empty_token() {
        let yaml = "server: vps:443\nauth: \nsocks5:\n  listen: 127.0.0.1:1080\n";
        let safe = redact_auth_line(yaml, "");
        // Empty auth — nothing to redact, original returned verbatim.
        assert_eq!(safe, yaml);
    }
}
