//! `neoth computer-use` — manage NEOTH's desktop computer-use capability
//! (trycua cua-driver, wired as a gated MCP server). See `crate::computer_use`.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::computer_use as cu;
use crate::mcp::config::McpServers;

#[derive(Args, Debug, Clone)]
pub struct ComputerUseArgs {
    #[command(subcommand)]
    pub action: ComputerUseAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ComputerUseAction {
    /// Show whether cua-driver is installed + enabled as an MCP server.
    Status,
    /// Enable computer-use: register the cua-driver MCP server (secure-by-
    /// default allowlist) in `mcp_servers.yaml` so the agent gets the tools.
    Enable,
    /// Disable computer-use (keeps the entry, sets `enabled: false`).
    Disable,
    /// Print the cua-driver install command for this platform.
    Install,
    /// Runtime proof + allowlist drift check: installed version, the LIVE
    /// advertised tools (real MCP handshake + `tools/list`), the pinned
    /// allowlist, and a missing/extra diff.
    Doctor,
}

pub async fn run_computer_use(args: ComputerUseArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        ComputerUseAction::Status => status(output),
        ComputerUseAction::Enable => set_enabled(true, output),
        ComputerUseAction::Disable => set_enabled(false, output),
        ComputerUseAction::Doctor => doctor(output).await,
        ComputerUseAction::Install => {
            let cmd = cu::install_command();
            let json = matches!(output, OutputFormat::Json | OutputFormat::Jsonl);
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "install_command": cmd, "installed": cu::is_installed() })
                );
            } else {
                println!("Install cua-driver (run in a shell):\n\n    {cmd}\n");
                println!("Then: `neoth computer-use enable`");
            }
            Ok(())
        }
    }
}

fn status(output: OutputFormat) -> Result<()> {
    let installed = cu::is_installed();
    // B18: strict load — invalid YAML is a distinct failure mode from "not
    // registered" and must not be silently swallowed as an empty config.
    let servers = match McpServers::load_from(&McpServers::default_path()) {
        Ok(s) => s,
        Err(e) => {
            if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
                println!(
                    "{}",
                    serde_json::json!({
                        "installed": installed,
                        "load_error": e.to_string(),
                        "server_id": cu::CUA_DRIVER_SERVER_ID,
                    })
                );
            } else {
                eprintln!("error: failed to load mcp_servers.yaml: {e}");
            }
            return Err(e);
        }
    };

    let entry = servers
        .servers
        .iter()
        .find(|s| s.id == cu::CUA_DRIVER_SERVER_ID);
    let enabled = entry.map(|s| s.enabled).unwrap_or(false);
    let tool_count = entry
        .and_then(|s| s.allow_tools.as_ref().map(|t| t.len()))
        .unwrap_or(0);

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "installed": installed,
                "registered": entry.is_some(),
                "enabled": enabled,
                "allowlisted_tools": tool_count,
                "server_id": cu::CUA_DRIVER_SERVER_ID,
                "load_error": serde_json::Value::Null,
            })
        );
        return Ok(());
    }

    println!("NEOTH computer-use (cua-driver)");
    println!(
        "  driver installed : {}",
        if installed { "yes" } else { "NO — run `neoth computer-use install`" }
    );
    println!(
        "  MCP server       : {}",
        match entry {
            Some(s) if s.enabled => "registered + ENABLED".to_string(),
            Some(_) => "registered (disabled)".to_string(),
            None => "not registered — run `neoth computer-use enable`".to_string(),
        }
    );
    if enabled {
        println!(
            "  allowlisted tools: {tool_count} (secure-by-default; autonomy-gated + WAL-audited)"
        );
    }
    Ok(())
}

fn set_enabled(on: bool, output: OutputFormat) -> Result<()> {
    let path = McpServers::default_path();
    // B18: route all writes through update_at (locked + validated + atomic).
    // Ok(false) from the closure → no write (disable of non-existent is a no-op).
    let mut action = "not registered (nothing to disable)";
    McpServers::update_at(&path, |servers| {
        if let Some(s) = servers.servers.iter_mut().find(|s| s.id == cu::CUA_DRIVER_SERVER_ID) {
            s.enabled = on;
            action = if on { "re-enabled existing entry" } else { "disabled" };
            Ok(true)
        } else if on {
            servers.servers.push(cu::cua_driver_server());
            action = "registered + enabled";
            Ok(true)
        } else {
            // Disabling a non-existent entry — no write needed.
            Ok(false)
        }
    })?;

    let installed = cu::is_installed();
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "enabled": on, "action": action, "installed": installed,
                "path": path.display().to_string(),
            })
        );
        return Ok(());
    }
    println!("computer-use {action} → {}", path.display());
    if on && !installed {
        println!(
            "\n⚠ cua-driver is NOT installed yet. Install it:\n\n    {}\n",
            cu::install_command()
        );
    } else if on {
        println!("The agent now has computer-use tools (autonomy-gated + WAL-audited).");
    }
    Ok(())
}

/// Runtime proof + allowlist-drift check: installed version, the LIVE advertised
/// tools via a real MCP handshake + `tools/list`, the pinned allowlist, and the
/// missing/extra diff (catches a cua-driver upgrade that renamed tools).
async fn doctor(output: OutputFormat) -> Result<()> {
    let installed = cu::is_installed();
    let version = cu::cua_driver_version();
    let allowed: Vec<String> = cu::COMPUTER_USE_TOOLS
        .iter()
        .map(|s| s.to_string())
        .collect();

    // The runtime proof: spawn cua-driver, do the MCP initialize handshake, and
    // read its real `tools/list`. None when not installed / handshake fails.
    let mut advertised: Option<Vec<String>> = None;
    let mut probe_error: Option<String> = None;
    if installed {
        match crate::mcp::client::McpClient::spawn(&cu::cua_driver_server()).await {
            Ok(mut client) => match client.list_tools().await {
                Ok(tools) => advertised = Some(tools.into_iter().map(|t| t.name).collect()),
                Err(e) => probe_error = Some(format!("tools/list failed: {e}")),
            },
            Err(e) => probe_error = Some(format!("MCP handshake failed: {e}")),
        }
    }

    let (missing, extra): (Vec<String>, Vec<String>) = match &advertised {
        Some(adv) => (
            allowed
                .iter()
                .filter(|a| !adv.contains(a))
                .cloned()
                .collect(),
            adv.iter()
                .filter(|a| !allowed.contains(a))
                .cloned()
                .collect(),
        ),
        None => (Vec::new(), Vec::new()),
    };

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "installed": installed, "version": version,
                "advertised": advertised, "allowed": allowed,
                "missing": missing, "extra": extra, "probe_error": probe_error,
            })
        );
        return Ok(());
    }

    println!("NEOTH computer-use doctor (cua-driver)");
    println!("  installed : {}", if installed { "yes" } else { "NO" });
    println!("  version   : {}", version.as_deref().unwrap_or("—"));
    match &advertised {
        Some(adv) => println!("  advertised: {} tools — {}", adv.len(), adv.join(", ")),
        None => println!(
            "  advertised: — (no live handshake{})",
            probe_error
                .as_ref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        ),
    }
    println!(
        "  allowed   : {} tools — {}",
        allowed.len(),
        allowed.join(", ")
    );
    if !missing.is_empty() {
        println!(
            "  ⚠ MISSING : pinned but NOT advertised — {} (driver upgrade may have renamed them; re-pin)",
            missing.join(", ")
        );
    }
    if !extra.is_empty() {
        println!(
            "  ⚠ EXTRA   : advertised but NOT allowed (blocked by the allowlist) — {}",
            extra.join(", ")
        );
    }
    if advertised.is_some() && missing.is_empty() && extra.is_empty() {
        println!("  ✓ allowlist matches the advertised tools exactly.");
    }
    Ok(())
}
