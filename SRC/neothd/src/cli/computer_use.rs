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
}

pub fn run_computer_use(args: ComputerUseArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        ComputerUseAction::Status => status(output),
        ComputerUseAction::Enable => set_enabled(true, output),
        ComputerUseAction::Disable => set_enabled(false, output),
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
    let servers = McpServers::load().unwrap_or_default();
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
        println!("  allowlisted tools: {tool_count} (secure-by-default; autonomy-gated + WAL-audited)");
    }
    Ok(())
}

fn set_enabled(on: bool, output: OutputFormat) -> Result<()> {
    let mut servers = McpServers::load().unwrap_or_default();
    let action = if let Some(s) = servers
        .servers
        .iter_mut()
        .find(|s| s.id == cu::CUA_DRIVER_SERVER_ID)
    {
        s.enabled = on;
        if on { "re-enabled existing entry" } else { "disabled" }
    } else if on {
        servers.servers.push(cu::cua_driver_server());
        "registered + enabled"
    } else {
        // disabling a non-existent entry — nothing to do
        "not registered (nothing to disable)"
    };

    let path = McpServers::default_path();
    let yaml = serde_yaml::to_string(&servers)?;
    crate::util::atomic_write::atomic_write(&path, yaml.as_bytes())?;

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
