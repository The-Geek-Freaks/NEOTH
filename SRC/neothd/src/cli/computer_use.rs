//! `neoth computer-use` — manage NEOTH's desktop computer-use capability
//! (trycua cua-driver, wired as a gated MCP server). See `crate::computer_use`.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::computer_use as cu;
use crate::mcp::config::{McpServerConfig, McpServers};

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
        if installed {
            "yes"
        } else {
            "NO — run `neoth computer-use install`"
        }
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

fn update_cua_driver_entry(entry: &mut McpServerConfig, on: bool) -> &'static str {
    entry.enabled = on;
    if on && cu::is_legacy_cua_driver_default(entry) {
        entry.allow_tools = Some(
            cu::COMPUTER_USE_TOOLS
                .iter()
                .map(|tool| tool.to_string())
                .collect(),
        );
        "migrated legacy default + enabled"
    } else if on {
        "re-enabled existing entry"
    } else {
        "disabled"
    }
}

fn set_enabled(on: bool, output: OutputFormat) -> Result<()> {
    let path = McpServers::default_path();
    // B18: route all writes through update_at (locked + validated + atomic).
    // Ok(false) from the closure → no write (disable of non-existent is a no-op).
    let mut action = "not registered (nothing to disable)";
    McpServers::update_at(&path, |servers| {
        if let Some(s) = servers
            .servers
            .iter_mut()
            .find(|s| s.id == cu::CUA_DRIVER_SERVER_ID)
        {
            action = update_cua_driver_entry(s, on);
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

fn classify_advertised_tools(
    allowed: &[String],
    advertised: &[String],
) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let missing: Vec<String> = allowed
        .iter()
        .filter(|tool| !advertised.contains(tool))
        .cloned()
        .collect();
    let missing_capabilities: Vec<String> = cu::COMPUTER_USE_CAPABILITY_GROUPS
        .iter()
        .filter(|(_, group)| allowed.iter().any(|tool| group.contains(&tool.as_str())))
        .filter(|(_, group)| {
            !group.iter().any(|tool| {
                allowed
                    .iter()
                    .any(|allowed_tool| allowed_tool.as_str() == *tool)
                    && advertised
                        .iter()
                        .any(|advertised_tool| advertised_tool.as_str() == *tool)
            })
        })
        .map(|(capability, _)| (*capability).to_string())
        .collect();
    let compatibility_aliases_absent = missing
        .iter()
        .filter(|tool| {
            let capability_is_missing = cu::COMPUTER_USE_CAPABILITY_GROUPS
                .iter()
                .find(|(_, group)| group.contains(&tool.as_str()))
                .is_some_and(|(capability, _)| {
                    missing_capabilities.contains(&capability.to_string())
                });
            !capability_is_missing
        })
        .cloned()
        .collect();
    let extra = advertised
        .iter()
        .filter(|tool| !allowed.contains(tool))
        .cloned()
        .collect();
    (
        missing,
        missing_capabilities,
        compatibility_aliases_absent,
        extra,
    )
}

fn effective_allowed_for_doctor(
    configured: Option<&McpServerConfig>,
    advertised: Option<&[String]>,
    recommended: &[String],
) -> (Vec<String>, &'static str) {
    match configured {
        Some(server) => match &server.allow_tools {
            Some(allowed) => (allowed.clone(), "configured_pinned"),
            None if server.trust_all_tools => (
                advertised.map(ToOwned::to_owned).unwrap_or_default(),
                "configured_trusted_catalogue",
            ),
            None => (Vec::new(), "configured_secure_default_deny"),
        },
        None => (recommended.to_vec(), "recommended_unconfigured"),
    }
}

/// Runtime proof + allowlist-drift check: installed version, the LIVE advertised
/// tools via a real MCP handshake + `tools/list`, the pinned allowlist, and the
/// missing/extra diff (catches a cua-driver upgrade that renamed tools).
async fn doctor(output: OutputFormat) -> Result<()> {
    let installed = cu::is_installed();
    let version = cu::cua_driver_version();
    let recommended_allowed: Vec<String> = cu::COMPUTER_USE_TOOLS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let configured_servers = McpServers::load_from(&McpServers::default_path())?;
    let configured = configured_servers
        .servers
        .iter()
        .find(|server| server.id == cu::CUA_DRIVER_SERVER_ID)
        .cloned();
    let configured_allowed = configured
        .as_ref()
        .and_then(|server| server.allow_tools.clone());
    let probe_command = configured
        .as_ref()
        .map_or("cua-driver", |server| server.command.as_str());

    // The runtime proof: spawn cua-driver, do the MCP initialize handshake, and
    // read its real `tools/list`. An explicit configured command may be an
    // absolute path or wrapper even when cua-driver itself is absent from PATH.
    let mut advertised: Option<Vec<String>> = None;
    let mut probe_error: Option<String> = None;
    if installed || configured.is_some() {
        let driver = configured.clone().unwrap_or_else(cu::cua_driver_server);
        match crate::mcp::client::McpClient::spawn(&driver).await {
            Ok(mut client) => match client.list_tools().await {
                Ok(tools) => advertised = Some(tools.into_iter().map(|t| t.name).collect()),
                Err(e) => probe_error = Some(format!("tools/list failed: {e}")),
            },
            Err(e) => probe_error = Some(format!("MCP handshake failed: {e}")),
        }
    }

    let (allowed, comparison_allowlist_source) = effective_allowed_for_doctor(
        configured.as_ref(),
        advertised.as_deref(),
        &recommended_allowed,
    );

    let (missing, missing_capabilities, compatibility_aliases_absent, extra) = match &advertised {
        Some(adv) => classify_advertised_tools(&allowed, adv),
        None => (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
    };

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "installed": installed, "version": version,
                "version_source": "cua-driver on PATH", "probe_command": probe_command,
                "advertised": advertised,
                "recommended_allowed": recommended_allowed,
                "configured_allowed": configured_allowed,
                "configured_enabled": configured.as_ref().map(|server| server.enabled),
                "configured_trust_all_tools": configured.as_ref().map(|server| server.trust_all_tools),
                "comparison_allowlist_source": comparison_allowlist_source,
                "allowed": allowed, "missing": &missing,
                "missing_capabilities": &missing_capabilities,
                "compatibility_aliases_absent": &compatibility_aliases_absent,
                "extra": &extra, "probe_error": probe_error,
            })
        );
        return Ok(());
    }

    println!("NEOTH computer-use doctor (cua-driver)");
    println!(
        "  PATH driver installed: {}",
        if installed { "yes" } else { "NO" }
    );
    println!(
        "  PATH driver version: {}",
        version.as_deref().unwrap_or("—")
    );
    println!("  probe command: {probe_command}");
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
        "  compared allowlist: {} tools — {}",
        allowed.len(),
        allowed.join(", ")
    );
    match &configured {
        Some(server) => println!(
            "  configured: saved {} allowlist{} (trust_all_tools: {}; policy: {})",
            if server.allow_tools.is_some() {
                "pinned"
            } else {
                "un-pinned"
            },
            if server.enabled { "" } else { ", disabled" },
            server.trust_all_tools,
            comparison_allowlist_source,
        ),
        None => println!(
            "  configured: no saved cua-driver entry; comparing recommended allowlist only"
        ),
    }
    if !missing_capabilities.is_empty() {
        println!(
            "  ⚠ MISSING CAPABILITIES: required pinned verbs NOT advertised — {}",
            missing_capabilities.join(", ")
        );
    }
    if !compatibility_aliases_absent.is_empty() {
        println!(
            "  ℹ COMPATIBILITY ALIASES ABSENT: legacy names not advertised by this driver — {}",
            compatibility_aliases_absent.join(", ")
        );
    }
    if !extra.is_empty() {
        println!(
            "  ⚠ EXTRA   : advertised but NOT allowed (blocked by the allowlist) — {}",
            extra.join(", ")
        );
    }
    if advertised.is_some() && missing_capabilities.is_empty() && extra.is_empty() {
        println!(
            "  ✓ all required capabilities are advertised; compatibility aliases may be absent."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computer_use_enable_migrates_only_the_exact_legacy_default() {
        let mut legacy = cu::cua_driver_server();
        legacy.enabled = false;
        legacy.allow_tools = Some(
            cu::LEGACY_COMPUTER_USE_TOOLS
                .iter()
                .map(|tool| tool.to_string())
                .collect(),
        );
        assert_eq!(
            update_cua_driver_entry(&mut legacy, true),
            "migrated legacy default + enabled"
        );
        assert!(legacy.enabled);
        assert_eq!(
            legacy.allow_tools.unwrap(),
            cu::COMPUTER_USE_TOOLS
                .iter()
                .map(|tool| tool.to_string())
                .collect::<Vec<_>>()
        );

        let mut customized = cu::cua_driver_server();
        customized.enabled = false;
        customized.command = "operator-cua-driver".to_string();
        customized.args = vec!["custom-mcp".to_string()];
        customized
            .env
            .insert("CUA_PROFILE".to_string(), "private".to_string());
        customized.allow_tools = Some(vec!["click".to_string()]);
        let before = customized.clone();
        assert_eq!(
            update_cua_driver_entry(&mut customized, true),
            "re-enabled existing entry"
        );
        assert!(customized.enabled);
        assert_eq!(customized.command, before.command);
        assert_eq!(customized.args, before.args);
        assert_eq!(customized.env, before.env);
        assert_eq!(customized.allow_tools, before.allow_tools);
    }

    #[test]
    fn doctor_classifies_legacy_current_missing_and_custom_capability_sets() {
        let union = cu::COMPUTER_USE_TOOLS
            .iter()
            .map(|tool| tool.to_string())
            .collect::<Vec<_>>();
        let current = [
            "click",
            "drag",
            "scroll",
            "get_desktop_state",
            "get_window_state",
            "move_cursor",
            "type_text",
            "press_key",
            "hotkey",
            "list_windows",
        ]
        .iter()
        .map(|tool| tool.to_string())
        .collect::<Vec<_>>();
        let legacy = cu::LEGACY_COMPUTER_USE_TOOLS
            .iter()
            .map(|tool| tool.to_string())
            .collect::<Vec<_>>();
        let (_, missing_capabilities, aliases, extra) = classify_advertised_tools(&union, &legacy);
        assert!(
            missing_capabilities.is_empty(),
            "legacy names cover every group"
        );
        assert!(aliases.contains(&"type_text".to_string()));
        assert!(extra.is_empty());

        let (_, missing_capabilities, aliases, extra) = classify_advertised_tools(&union, &current);
        assert!(
            missing_capabilities.is_empty(),
            "current names cover every group"
        );
        assert!(aliases.contains(&"screenshot".to_string()));
        assert!(extra.is_empty());

        let no_screen = current
            .iter()
            .filter(|tool| {
                tool.as_str() != "get_desktop_state" && tool.as_str() != "get_window_state"
            })
            .cloned()
            .collect::<Vec<_>>();
        let (_, missing_capabilities, _, _) = classify_advertised_tools(&union, &no_screen);
        assert_eq!(missing_capabilities, vec!["screen".to_string()]);

        let custom_allowed = vec!["click".to_string()];
        let (_, missing_capabilities, aliases, extra) =
            classify_advertised_tools(&custom_allowed, &vec!["click".to_string()]);
        assert!(missing_capabilities.is_empty());
        assert!(aliases.is_empty());
        assert!(extra.is_empty());
    }

    #[test]
    fn verified_upstream_catalogue_keeps_nineteen_unrelated_tools_denied() {
        let standard = cu::COMPUTER_USE_TOOLS
            .iter()
            .map(|tool| tool.to_string())
            .collect::<Vec<_>>();
        let upstream_29 = [
            "click",
            "clipboard_read",
            "clipboard_write",
            "drag",
            "end_session",
            "escalate_session",
            "get_agent_cursor_state",
            "get_cursor_position",
            "get_desktop_state",
            "get_screen_size",
            "get_session",
            "get_session_state",
            "get_window_state",
            "hotkey",
            "invoke_menu",
            "list_apps",
            "list_sessions",
            "list_windows",
            "move_cursor",
            "parse_visual_regions",
            "press_key",
            "scroll",
            "set_agent_cursor_enabled",
            "set_agent_cursor_motion",
            "set_agent_cursor_theme",
            "set_window_frame",
            "start_session",
            "type_text",
            "verify_state",
        ]
        .iter()
        .map(|tool| tool.to_string())
        .collect::<Vec<_>>();
        let (_, missing_capabilities, _, extra) =
            classify_advertised_tools(&standard, &upstream_29);
        assert!(missing_capabilities.is_empty());
        assert_eq!(extra.len(), 19);
        for denied in [
            "clipboard_read",
            "escalate_session",
            "start_session",
            "set_window_frame",
            "parse_visual_regions",
        ] {
            assert!(
                extra.contains(&denied.to_string()),
                "must remain denied: {denied}"
            );
        }
    }

    #[test]
    fn doctor_reports_trusted_catalogue_as_effective_full_access() {
        let mut trusted = cu::cua_driver_server();
        trusted.allow_tools = None;
        trusted.trust_all_tools = true;
        let advertised = vec!["click".to_string(), "clipboard_read".to_string()];
        let recommended = cu::COMPUTER_USE_TOOLS
            .iter()
            .map(|tool| tool.to_string())
            .collect::<Vec<_>>();

        let (allowed, policy) =
            effective_allowed_for_doctor(Some(&trusted), Some(&advertised), &recommended);
        assert_eq!(policy, "configured_trusted_catalogue");
        assert_eq!(allowed, advertised);
        let (_, _, _, extra) = classify_advertised_tools(&allowed, &advertised);
        assert!(
            extra.is_empty(),
            "trusted catalogue must not be shown as blocked"
        );
    }
}
