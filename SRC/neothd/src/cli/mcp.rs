//! `neoth mcp` — operator surface for MCP clients plus NEOTH's built-in
//! read-only codegraph server.
//!
//! Five actions:
//!   - `list` dumps `~/.neoth/mcp_servers.yaml`. No process spawning;
//!     pure read against the config.
//!   - `tools <server>` spawns the named server + runs `tools/list`
//!     and renders the catalogue. Verifies the server config actually
//!     produces a working handshake.
//!   - `call <server> <tool> --args '{...}'` invokes one tool. The args
//!     JSON is passed through unchanged.
//!   - `codegraph-serve` runs NEOTH's built-in read-only codegraph MCP server.
//!   - `codegraph-install` registers that server with an exact allowlist.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::mcp::{GateError, McpClient, McpServers, invoke_with_audit, list_tools_sanitized};

#[derive(Args, Debug, Clone)]
pub struct McpArgs {
    #[command(subcommand)]
    pub action: McpAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum McpAction {
    /// List configured MCP servers from `~/.neoth/mcp_servers.yaml`.
    /// Pure config read; no child processes are spawned.
    List,
    /// Spawn a server + dump its `tools/list` response.
    Tools {
        /// Server id from the config.
        server: String,
    },
    /// Invoke a single tool. `--args` accepts a JSON object; defaults
    /// to `{}` when omitted.
    Call {
        server: String,
        tool: String,
        #[arg(long, default_value = "{}")]
        args: String,
    },
    /// Serve NEOTH's six read-only codegraph tools over MCP stdio. Intended as
    /// a subprocess entrypoint for MCP hosts; stdout contains protocol messages
    /// only. Run `codegraph-install` to register it in NEOTH itself.
    CodegraphServe {
        /// Override the persisted code-map database path.
        #[arg(long)]
        db: Option<std::path::PathBuf>,
    },
    /// Idempotently register the built-in codegraph stdio server in
    /// `~/.neoth/mcp_servers.yaml` with an exact tool allowlist.
    CodegraphInstall {
        /// Override the code-map database passed to the server process.
        #[arg(long)]
        db: Option<std::path::PathBuf>,
    },
}

pub async fn run_mcp(args: McpArgs) -> Result<()> {
    match args.action {
        McpAction::List => run_list(&McpServers::load()?, &args.output),
        McpAction::Tools { server } => run_tools(&McpServers::load()?, &server, &args.output).await,
        McpAction::Call {
            server,
            tool,
            args: tool_args,
        } => {
            run_call(
                &McpServers::load()?,
                &server,
                &tool,
                &tool_args,
                &args.output,
            )
            .await
        }
        McpAction::CodegraphServe { db } => {
            crate::mcp::codegraph_server::serve_stdio(
                db.unwrap_or_else(crate::code_map::persist::default_path),
            )
            .await
        }
        McpAction::CodegraphInstall { db } => install_codegraph_server(db, &args.output),
    }
}

fn install_codegraph_server(db: Option<std::path::PathBuf>, output: &OutputFormat) -> Result<()> {
    const SERVER_ID: &str = "neoth-codegraph";
    let executable = std::env::current_exe()?.canonicalize()?;
    let desired = codegraph_server_config(&executable, db);
    desired.validate_launcher()?;
    let path = McpServers::default_path();
    McpServers::update_at(&path, |servers| {
        match servers
            .servers
            .iter_mut()
            .find(|server| server.id == SERVER_ID)
        {
            Some(existing) if existing == &desired => return Ok(false),
            Some(existing) => *existing = desired.clone(),
            None => servers.servers.push(desired.clone()),
        }
        Ok(true)
    })?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "installed": true,
                "id": SERVER_ID,
                "config": path,
                "command": desired.command,
                "args": desired.args,
                "allow_tools": desired.allow_tools,
            })
        ),
        OutputFormat::Table => println!(
            "installed `{SERVER_ID}` in {} ({} read-only tools)",
            path.display(),
            crate::mcp::codegraph_server::TOOL_NAMES.len()
        ),
    }
    Ok(())
}

fn codegraph_server_config(
    executable: &std::path::Path,
    db: Option<std::path::PathBuf>,
) -> crate::mcp::McpServerConfig {
    let mut server_args = vec!["mcp".to_string(), "codegraph-serve".to_string()];
    if let Some(db) = db {
        server_args.push("--db".into());
        server_args.push(db.canonicalize().unwrap_or(db).display().to_string());
    }
    crate::mcp::McpServerConfig {
        id: "neoth-codegraph".into(),
        description: Some("NEOTH's read-only persisted codegraph tools".into()),
        command: executable.display().to_string(),
        args: server_args,
        env: std::collections::HashMap::new(),
        enabled: true,
        allow_tools: Some(
            crate::mcp::codegraph_server::TOOL_NAMES
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        ),
        trust_all_tools: false,
        smart_approve: true,
        autonomy_gate: None,
    }
}

fn run_list(servers: &McpServers, output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let launcher_posture: Vec<serde_json::Value> = servers
                .servers
                .iter()
                .map(|server| match server.validate_launcher() {
                    Ok(posture) => serde_json::json!({
                        "id": server.id,
                        "valid": true,
                        "posture": posture.as_str(),
                    }),
                    Err(error) => serde_json::json!({
                        "id": server.id,
                        "valid": false,
                        "error": error.to_string(),
                    }),
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "count": servers.servers.len(),
                    "enabled_count": servers.enabled().len(),
                    "servers": servers.servers,
                    "launcher_posture": launcher_posture,
                }))?
            );
        }
        OutputFormat::Table => {
            if servers.servers.is_empty() {
                println!(
                    "# MCP servers\n  (none configured — create ~/.neoth/mcp_servers.yaml \
                     with `servers: [...]`)"
                );
                return Ok(());
            }
            println!("# MCP servers ({})", servers.servers.len());
            for s in &servers.servers {
                let status = if s.enabled { "ON " } else { "OFF" };
                let desc = s.description.as_deref().unwrap_or("(no description)");
                let launcher = s
                    .validate_launcher()
                    .map(|posture| posture.as_str().to_string())
                    .unwrap_or_else(|error| format!("INVALID: {error}"));
                println!(
                    "  {status}  {:<20}  launcher={launcher} command={} args={:?}",
                    s.id, s.command, s.args,
                );
                println!("           {desc}");
            }
        }
    }
    Ok(())
}

async fn run_tools(servers: &McpServers, server_id: &str, output: &OutputFormat) -> Result<()> {
    let cfg = servers.get_enabled(server_id).ok_or_else(|| {
        let known: Vec<&str> = servers.enabled().iter().map(|s| s.id.as_str()).collect();
        anyhow::anyhow!(
            "no enabled MCP server `{server_id}`. Enabled: {}",
            if known.is_empty() {
                "(none)".to_string()
            } else {
                known.join(", ")
            }
        )
    })?;
    let mut client = McpClient::spawn(cfg).await?;
    let tools = list_tools_sanitized(&mut client).await?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "server": server_id,
                    "count": tools.len(),
                    "flagged_count": tools.iter().filter(|t| t.verdict.flagged).count(),
                    "tools": tools.iter().map(|t| serde_json::json!({
                        "name": t.tool.name,
                        "description": t.tool.description,
                        "inputSchema": t.tool.input_schema,
                        "flagged": t.verdict.flagged,
                        "matched_patterns": t.verdict.matched_patterns,
                    })).collect::<Vec<_>>(),
                }))?
            );
        }
        OutputFormat::Table => {
            if tools.is_empty() {
                println!("# {server_id} — tools/list returned empty catalogue");
                return Ok(());
            }
            let flagged = tools.iter().filter(|t| t.verdict.flagged).count();
            println!("# {server_id} — {} tool(s)", tools.len());
            if flagged > 0 {
                println!("  ! {flagged} tool description(s) flagged by prompt-injection sanitizer");
            }
            for t in &tools {
                let desc = t.tool.description.as_deref().unwrap_or("(no description)");
                let marker = if t.verdict.flagged { "[!]" } else { "   " };
                println!("  {marker} {:<32}  {desc}", t.tool.name);
            }
        }
    }
    Ok(())
}

async fn run_call(
    servers: &McpServers,
    server_id: &str,
    tool: &str,
    args_json: &str,
    output: &OutputFormat,
) -> Result<()> {
    let cfg = servers.get_enabled(server_id).ok_or_else(|| {
        anyhow::anyhow!(
            "no enabled MCP server `{server_id}`. Run `neoth mcp list` for available ids."
        )
    })?;
    let args: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|e| anyhow::anyhow!("--args is not valid JSON: {e}"))?;
    let config = FreedomConfig::load_from_default_path_or_default()?;
    let autonomy_policy = config.autonomy_policy();
    let mut client = McpClient::spawn(cfg).await?;
    let now_unix = crate::time::now_unix_i64();
    // `neoth mcp call` is an explicit operator one-shot — no SmartApprove
    // (the operator is invoking the tool deliberately), so pass `None`.
    let result = match invoke_with_audit(
        &mut client,
        cfg,
        tool,
        args,
        &autonomy_policy,
        None,
        None,
        None,
        now_unix,
        // GOLD-ADAPT-AWE-CODE-01 — CLI one-shot: no inbound identity.
        None,
    )
    .await
    {
        Ok(r) => r,
        Err(GateError::NotInAllowlist { .. }) => {
            anyhow::bail!(
                "MCP `{server_id}::{tool}` blocked by per-server allow_tools allowlist. \
                 Edit ~/.neoth/mcp_servers.yaml to allow it, or pick a listed tool."
            );
        }
        Err(GateError::MissingAllowlistSecureDefault { .. }) => {
            // Reviewer-1 P1-A secure-by-default (2026-05-20): server
            // has neither an allow_tools list nor `trust_all_tools:
            // true`. Operator must opt in explicitly — silent
            // catalogue-trust is the very behaviour we removed.
            anyhow::bail!(
                "MCP `{server_id}::{tool}` denied: secure-by-default requires either \
                     an `allow_tools` pin or `trust_all_tools: true` for this server. \
                     Edit ~/.neoth/mcp_servers.yaml."
            );
        }
        Err(GateError::PermissionDenied { reason, .. }) => {
            anyhow::bail!(
                "MCP `{server_id}::{tool}` denied by autonomy policy ({}): {reason}",
                autonomy_policy.level().as_str()
            );
        }
        Err(GateError::AutonomyGate {
            required, current, ..
        }) => {
            anyhow::bail!(
                "MCP `{server_id}::{tool}` denied: this server requires autonomy ≥ {} \
                 (current {}). Raise autonomy via `neoth init`, or clear the server's \
                 `autonomy_gate` in ~/.neoth/mcp_servers.yaml.",
                required.as_str(),
                current.as_str()
            );
        }
        Err(GateError::ConfirmRequired { reason, .. }) => {
            anyhow::bail!(
                "MCP `{server_id}::{tool}` requires operator confirm ({}): {reason}. \
                 Lower autonomy via `neoth init` or extend allow_tools.",
                autonomy_policy.level().as_str()
            );
        }
        // SC-11 — `neoth mcp call` invokes a tool directly (no skill
        // context), so `invoke_with_audit` never produces this; the
        // arm exists only to keep the match exhaustive after the
        // variant was added for the skill-scoped dispatch path.
        Err(GateError::SkillAllowlistBlocked { .. }) => {
            anyhow::bail!("MCP `{server_id}::{tool}` blocked by an active skill's tool_allowlist");
        }
        // GOLD-CCPARITY-SA-DENY-01 — `neoth mcp call` has no sub-agent
        // context, so this variant is unreachable here; arm keeps the
        // match exhaustive after the variant was added for the
        // sub-agent dispatch path.
        Err(GateError::AgentDenylistBlocked { .. }) => {
            anyhow::bail!(
                "MCP `{server_id}::{tool}` blocked by sub-agent disallowedTools denylist"
            );
        }
        Err(GateError::Mcp(e)) => return Err(e.into()),
        Err(GateError::Wal(e)) => return Err(e),
    };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Table => {
            println!("# {server_id} :: {tool}");
            println!("  is_error: {}", result.is_error);
            for (i, c) in result.content.iter().enumerate() {
                println!("  content[{i}]: {c:?}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::McpServerConfig;
    use std::collections::HashMap;

    #[test]
    fn built_in_codegraph_registration_is_hardened_and_complete() {
        let config = codegraph_server_config(std::path::Path::new("neothd"), None);
        assert_eq!(config.id, "neoth-codegraph");
        assert_eq!(config.command, "neothd");
        assert_eq!(config.args, ["mcp", "codegraph-serve"]);
        assert_eq!(
            config.allow_tools.as_deref().unwrap(),
            crate::mcp::codegraph_server::TOOL_NAMES
        );
        assert!(!config.trust_all_tools);
        assert!(
            config.smart_approve,
            "built-in tools declare read-only effects"
        );
        config.validate_launcher().unwrap();
    }

    #[test]
    fn built_in_codegraph_registration_threads_db_override_as_one_arg() {
        let db = std::path::PathBuf::from("relative-code-map.db");
        let config = codegraph_server_config(std::path::Path::new("neothd"), Some(db));
        assert_eq!(
            config.args,
            ["mcp", "codegraph-serve", "--db", "relative-code-map.db"]
        );
    }

    #[test]
    fn run_list_renders_empty_state_cleanly() {
        let s = McpServers::default();
        run_list(&s, &OutputFormat::Json).unwrap();
        run_list(&s, &OutputFormat::Table).unwrap();
    }

    #[test]
    fn run_list_renders_with_entries() {
        let s = McpServers {
            smart_loading: true,
            servers: vec![McpServerConfig {
                id: "filesystem".into(),
                description: Some("local fs server".into()),
                command: "npx".into(),
                args: vec![
                    "-y".into(),
                    "@modelcontextprotocol/server-filesystem@1.0.0".into(),
                ],
                env: HashMap::new(),
                enabled: true,
                allow_tools: None,
                trust_all_tools: false,
                smart_approve: false,
                autonomy_gate: None,
            }],
        };
        run_list(&s, &OutputFormat::Json).unwrap();
        run_list(&s, &OutputFormat::Table).unwrap();
        assert!(s.servers[0].validate_launcher().is_ok());
    }

    #[test]
    fn list_surfaces_invalid_launcher_without_spawning_it() {
        let s = McpServers {
            smart_loading: true,
            servers: vec![McpServerConfig {
                id: "drifting".into(),
                description: None,
                command: "npx".into(),
                args: vec!["-y".into(), "example@latest".into()],
                env: HashMap::new(),
                enabled: false,
                allow_tools: Some(vec!["read".into()]),
                trust_all_tools: false,
                smart_approve: false,
                autonomy_gate: None,
            }],
        };
        assert!(s.servers[0].validate_launcher().is_err());
        run_list(&s, &OutputFormat::Json).unwrap();
        run_list(&s, &OutputFormat::Table).unwrap();
    }

    #[tokio::test]
    async fn run_tools_errors_on_unknown_server_with_actionable_message() {
        let s = McpServers::default();
        let err = run_tools(&s, "ghost", &OutputFormat::Json)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[tokio::test]
    async fn run_call_errors_on_bad_args_json() {
        let s = McpServers {
            smart_loading: true,
            servers: vec![McpServerConfig {
                id: "test".into(),
                description: None,
                command: "true".into(),
                args: vec![],
                env: HashMap::new(),
                enabled: true,
                allow_tools: None,
                trust_all_tools: false,
                smart_approve: false,
                autonomy_gate: None,
            }],
        };
        let err = run_call(&s, "test", "echo", "this is not json", &OutputFormat::Json)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not valid JSON"));
    }
}
