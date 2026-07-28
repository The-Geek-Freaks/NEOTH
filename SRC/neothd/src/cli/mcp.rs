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

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::mcp::{
    GateError, McpClient, McpError, McpServers, ToolCallResult, list_tools_sanitized,
};

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
    /// Serve NEOTH's seven read-only codegraph tools over MCP stdio. Intended as
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
    let executable = std::env::current_exe()?.canonicalize()?;
    let desired = codegraph_server_config(&executable, db);
    desired.validate_launcher()?;
    let path = McpServers::default_path();
    let rendered = install_codegraph_server_at(&path, &desired, output)?;
    println!("{rendered}");
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodegraphRegistrationOutcome {
    Created,
    RepairedLegacy,
    AlreadyCurrent,
    Conflict,
}

impl CodegraphRegistrationOutcome {
    fn changed(self) -> bool {
        matches!(self, Self::Created | Self::RepairedLegacy)
    }

    fn status(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::RepairedLegacy => "repaired_legacy",
            Self::AlreadyCurrent => "already_current",
            Self::Conflict => "conflict",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodegraphPostStateKind {
    ExactGenerated,
    RecognizedCustom,
    Disabled,
    Noncanonical,
}

impl CodegraphPostStateKind {
    fn status(self) -> &'static str {
        match self {
            Self::ExactGenerated => "exact_generated",
            Self::RecognizedCustom => "recognized_custom",
            Self::Disabled => "disabled",
            Self::Noncanonical => "noncanonical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodegraphDbSelection<'a> {
    Default,
    Explicit(&'a str),
}

impl<'a> CodegraphDbSelection<'a> {
    fn path(self) -> Option<&'a str> {
        match self {
            Self::Default => None,
            Self::Explicit(path) => Some(path),
        }
    }
}

#[derive(Debug)]
struct CodegraphPostState {
    kind: CodegraphPostStateKind,
    installed: bool,
    read_only_verified: bool,
    launcher_valid: bool,
    launcher_posture: Option<&'static str>,
    launcher_error: Option<String>,
    invocation_valid: bool,
    db_path: Option<String>,
    db_matches_requested: bool,
    command_verified: bool,
    security_hardened: bool,
    exact_tool_allowlist: bool,
    tool_count: usize,
    expected_tool_count: usize,
}

fn install_codegraph_server_at(
    path: &std::path::Path,
    desired: &crate::mcp::McpServerConfig,
    output: &OutputFormat,
) -> Result<String> {
    let mut outcome = None;
    McpServers::update_at(path, |servers| {
        let registration = upsert_codegraph_server(servers, desired);
        outcome = Some(registration);
        if registration == CodegraphRegistrationOutcome::Conflict {
            bail!(
                "MCP server id {:?} is already owned by an unrecognized configuration; \
                 refusing to overwrite it",
                desired.id
            );
        }
        Ok(registration.changed())
    })?;
    let outcome = outcome.context("codegraph registration mutation did not run")?;
    let persisted = McpServers::load_from(path)
        .with_context(|| format!("verify codegraph registration at {}", path.display()))?;
    let actual = persisted
        .servers
        .iter()
        .find(|server| server.id == desired.id)
        .with_context(|| {
            format!(
                "codegraph registration {:?} disappeared before post-state verification",
                desired.id
            )
        })?;
    let post_state = inspect_codegraph_post_state(actual, desired);
    render_codegraph_install(outcome, actual, &post_state, path, output)
}

fn inspect_codegraph_post_state(
    actual: &crate::mcp::McpServerConfig,
    desired: &crate::mcp::McpServerConfig,
) -> CodegraphPostState {
    let (launcher_valid, launcher_posture, launcher_error) = match actual.validate_launcher() {
        Ok(posture) => (true, Some(posture.as_str()), None),
        Err(error) => (false, None, Some(error.to_string())),
    };
    let actual_invocation = parse_codegraph_invocation(&actual.args);
    let desired_invocation = parse_codegraph_invocation(&desired.args);
    let exact_tool_allowlist = has_exact_codegraph_allowlist(actual);
    let tool_count = actual.allow_tools.as_ref().map_or(0, Vec::len);
    let expected_tool_count = crate::mcp::codegraph_server::TOOL_NAMES.len();
    let command_verified = actual.command == desired.command && actual.env.is_empty();
    let security_hardened = !actual.trust_all_tools && exact_tool_allowlist;
    let invocation_valid = actual_invocation.is_some();
    let read_only_verified = actual.enabled
        && launcher_valid
        && invocation_valid
        && command_verified
        && security_hardened;
    let kind = if !actual.enabled {
        CodegraphPostStateKind::Disabled
    } else if actual == desired && read_only_verified {
        CodegraphPostStateKind::ExactGenerated
    } else if launcher_valid && invocation_valid && security_hardened {
        CodegraphPostStateKind::RecognizedCustom
    } else {
        CodegraphPostStateKind::Noncanonical
    };

    CodegraphPostState {
        kind,
        installed: read_only_verified,
        read_only_verified,
        launcher_valid,
        launcher_posture,
        launcher_error,
        invocation_valid,
        db_path: actual_invocation
            .and_then(CodegraphDbSelection::path)
            .map(str::to_string),
        db_matches_requested: actual_invocation.is_some()
            && actual_invocation == desired_invocation,
        command_verified,
        security_hardened,
        exact_tool_allowlist,
        tool_count,
        expected_tool_count,
    }
}

fn parse_codegraph_invocation(args: &[String]) -> Option<CodegraphDbSelection<'_>> {
    match args {
        [mcp, serve] if mcp == "mcp" && serve == "codegraph-serve" => {
            Some(CodegraphDbSelection::Default)
        }
        [mcp, serve, db_flag, db]
            if mcp == "mcp"
                && serve == "codegraph-serve"
                && db_flag == "--db"
                && !db.is_empty()
                && !db.contains('\0') =>
        {
            Some(CodegraphDbSelection::Explicit(db))
        }
        _ => None,
    }
}

fn has_exact_codegraph_allowlist(server: &crate::mcp::McpServerConfig) -> bool {
    server.allow_tools.as_ref().is_some_and(|tools| {
        tools.len() == crate::mcp::codegraph_server::TOOL_NAMES.len()
            && crate::mcp::codegraph_server::TOOL_NAMES
                .iter()
                .all(|required| tools.iter().any(|tool| tool == required))
    })
}

fn render_codegraph_install(
    outcome: CodegraphRegistrationOutcome,
    actual: &crate::mcp::McpServerConfig,
    post_state: &CodegraphPostState,
    path: &std::path::Path,
    output: &OutputFormat,
) -> Result<String> {
    match output {
        OutputFormat::Json => serde_json::to_string_pretty(&serde_json::json!({
            "installed": post_state.installed,
            "read_only_verified": post_state.read_only_verified,
            "changed": outcome.changed(),
            "status": post_state.kind.status(),
            "mutation": outcome.status(),
            "id": actual.id,
            "config": path,
            "command": actual.command,
            "args": actual.args,
            "enabled": actual.enabled,
            "allow_tools": actual.allow_tools,
            "tool_count": post_state.tool_count,
            "expected_tool_count": post_state.expected_tool_count,
            "exact_tool_allowlist": post_state.exact_tool_allowlist,
            "security_hardened": post_state.security_hardened,
            "command_verified": post_state.command_verified,
            "invocation_valid": post_state.invocation_valid,
            "db": post_state.db_path,
            "db_matches_requested": post_state.db_matches_requested,
            "launcher": {
                "valid": post_state.launcher_valid,
                "posture": post_state.launcher_posture,
                "error": post_state.launcher_error,
            },
        }))
        .context("serialize codegraph install result"),
        OutputFormat::Jsonl => serde_json::to_string(&serde_json::json!({
            "installed": post_state.installed,
            "read_only_verified": post_state.read_only_verified,
            "changed": outcome.changed(),
            "status": post_state.kind.status(),
            "mutation": outcome.status(),
            "id": actual.id,
            "config": path,
            "command": actual.command,
            "args": actual.args,
            "enabled": actual.enabled,
            "allow_tools": actual.allow_tools,
            "tool_count": post_state.tool_count,
            "expected_tool_count": post_state.expected_tool_count,
            "exact_tool_allowlist": post_state.exact_tool_allowlist,
            "security_hardened": post_state.security_hardened,
            "command_verified": post_state.command_verified,
            "invocation_valid": post_state.invocation_valid,
            "db": post_state.db_path,
            "db_matches_requested": post_state.db_matches_requested,
            "launcher": {
                "valid": post_state.launcher_valid,
                "posture": post_state.launcher_posture,
                "error": post_state.launcher_error,
            },
        }))
        .context("serialize codegraph install JSONL result"),
        OutputFormat::Table => Ok(format!(
            "`{}` in {}: mutation={}, post_state={}, installed={}, \
             read_only_verified={}, tools={}/{}, launcher_valid={}, \
             command_verified={}, db={}",
            actual.id,
            path.display(),
            outcome.status(),
            post_state.kind.status(),
            post_state.installed,
            post_state.read_only_verified,
            post_state.tool_count,
            post_state.expected_tool_count,
            post_state.launcher_valid,
            post_state.command_verified,
            post_state.db_path.as_deref().unwrap_or("<default>"),
        )),
    }
}

fn upsert_codegraph_server(
    servers: &mut McpServers,
    desired: &crate::mcp::McpServerConfig,
) -> CodegraphRegistrationOutcome {
    match servers
        .servers
        .iter_mut()
        .find(|server| server.id == desired.id)
    {
        Some(existing) if &*existing == desired => CodegraphRegistrationOutcome::AlreadyCurrent,
        Some(existing) if repair_legacy_codegraph_allowlist(existing) => {
            CodegraphRegistrationOutcome::RepairedLegacy
        }
        Some(existing) if is_ready_codegraph_registration(existing) => {
            CodegraphRegistrationOutcome::AlreadyCurrent
        }
        Some(_) => CodegraphRegistrationOutcome::Conflict,
        None => {
            servers.servers.push(desired.clone());
            CodegraphRegistrationOutcome::Created
        }
    }
}

fn is_ready_codegraph_registration(server: &crate::mcp::McpServerConfig) -> bool {
    server.args.first().map(String::as_str) == Some("mcp")
        && server.args.get(1).map(String::as_str) == Some("codegraph-serve")
        && server.allow_tools.as_ref().is_some_and(|tools| {
            crate::mcp::codegraph_server::TOOL_NAMES
                .iter()
                .all(|required| tools.iter().any(|tool| tool == required))
        })
}

fn repair_legacy_codegraph_allowlist(existing: &mut crate::mcp::McpServerConfig) -> bool {
    const IMPACT_TOOL: &str = "codegraph_impact_radius";

    // Only registrations that still launch NEOTH's codegraph subcommand and
    // expose every member of the former six-tool catalogue are recognizable as
    // legacy built-ins. Everything else may be an operator-owned server that
    // merely reused the ID and must not be rewritten.
    if existing.args.first().map(String::as_str) != Some("mcp")
        || existing.args.get(1).map(String::as_str) != Some("codegraph-serve")
    {
        return false;
    }
    let Some(tools) = existing.allow_tools.as_mut() else {
        return false;
    };
    if tools.iter().any(|tool| tool == IMPACT_TOOL) {
        return false;
    }
    let has_legacy_catalogue = crate::mcp::codegraph_server::TOOL_NAMES
        .iter()
        .filter(|tool| **tool != IMPACT_TOOL)
        .all(|required| tools.iter().any(|tool| tool == required));
    if !has_legacy_catalogue {
        return false;
    }

    // Preserve custom tools and their order. Inserting immediately before the
    // old outline entry reproduces the canonical seven-tool order for an exact
    // legacy registration without touching command/env/db/security settings.
    let insertion = tools
        .iter()
        .position(|tool| tool == "codegraph_outline")
        .unwrap_or(tools.len());
    tools.insert(insertion, IMPACT_TOOL.to_string());
    true
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
    let now_unix = crate::time::now_unix_i64();
    // `neoth mcp call` is an explicit operator one-shot — no SmartApprove
    // (the operator is invoking the tool deliberately). Static policy and
    // confirmation resolution happen before the spawn closure is touched.
    let result = match invoke_cli_call_with_spawner(
        cfg,
        tool,
        args,
        autonomy_policy.clone(),
        now_unix,
        |config| async move { McpClient::spawn(&config).await },
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
        // context), so the CLI authorization path never produces this; the
        // arm exists only to keep the match exhaustive after the
        // variant was added for the skill-scoped dispatch path.
        Err(GateError::SkillAllowlistBlocked { .. }) => {
            anyhow::bail!("MCP `{server_id}::{tool}` blocked by an active skill's tool_allowlist");
        }
        // GOLD-CCPARITY-SA-ALLOW-01 — the direct CLI call has no
        // sub-agent context, so this is unreachable here. Keep the
        // fail-closed diagnostic explicit when the gate grows a new
        // agent-scoped allowlist outcome.
        Err(GateError::AgentAllowlistBlocked { .. }) => {
            anyhow::bail!("MCP `{server_id}::{tool}` blocked by sub-agent allowedTools allowlist");
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
    verify_tool_call_succeeded(&result, server_id, tool)?;
    Ok(())
}

/// MCP encodes tool-level failures in a successful JSON-RPC response. Keep the
/// structured result on stdout for automation, but make the process exit
/// non-zero so GUI and shell callers cannot mistake `isError: true` for a
/// successful tool effect.
fn verify_tool_call_succeeded(result: &ToolCallResult, server_id: &str, tool: &str) -> Result<()> {
    if result.is_error {
        anyhow::bail!("MCP `{server_id}::{tool}` reported a tool execution failure");
    }
    Ok(())
}

/// CLI one-shot MCP dispatch with the process-start boundary injected for a
/// regression-testable ordering contract. All static and Confirm policy paths
/// resolve before `spawn` is invoked; the opaque authorization proof is then
/// consumed by the exact configured call.
async fn invoke_cli_call_with_spawner<F, Fut>(
    cfg: &crate::mcp::McpServerConfig,
    tool: &str,
    arguments: serde_json::Value,
    policy: crate::permissions::AutonomyPolicySnapshot,
    now_unix: i64,
    spawn: F,
) -> Result<ToolCallResult, GateError>
where
    F: FnOnce(crate::mcp::McpServerConfig) -> Fut,
    Fut: std::future::Future<Output = Result<McpClient, McpError>>,
{
    let preflight =
        crate::mcp::gate::preflight_with_audit(cfg, tool, &policy, None, now_unix).await?;
    let instance_home = crate::config::FreedomConfig::default_neoth_home();
    let authorized = crate::mcp::gate::authorize_preflight_with_audit(
        preflight,
        cfg,
        tool,
        None,
        None,
        now_unix,
        // GOLD-ADAPT-AWE-CODE-01 — CLI one-shot has no inbound identity.
        None,
        &instance_home,
    )
    .await?;
    let mut client = spawn(cfg.clone()).await?;
    crate::mcp::gate::invoke_authorized_with_audit(
        &mut client,
        cfg,
        tool,
        arguments,
        authorized,
        None,
        None,
        now_unix,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::McpServerConfig;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn callable_server() -> McpServerConfig {
        McpServerConfig {
            id: "test".into(),
            description: None,
            command: "must-not-spawn".into(),
            args: vec![],
            env: HashMap::new(),
            enabled: true,
            allow_tools: Some(vec!["read".into()]),
            trust_all_tools: false,
            smart_approve: false,
            autonomy_gate: None,
        }
    }

    async fn rejected_cli_call_spawn_attempts(
        config: &McpServerConfig,
        tool: &str,
        policy: crate::permissions::AutonomyPolicySnapshot,
    ) -> (GateError, usize) {
        let attempts = Arc::new(AtomicUsize::new(0));
        let spawn_attempts = Arc::clone(&attempts);
        let error = invoke_cli_call_with_spawner(
            config,
            tool,
            serde_json::json!({}),
            policy,
            1_700_000_000,
            move |_| {
                spawn_attempts.fetch_add(1, Ordering::SeqCst);
                async { panic!("rejected CLI MCP call reached process spawn") }
            },
        )
        .await
        .expect_err("policy rejection must fail before spawn");
        (error, attempts.load(Ordering::SeqCst))
    }

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
    fn codegraph_registration_repairs_the_previous_exact_six_tool_allowlist() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut previous = desired.clone();
        previous.allow_tools = Some(
            crate::mcp::codegraph_server::TOOL_NAMES
                .iter()
                .filter(|name| **name != "codegraph_impact_radius")
                .map(|name| (*name).to_string())
                .collect(),
        );
        assert_eq!(previous.allow_tools.as_ref().unwrap().len(), 6);
        let mut servers = McpServers {
            smart_loading: true,
            servers: vec![previous],
        };

        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::RepairedLegacy,
            "an installed six-tool registration must be rewritten"
        );
        assert_eq!(servers.servers.len(), 1);
        assert_eq!(
            servers.servers[0].allow_tools.as_deref().unwrap(),
            crate::mcp::codegraph_server::TOOL_NAMES
        );
        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::AlreadyCurrent,
            "the repaired seven-tool registration must be idempotent"
        );
    }

    #[test]
    fn codegraph_registration_adds_seventh_tool_without_clobbering_custom_settings() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut customized = desired.clone();
        customized.description = Some("operator-owned description".into());
        customized.command = "C:/custom/neoth-wrapper.exe".into();
        customized.args = vec![
            "mcp".into(),
            "codegraph-serve".into(),
            "--db".into(),
            "D:/custom/code-map.db".into(),
        ];
        customized
            .env
            .insert("NEOTH_CUSTOM".into(), "preserve-me".into());
        customized.enabled = false;
        customized.trust_all_tools = true;
        customized.smart_approve = false;
        customized.autonomy_gate = Some(crate::permissions::AutonomyLevel::Elevated);
        customized.allow_tools = Some(
            crate::mcp::codegraph_server::TOOL_NAMES
                .iter()
                .filter(|name| **name != "codegraph_impact_radius")
                .map(|name| (*name).to_string())
                .chain(std::iter::once("operator_custom_tool".into()))
                .collect(),
        );
        let before = customized.clone();
        let mut servers = McpServers {
            smart_loading: true,
            servers: vec![customized],
        };

        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::RepairedLegacy
        );
        let repaired = &servers.servers[0];
        assert_eq!(repaired.description, before.description);
        assert_eq!(repaired.command, before.command);
        assert_eq!(repaired.args, before.args);
        assert_eq!(repaired.env, before.env);
        assert_eq!(repaired.enabled, before.enabled);
        assert_eq!(repaired.trust_all_tools, before.trust_all_tools);
        assert_eq!(repaired.smart_approve, before.smart_approve);
        assert_eq!(repaired.autonomy_gate, before.autonomy_gate);
        let tools = repaired.allow_tools.as_ref().unwrap();
        assert!(tools.iter().any(|tool| tool == "operator_custom_tool"));
        assert!(tools.iter().any(|tool| tool == "codegraph_impact_radius"));
        assert_eq!(tools.len(), before.allow_tools.as_ref().unwrap().len() + 1);
    }

    #[test]
    fn codegraph_registration_does_not_rewrite_unrecognized_same_id_server() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let custom = crate::mcp::McpServerConfig {
            id: "neoth-codegraph".into(),
            description: Some("different server".into()),
            command: "custom-server".into(),
            args: vec!["serve".into()],
            env: std::collections::HashMap::from([("TOKEN".into(), "from_env".into())]),
            enabled: false,
            allow_tools: Some(vec!["custom_tool".into()]),
            trust_all_tools: false,
            smart_approve: false,
            autonomy_gate: Some(crate::permissions::AutonomyLevel::Full),
        };
        let mut servers = McpServers {
            smart_loading: true,
            servers: vec![custom.clone()],
        };

        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::Conflict
        );
        assert_eq!(servers.servers, vec![custom]);
    }

    #[test]
    fn codegraph_install_reports_actual_post_state_in_json_and_table() {
        for output in [OutputFormat::Json, OutputFormat::Jsonl, OutputFormat::Table] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("mcp_servers.yaml");
            let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
            McpServers::update_at(&path, |servers| {
                servers.servers.push(desired.clone());
                Ok(true)
            })
            .unwrap();

            let rendered =
                install_codegraph_server_at(&path, &desired, &output).expect("post-state is ready");
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
                    assert_eq!(value["installed"], true);
                    assert_eq!(value["read_only_verified"], true);
                    assert_eq!(value["changed"], false);
                    assert_eq!(value["status"], "exact_generated");
                    assert_eq!(value["mutation"], "already_current");
                    assert_eq!(value["launcher"]["valid"], true);
                    assert_eq!(value["launcher"]["posture"], "direct_executable");
                    assert_eq!(value["command_verified"], true);
                    assert_eq!(value["invocation_valid"], true);
                    assert_eq!(value["db"], serde_json::Value::Null);
                    assert_eq!(value["db_matches_requested"], true);
                    assert_eq!(value["security_hardened"], true);
                    assert_eq!(value["exact_tool_allowlist"], true);
                    assert_eq!(
                        value["tool_count"].as_u64(),
                        Some(crate::mcp::codegraph_server::TOOL_NAMES.len() as u64)
                    );
                    assert_eq!(
                        value["expected_tool_count"].as_u64(),
                        Some(crate::mcp::codegraph_server::TOOL_NAMES.len() as u64)
                    );
                    assert_eq!(
                        value["allow_tools"].as_array().unwrap().len(),
                        crate::mcp::codegraph_server::TOOL_NAMES.len()
                    );
                }
                OutputFormat::Table => {
                    assert!(rendered.contains("mutation=already_current"));
                    assert!(rendered.contains("post_state=exact_generated"));
                    assert!(rendered.contains("installed=true"));
                    assert!(rendered.contains("read_only_verified=true"));
                    assert!(rendered.contains(&format!(
                        "tools={0}/{0}",
                        crate::mcp::codegraph_server::TOOL_NAMES.len()
                    )));
                }
            }
        }
    }

    #[test]
    fn codegraph_install_preserves_disabled_registration_without_install_claims() {
        for output in [OutputFormat::Json, OutputFormat::Table] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("mcp_servers.yaml");
            let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
            let mut disabled = desired.clone();
            disabled.enabled = false;
            McpServers::update_at(&path, |servers| {
                servers.servers.push(disabled.clone());
                Ok(true)
            })
            .unwrap();

            let rendered = install_codegraph_server_at(&path, &desired, &output).unwrap();
            match output {
                OutputFormat::Json => {
                    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
                    assert_eq!(value["status"], "disabled");
                    assert_eq!(value["mutation"], "already_current");
                    assert_eq!(value["installed"], false);
                    assert_eq!(value["read_only_verified"], false);
                    assert_eq!(value["enabled"], false);
                    assert_eq!(value["launcher"]["valid"], true);
                    assert_eq!(value["command_verified"], true);
                    assert_eq!(value["security_hardened"], true);
                    assert_eq!(value["exact_tool_allowlist"], true);
                }
                OutputFormat::Table => {
                    assert!(rendered.contains("post_state=disabled"));
                    assert!(rendered.contains("installed=false"));
                    assert!(rendered.contains("read_only_verified=false"));
                }
                OutputFormat::Jsonl => unreachable!(),
            }
            assert_eq!(
                McpServers::load_from(&path).unwrap().servers,
                vec![disabled]
            );
        }
    }

    #[test]
    fn codegraph_install_reports_custom_db_and_unverified_command_truthfully() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);

        let db_dir = tempfile::tempdir().unwrap();
        let db_config_path = db_dir.path().join("mcp_servers.yaml");
        let mut custom_db = desired.clone();
        custom_db.args = vec![
            "mcp".into(),
            "codegraph-serve".into(),
            "--db".into(),
            "D:/operator/code-map.db".into(),
        ];
        McpServers::update_at(&db_config_path, |servers| {
            servers.servers.push(custom_db.clone());
            Ok(true)
        })
        .unwrap();
        let db_rendered =
            install_codegraph_server_at(&db_config_path, &desired, &OutputFormat::Json).unwrap();
        let db_value: serde_json::Value = serde_json::from_str(&db_rendered).unwrap();
        assert_eq!(db_value["status"], "recognized_custom");
        assert_eq!(db_value["mutation"], "already_current");
        assert_eq!(db_value["installed"], true);
        assert_eq!(db_value["read_only_verified"], true);
        assert_eq!(db_value["db"], "D:/operator/code-map.db");
        assert_eq!(db_value["db_matches_requested"], false);
        assert_eq!(db_value["command_verified"], true);
        assert_eq!(
            McpServers::load_from(&db_config_path).unwrap().servers,
            vec![custom_db]
        );

        let command_dir = tempfile::tempdir().unwrap();
        let command_config_path = command_dir.path().join("mcp_servers.yaml");
        let mut custom_command = desired.clone();
        custom_command.command = "operator-codegraph".into();
        McpServers::update_at(&command_config_path, |servers| {
            servers.servers.push(custom_command.clone());
            Ok(true)
        })
        .unwrap();
        let command_rendered =
            install_codegraph_server_at(&command_config_path, &desired, &OutputFormat::Json)
                .unwrap();
        let command_value: serde_json::Value = serde_json::from_str(&command_rendered).unwrap();
        assert_eq!(command_value["status"], "recognized_custom");
        assert_eq!(command_value["installed"], false);
        assert_eq!(command_value["read_only_verified"], false);
        assert_eq!(command_value["launcher"]["valid"], true);
        assert_eq!(command_value["command_verified"], false);
        assert_eq!(command_value["db_matches_requested"], true);
        assert_eq!(
            McpServers::load_from(&command_config_path).unwrap().servers,
            vec![custom_command]
        );
    }

    #[test]
    fn codegraph_install_marks_invalid_launcher_security_and_tool_count_noncanonical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_servers.yaml");
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut noncanonical = desired.clone();
        noncanonical.command = "powershell".into();
        noncanonical.trust_all_tools = true;
        noncanonical
            .allow_tools
            .as_mut()
            .unwrap()
            .push("operator_unknown_tool".into());
        McpServers::update_at(&path, |servers| {
            servers.servers.push(noncanonical.clone());
            Ok(true)
        })
        .unwrap();

        let rendered = install_codegraph_server_at(&path, &desired, &OutputFormat::Json).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["status"], "noncanonical");
        assert_eq!(value["installed"], false);
        assert_eq!(value["read_only_verified"], false);
        assert_eq!(value["launcher"]["valid"], false);
        assert!(
            value["launcher"]["error"]
                .as_str()
                .unwrap()
                .contains("opaque")
        );
        assert_eq!(value["security_hardened"], false);
        assert_eq!(value["exact_tool_allowlist"], false);
        assert_eq!(
            value["tool_count"].as_u64(),
            Some((crate::mcp::codegraph_server::TOOL_NAMES.len() + 1) as u64)
        );
        assert_eq!(
            value["expected_tool_count"].as_u64(),
            Some(crate::mcp::codegraph_server::TOOL_NAMES.len() as u64)
        );
        assert_eq!(
            McpServers::load_from(&path).unwrap().servers,
            vec![noncanonical]
        );
    }

    #[test]
    fn codegraph_install_conflict_is_nonzero_and_preserves_custom_server() {
        for output in [OutputFormat::Json, OutputFormat::Table] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("mcp_servers.yaml");
            let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
            let custom = crate::mcp::McpServerConfig {
                id: desired.id.clone(),
                description: Some("operator-owned server".into()),
                command: "custom-server".into(),
                args: vec!["serve".into()],
                env: std::collections::HashMap::new(),
                enabled: true,
                allow_tools: Some(vec!["custom_tool".into()]),
                trust_all_tools: false,
                smart_approve: false,
                autonomy_gate: None,
            };
            McpServers::update_at(&path, |servers| {
                servers.servers.push(custom.clone());
                Ok(true)
            })
            .unwrap();

            let error = install_codegraph_server_at(&path, &desired, &output).unwrap_err();
            assert!(error.to_string().contains("already owned"));
            assert_eq!(McpServers::load_from(&path).unwrap().servers, vec![custom]);
        }
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

    #[test]
    fn tool_level_error_cannot_exit_successfully() {
        let result = ToolCallResult {
            content: Vec::new(),
            is_error: true,
        };
        let error = verify_tool_call_succeeded(&result, "filesystem", "write")
            .expect_err("MCP isError=true must produce a failing process result");
        assert!(error.to_string().contains("filesystem::write"));

        verify_tool_call_succeeded(&ToolCallResult::default(), "filesystem", "read")
            .expect("a successful MCP result must remain successful");
    }

    #[tokio::test]
    async fn cli_call_allowlist_rejection_never_starts_server() {
        let config = callable_server();
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Full,
        )
        .unwrap();
        let (error, attempts) = rejected_cli_call_spawn_attempts(&config, "write", policy).await;
        assert!(matches!(error, GateError::NotInAllowlist { .. }));
        assert_eq!(attempts, 0);
    }

    #[tokio::test]
    async fn cli_call_autonomy_rejection_never_starts_server() {
        let mut config = callable_server();
        config.autonomy_gate = Some(crate::permissions::AutonomyLevel::Elevated);
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Standard,
        )
        .unwrap();
        let (error, attempts) = rejected_cli_call_spawn_attempts(&config, "read", policy).await;
        assert!(matches!(error, GateError::AutonomyGate { .. }));
        assert_eq!(attempts, 0);
    }

    #[tokio::test]
    async fn cli_call_custom_deny_never_starts_server() {
        let config = callable_server();
        let custom = crate::permissions::CustomAutonomyConfig {
            overrides: std::collections::BTreeMap::from([(
                crate::permissions::ActionKind::McpToolInvocation,
                crate::permissions::CustomDecision::Deny,
            )]),
        };
        let policy = crate::permissions::AutonomyPolicySnapshot::new(
            crate::permissions::AutonomyLevel::Custom,
            &custom,
        );
        let (error, attempts) = rejected_cli_call_spawn_attempts(&config, "read", policy).await;
        assert!(matches!(error, GateError::PermissionDenied { .. }));
        assert_eq!(attempts, 0);
    }
}
