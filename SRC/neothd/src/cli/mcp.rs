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

use crate::cli::{OutputFormat, permission_audit::RequiredPermissionAudit};
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
    /// Serve NEOTH's nine read-only codegraph tools over MCP stdio. Intended as
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
        Some(existing) => {
            if &*existing == desired {
                CodegraphRegistrationOutcome::AlreadyCurrent
            } else if repair_legacy_codegraph_allowlist(existing, desired) {
                CodegraphRegistrationOutcome::RepairedLegacy
            } else if is_ready_codegraph_registration(existing, desired) {
                CodegraphRegistrationOutcome::AlreadyCurrent
            } else {
                CodegraphRegistrationOutcome::Conflict
            }
        }
        None => {
            servers.servers.push(desired.clone());
            CodegraphRegistrationOutcome::Created
        }
    }
}

fn is_ready_codegraph_registration(
    server: &crate::mcp::McpServerConfig,
    desired: &crate::mcp::McpServerConfig,
) -> bool {
    is_trusted_generated_codegraph_identity(server, desired)
        && server.allow_tools.as_ref().is_some_and(|tools| {
            tools.len() == crate::mcp::codegraph_server::TOOL_NAMES.len()
                && crate::mcp::codegraph_server::TOOL_NAMES
                    .iter()
                    .all(|required| {
                        tools
                            .iter()
                            .filter(|tool| tool.as_str() == *required)
                            .count()
                            == 1
                    })
        })
}

fn is_trusted_generated_codegraph_identity(
    server: &crate::mcp::McpServerConfig,
    desired: &crate::mcp::McpServerConfig,
) -> bool {
    crate::mcp::codegraph_server::is_trusted_generated_codegraph_identity(server, desired)
}
// These are complete historical built-in catalogues, kept independent of the
// evolving current `TOOL_NAMES`. A migration may add later built-ins only when
// the persisted codegraph subset exactly matches one of these releases.
const LEGACY_CODEGRAPH_V6_TOOLS: &[&str] = &[
    "codegraph_relevant_files",
    "codegraph_extract_identifiers",
    "codegraph_path_keywords",
    "codegraph_callers",
    "codegraph_callees",
    "codegraph_outline",
];

const LEGACY_CODEGRAPH_V7_TOOLS: &[&str] = &[
    "codegraph_relevant_files",
    "codegraph_extract_identifiers",
    "codegraph_path_keywords",
    "codegraph_callers",
    "codegraph_callees",
    "codegraph_impact_radius",
    "codegraph_outline",
];

const LEGACY_CODEGRAPH_V8_TOOLS: &[&str] = &[
    "codegraph_relevant_files",
    "codegraph_recall_v1",
    "codegraph_extract_identifiers",
    "codegraph_path_keywords",
    "codegraph_callers",
    "codegraph_callees",
    "codegraph_impact_radius",
    "codegraph_outline",
];

const LEGACY_CODEGRAPH_V9_TOOLS: &[&str] = &[
    "codegraph_relevant_files",
    "codegraph_recall_v1",
    "codegraph_extract_identifiers",
    "codegraph_path_keywords",
    "codegraph_callers",
    "codegraph_callees",
    "codegraph_impact_radius",
    "codegraph_diff_impact",
    "codegraph_outline",
];

fn is_exact_legacy_codegraph_catalogue(tools: &[String]) -> bool {
    [
        LEGACY_CODEGRAPH_V6_TOOLS,
        LEGACY_CODEGRAPH_V7_TOOLS,
        LEGACY_CODEGRAPH_V8_TOOLS,
        LEGACY_CODEGRAPH_V9_TOOLS,
    ]
    .iter()
    .any(|catalogue| {
        let codegraph_count = tools
            .iter()
            .filter(|tool| tool.starts_with("codegraph_"))
            .count();
        codegraph_count == catalogue.len()
            && catalogue.iter().all(|required| {
                tools
                    .iter()
                    .filter(|tool| tool.as_str() == *required)
                    .count()
                    == 1
            })
    })
}

fn repair_legacy_codegraph_allowlist(
    existing: &mut crate::mcp::McpServerConfig,
    desired: &crate::mcp::McpServerConfig,
) -> bool {
    // A historic tool catalogue is not a sufficient ownership proof: an
    // operator-owned or malicious lookalike might reuse it. Only the exact
    // generated launcher/invocation with the secure built-in gates can be
    // upgraded automatically. All other registrations remain untouched and
    // force the caller to report Conflict.
    if !is_trusted_generated_codegraph_identity(existing, desired) {
        return false;
    }
    let Some(tools) = existing.allow_tools.as_mut() else {
        return false;
    };
    if !is_exact_legacy_codegraph_catalogue(tools) {
        return false;
    }

    // Rebuild the built-in portion in the current canonical order so a v6 or
    // v7 or v8 registration receives every current tool. Preserve only
    // non-codegraph operator extras in their original order; an unrecognized
    // `codegraph_*` entry never qualifies as a trusted historical catalogue.
    let custom_tools = std::mem::take(tools)
        .into_iter()
        .filter(|tool| !tool.starts_with("codegraph_"))
        .collect::<Vec<_>>();
    tools.extend(
        crate::mcp::codegraph_server::TOOL_NAMES
            .iter()
            .map(|tool| (*tool).to_string()),
    );
    tools.extend(custom_tools);
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

    // ADOPT31-C4 — fingerprint every declared tool against its pin. This is the
    // operator-facing surface, so a violation is REPORTED here rather than
    // silently dropping the row: the operator asked what the server declares,
    // and "it changed what it declares" is the most important possible answer.
    //
    // Pinning the post-sanitisation form is deliberate. The sanitiser rewrites
    // `description` and nested schema descriptions but never `annotations` —
    // and annotations are the auto-approval surface the rug-pull actually
    // targets, so the facet that matters is bound exactly. The cost is that a
    // future change to the sanitiser's own rules shifts these hashes and shows
    // up as violations on upgrade; that is visible and recoverable, whereas
    // pinning the raw form would have to re-derive what the sanitiser removed.
    let home = crate::config::FreedomConfig::default_neoth_home();
    let pin_report: Vec<(String, crate::security::mcp_guardian::PinVerdict)> =
        match crate::security::mcp_guardian::McpGuardian::open(&home) {
            Ok(mut guardian) => {
                let now = crate::time::now_unix_i64();
                let report: Vec<_> = tools
                    .iter()
                    .filter_map(|t| {
                        guardian
                            .check(server_id, &t.tool, now)
                            .map(|v| (t.tool.name.clone(), v))
                            .ok()
                    })
                    .collect();
                if let Err(error) = guardian.flush() {
                    tracing::warn!(error = %error, "could not persist MCP tool pins");
                }
                report
            }
            Err(error) => {
                // Fail loud, not closed: this command only *lists*. Refusing to
                // print would hide the server's declaration from the operator,
                // which is the opposite of what they asked for.
                tracing::warn!(error = %error, "MCP tool pin check unavailable");
                Vec::new()
            }
        };
    for (tool, verdict) in &pin_report {
        if let crate::security::mcp_guardian::PinVerdict::Violation { detail } = verdict {
            tracing::error!(server = %server_id, tool = %tool, "{detail}");
        }
    }

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
        Err(GateError::PreToolUseBlocked { .. })
        | Err(GateError::PreToolUseContext(_))
        | Err(GateError::PreToolUsePermitMismatch { .. }) => {
            anyhow::bail!("MCP `{server_id}::{tool}` blocked by PreToolUse authorization")
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
    let instance_home = crate::config::FreedomConfig::default_neoth_home();
    invoke_cli_call_with_spawner_at_home(
        cfg,
        tool,
        arguments,
        policy,
        now_unix,
        &instance_home,
        spawn,
    )
    .await
}

/// Explicit-home form of the production audit owner. Keeping this separate
/// from the default-home adapter lets regression tests exercise the real
/// daemon-or-standalone selection and bounded finalizer without mutating the
/// process environment.
async fn invoke_cli_call_with_spawner_at_home<F, Fut>(
    cfg: &crate::mcp::McpServerConfig,
    tool: &str,
    arguments: serde_json::Value,
    policy: crate::permissions::AutonomyPolicySnapshot,
    now_unix: i64,
    instance_home: &std::path::Path,
    spawn: F,
) -> Result<ToolCallResult, GateError>
where
    F: FnOnce(crate::mcp::McpServerConfig) -> Fut,
    Fut: std::future::Future<Output = Result<McpClient, McpError>>,
{
    let audit = RequiredPermissionAudit::open(instance_home, "mcp-call").map_err(GateError::Wal)?;
    let result = invoke_cli_call_with_spawner_and_audit_sink(
        cfg,
        tool,
        arguments,
        policy,
        now_unix,
        crate::mcp::gate::McpAuditSink::from_permission_sink(audit.sink()),
        instance_home,
        spawn,
    )
    .await;
    let finish = audit.finish().await.map_err(GateError::Wal);
    match (result, finish) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(result), Ok(())) => Ok(result),
    }
}

/// The audit-aware core is deliberately injectable: production obtains its
/// only sink from `RequiredPermissionAudit`, while tests exercise the exact
/// home-WAL boundary without provider network access.
#[allow(clippy::too_many_arguments)]
async fn invoke_cli_call_with_spawner_and_audit_sink<F, Fut>(
    cfg: &crate::mcp::McpServerConfig,
    tool: &str,
    arguments: serde_json::Value,
    policy: crate::permissions::AutonomyPolicySnapshot,
    now_unix: i64,
    sink: crate::mcp::gate::McpAuditSink<'_>,
    instance_home: &std::path::Path,
    spawn: F,
) -> Result<ToolCallResult, GateError>
where
    F: FnOnce(crate::mcp::McpServerConfig) -> Fut,
    Fut: std::future::Future<Output = Result<McpClient, McpError>>,
{
    let request_binding_sha256 = crate::mcp::gate::mcp_request_binding(cfg, tool, &arguments)?;
    let preflight = crate::mcp::gate::preflight_with_audit_sink(
        cfg,
        tool,
        &policy,
        sink,
        now_unix,
        Some(crate::permissions::trust_ledger::LOCAL_SUBJECT),
        Some(&request_binding_sha256),
    )
    .await?;
    let authorized = crate::mcp::gate::authorize_preflight_with_audit_sink(
        preflight,
        cfg,
        tool,
        sink,
        None,
        now_unix,
        Some(crate::permissions::trust_ledger::LOCAL_SUBJECT),
        instance_home,
    )
    .await?;
    // Direct `neoth mcp call` owns no chat cancellation token. It does load
    // the configured TOML set from the exact instance root, then runs the
    // same bounded typed boundary as provider-emitted calls.
    let hooks = crate::hooks::load_all_strict(&instance_home.join("hooks"))
        .await
        .map_err(|error| GateError::PreToolUseBlocked {
            server: cfg.id.clone(),
            tool: tool.to_owned(),
            reason: format!("cannot load configured PreToolUse hooks: {error}"),
        })?;
    let once_guard = crate::hooks::SessionOnceGuard::new();
    // One-shot CLI calls have no reload controller. Read one config snapshot
    // from the exact instance home; an unreadable optional file preserves legacy off.
    let outline_enrichment_enabled = crate::config::FreedomConfig::load_from_path_or_default(
        &instance_home.join("freedom.yaml"),
    )
    .map(|config| config.code_map.outline_enrichment)
    .unwrap_or(false);
    let pre_tool_use = crate::mcp::gate::admit_pre_tool_use_with_outline(
        crate::hooks::PreToolUseOrigin::DirectCliMcp,
        cfg,
        tool,
        &arguments,
        instance_home,
        &request_binding_sha256,
        crate::hooks::PreToolUseHookPolicy::Configured(&hooks),
        &once_guard,
        crate::hooks::PreToolUseCancellation::unbound(),
        crate::hooks::PreToolUseReplay::direct_request(),
        outline_enrichment_enabled,
    )?;
    let mut client = spawn(cfg.clone()).await?;
    crate::mcp::gate::invoke_authorized_with_audit_sink(
        &mut client,
        cfg,
        tool,
        arguments,
        authorized,
        sink,
        None,
        now_unix,
        Some(&request_binding_sha256),
        pre_tool_use,
    )
    .await
}

/// SHA-256 commitment to the exact operator request. Object keys are sorted
/// recursively before serialization, while arrays retain their semantic order.
/// The WAL receives this digest only, never the tool arguments themselves.
#[cfg(test)]
fn cli_mcp_request_binding(
    cfg: &crate::mcp::McpServerConfig,
    tool: &str,
    arguments: &serde_json::Value,
) -> Result<String, GateError> {
    crate::mcp::gate::mcp_request_binding(cfg, tool, arguments)
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

    fn home_audit_writer(
        home: &std::path::Path,
    ) -> (
        crate::wal::writer::WalWriterHandle,
        tokio::task::JoinHandle<()>,
    ) {
        let wal = home.join("wal");
        std::fs::create_dir_all(&wal).expect("create test home WAL directory");
        crate::wal::writer::spawn_for_home(wal.join("000001.wal"), home.to_path_buf())
            .expect("open authenticated test HOME-WAL writer")
    }

    async fn home_trust_entries(
        home: &std::path::Path,
        writer: crate::wal::writer::WalWriterHandle,
        join: tokio::task::JoinHandle<()>,
    ) -> Vec<crate::permissions::trust_ledger::TrustLedgerEntry> {
        drop(writer);
        join.await.expect("test HOME-WAL writer exits cleanly");
        let replay = crate::permissions::trust_ledger::TrustLedger::replay_subject_at_home(
            home,
            crate::permissions::trust_ledger::LOCAL_SUBJECT,
        )
        .expect("replay authenticated HOME-WAL trust ledger");
        assert!(matches!(
            replay.completeness,
            crate::permissions::trust_ledger::TrustLedgerCompleteness::Complete
        ));
        replay.entries
    }

    #[tokio::test]
    async fn cli_call_audits_one_bound_allow_before_the_spawn_boundary() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join) = home_audit_writer(home.path());
        let config = callable_server();
        let args = serde_json::json!({"nested": {"z": 1, "a": true}});
        let binding = cli_mcp_request_binding(&config, "read", &args).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&attempts);
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Full,
        )
        .unwrap();

        let error = invoke_cli_call_with_spawner_and_audit_sink(
            &config,
            "read",
            args,
            policy,
            1_700_000_000,
            crate::mcp::gate::McpAuditSink::Writer(&writer),
            home.path(),
            move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(McpError::Protocol(
                        "test".into(),
                        "stop after audited spawn boundary".into(),
                    ))
                }
            },
        )
        .await
        .expect_err("the injected spawn failure must surface after admission");
        assert!(matches!(error, GateError::Mcp(_)));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        let entries = home_trust_entries(home.path(), writer, join).await;
        assert_eq!(entries.len(), 1, "one final typed allow is durable");
        let event = &entries[0].event;
        assert_eq!(
            event.action,
            crate::permissions::ActionKind::McpToolInvocation
        );
        assert_eq!(
            event.outcome,
            crate::permissions::trust_ledger::TrustOutcome::Allowed
        );
        assert_eq!(
            event.request_binding_sha256.as_deref(),
            Some(binding.as_str())
        );
    }

    #[tokio::test]
    async fn configured_pre_tool_block_reaches_the_real_cli_spawner_seam_zero_times() {
        let home = tempfile::tempdir().expect("temporary instance home");
        let hooks_dir = home.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir).expect("hook directory");
        std::fs::write(
            hooks_dir.join("block.toml"),
            r#"
name = "deny-real-cli-call"
stage = "pre_tool_use"
[action]
kind = "block"
reason = "test block before external call"
"#,
        )
        .expect("configured hook");
        let config = callable_server();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&attempts);
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Full,
        )
        .unwrap();

        let error = invoke_cli_call_with_spawner_and_audit_sink(
            &config,
            "read",
            serde_json::json!({"exact": true}),
            policy,
            1_700_000_000,
            crate::mcp::gate::McpAuditSink::None,
            home.path(),
            move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                async { panic!("configured PreToolUse block reached the real CLI spawn seam") }
            },
        )
        .await
        .expect_err("configured block must stop the real CLI route");

        assert!(matches!(error, GateError::PreToolUseBlocked { .. }));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn real_cli_fixture_route_executes_exactly_one_tools_call() {
        let home = tempfile::tempdir().unwrap();
        let counter = home.path().join("tools-call-count.txt");
        let config = crate::mcp::client::stdio_fixture_config(&counter);
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Full,
        )
        .unwrap();
        let result = invoke_cli_call_with_spawner_and_audit_sink(
            &config,
            "read",
            serde_json::json!({"exact": "cli"}),
            policy,
            1,
            crate::mcp::gate::McpAuditSink::None,
            home.path(),
            |fixture| async move { McpClient::spawn(&fixture).await },
        )
        .await
        .expect("real CLI core uses fixture client");
        assert!(!result.is_error);
        assert_eq!(crate::mcp::client::stdio_fixture_call_count(&counter), 1);
    }

    #[tokio::test]
    async fn cli_call_production_wrapper_finalizes_owned_home_wal_after_audited_spawn() {
        let home = tempfile::tempdir().unwrap();
        let config = callable_server();
        let args = serde_json::json!({"nested": {"z": 1, "a": true}});
        let binding = cli_mcp_request_binding(&config, "read", &args).unwrap();
        let expected_binding = binding.clone();
        let spawn_home = home.path().to_path_buf();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&attempts);
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Full,
        )
        .unwrap();

        let error = invoke_cli_call_with_spawner_at_home(
            &config,
            "read",
            args,
            policy,
            1_700_000_000,
            home.path(),
            move |_| {
                let replay = crate::permissions::trust_ledger::TrustLedger::replay_subject_at_home(
                    &spawn_home,
                    crate::permissions::trust_ledger::LOCAL_SUBJECT,
                )
                .expect("the authenticated allow must be visible before spawn");
                assert_eq!(
                    replay.entries.len(),
                    1,
                    "exactly one typed decision precedes spawn"
                );
                let event = &replay.entries[0].event;
                assert_eq!(
                    event.action,
                    crate::permissions::ActionKind::McpToolInvocation
                );
                assert_eq!(
                    event.outcome,
                    crate::permissions::trust_ledger::TrustOutcome::Allowed
                );
                assert_eq!(
                    event.request_binding_sha256.as_deref(),
                    Some(expected_binding.as_str())
                );
                count.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(McpError::Protocol(
                        "test".into(),
                        "controlled audited spawn outcome".into(),
                    ))
                }
            },
        )
        .await
        .expect_err("the controlled spawn outcome must surface");

        assert!(matches!(error, GateError::Mcp(_)));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        let replay = crate::permissions::trust_ledger::TrustLedger::replay_subject_at_home(
            home.path(),
            crate::permissions::trust_ledger::LOCAL_SUBJECT,
        )
        .expect("production wrapper finalizer must leave a replayable HOME-WAL");
        assert!(matches!(
            replay.completeness,
            crate::permissions::trust_ledger::TrustLedgerCompleteness::Complete
        ));
        assert_eq!(replay.entries.len(), 1, "the owned session finalizes once");
        assert_eq!(
            replay.entries[0].event.request_binding_sha256.as_deref(),
            Some(binding.as_str())
        );
    }

    #[tokio::test]
    async fn cli_call_production_wrapper_live_daemon_rpc_failure_never_falls_back_or_spawns() {
        let home = tempfile::tempdir().unwrap();
        let _daemon_owner = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid"))
            .expect("hold a real live-daemon pidfile lock for this HOME");
        let selected = RequiredPermissionAudit::open(home.path(), "mcp-call")
            .expect("live daemon selection itself is local and fallible");
        assert!(matches!(
            selected.sink(),
            crate::permissions::PermissionAuditSink::DaemonRpc(_)
        ));
        selected
            .finish()
            .await
            .expect("daemon audit session has no standalone finalizer");

        let config = callable_server();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&attempts);
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Full,
        )
        .unwrap();
        let error = invoke_cli_call_with_spawner_at_home(
            &config,
            "read",
            serde_json::json!({}),
            policy,
            1_700_000_000,
            home.path(),
            move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                async { panic!("unavailable daemon audit RPC reached process spawn") }
            },
        )
        .await
        .expect_err("required daemon audit RPC failure must fail closed");

        assert!(matches!(&error, GateError::Wal(_)), "{error:#}");
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert!(
            !home.path().join("wal").exists(),
            "a live daemon selection must never fall back to an owned WAL writer"
        );
    }

    #[tokio::test]
    async fn cli_call_audits_one_bound_deny_and_never_spawns() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join) = home_audit_writer(home.path());
        let config = callable_server();
        let args = serde_json::json!({"path": "secret"});
        let binding = cli_mcp_request_binding(&config, "write", &args).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&attempts);
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Full,
        )
        .unwrap();

        let error = invoke_cli_call_with_spawner_and_audit_sink(
            &config,
            "write",
            args,
            policy,
            1_700_000_000,
            crate::mcp::gate::McpAuditSink::Writer(&writer),
            home.path(),
            move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                async { panic!("denied CLI MCP call reached process spawn") }
            },
        )
        .await
        .expect_err("allowlist deny is final before spawn");
        assert!(matches!(error, GateError::NotInAllowlist { .. }));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);

        let entries = home_trust_entries(home.path(), writer, join).await;
        assert_eq!(entries.len(), 1, "one final typed deny is durable");
        let event = &entries[0].event;
        assert_eq!(
            event.outcome,
            crate::permissions::trust_ledger::TrustOutcome::Denied
        );
        assert_eq!(
            event.request_binding_sha256.as_deref(),
            Some(binding.as_str())
        );
    }

    #[tokio::test]
    async fn cli_call_confirm_is_one_bound_deny_and_never_spawns() {
        let home = tempfile::tempdir().unwrap();
        let (writer, join) = home_audit_writer(home.path());
        let config = callable_server();
        let args = serde_json::json!({"path": "needs-operator-confirm"});
        let binding = cli_mcp_request_binding(&config, "read", &args).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&attempts);
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Standard,
        )
        .unwrap();

        let error = invoke_cli_call_with_spawner_and_audit_sink(
            &config,
            "read",
            args,
            policy,
            1_700_000_000,
            crate::mcp::gate::McpAuditSink::Writer(&writer),
            home.path(),
            move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                async { panic!("Confirm-gated CLI MCP call reached process spawn") }
            },
        )
        .await
        .expect_err("unleased confirmation must remain denied");
        assert!(matches!(error, GateError::ConfirmRequired { .. }));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);

        let entries = home_trust_entries(home.path(), writer, join).await;
        assert_eq!(entries.len(), 1, "Confirm produces one final typed deny");
        let event = &entries[0].event;
        assert_eq!(
            event.outcome,
            crate::permissions::trust_ledger::TrustOutcome::Denied
        );
        assert_eq!(
            event.request_binding_sha256.as_deref(),
            Some(binding.as_str())
        );
    }

    #[tokio::test]
    async fn failed_required_cli_audit_blocks_spawn() {
        let config = callable_server();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&attempts);
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Full,
        )
        .unwrap();
        let error = invoke_cli_call_with_spawner_and_audit_sink(
            &config,
            "read",
            serde_json::json!({}),
            policy,
            1_700_000_000,
            crate::mcp::gate::McpAuditSink::Fail("forced required audit failure"),
            std::path::Path::new("."),
            move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                async { panic!("audit failure reached process spawn") }
            },
        )
        .await
        .expect_err("required audit failure must fail closed");
        assert!(matches!(error, GateError::Wal(_)));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cli_mcp_request_binding_is_canonical_and_exact() {
        let config = callable_server();
        let reordered = serde_json::json!({"z": [2, 1], "a": {"y": true, "x": null}});
        let equivalent = serde_json::json!({"a": {"x": null, "y": true}, "z": [2, 1]});
        assert_eq!(
            cli_mcp_request_binding(&config, "read", &reordered).unwrap(),
            cli_mcp_request_binding(&config, "read", &equivalent).unwrap(),
        );
        assert_ne!(
            cli_mcp_request_binding(&config, "read", &reordered).unwrap(),
            cli_mcp_request_binding(&config, "read", &serde_json::json!({"z": [1, 2]})).unwrap(),
        );
        assert_ne!(
            cli_mcp_request_binding(&config, "read", &reordered).unwrap(),
            cli_mcp_request_binding(&config, "other", &reordered).unwrap(),
        );
    }

    #[test]
    fn built_in_codegraph_registration_is_hardened_and_complete() {
        let config = codegraph_server_config(std::path::Path::new("neothd"), None);
        assert_eq!(crate::mcp::codegraph_server::TOOL_NAMES.len(), 10);
        assert!(crate::mcp::codegraph_server::TOOL_NAMES.contains(&"codegraph_diff_test_gaps"));
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
    fn codegraph_registration_repairs_historic_v6_allowlist_to_current_nine_tools() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut previous = desired.clone();
        previous.allow_tools = Some(
            LEGACY_CODEGRAPH_V6_TOOLS
                .iter()
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
            "an installed v6 registration must be rewritten"
        );
        assert_eq!(servers.servers.len(), 1);
        assert_eq!(
            servers.servers[0].allow_tools.as_deref().unwrap(),
            crate::mcp::codegraph_server::TOOL_NAMES
        );
        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::AlreadyCurrent,
            "the repaired nine-tool registration must be idempotent"
        );
    }

    #[test]
    fn codegraph_registration_repairs_historic_v7_allowlist_to_current_nine_tools() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut previous = desired.clone();
        previous.allow_tools = Some(
            LEGACY_CODEGRAPH_V7_TOOLS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        );
        assert_eq!(previous.allow_tools.as_ref().unwrap().len(), 7);
        let mut servers = McpServers {
            smart_loading: true,
            servers: vec![previous],
        };

        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::RepairedLegacy,
            "an installed v7 registration must be rewritten"
        );
        assert_eq!(
            servers.servers[0].allow_tools.as_deref().unwrap(),
            crate::mcp::codegraph_server::TOOL_NAMES
        );
    }

    #[test]
    fn codegraph_registration_repairs_historic_v8_allowlist_to_current_nine_tools() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut previous = desired.clone();
        previous.allow_tools = Some(
            LEGACY_CODEGRAPH_V8_TOOLS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        );
        let mut servers = McpServers {
            smart_loading: true,
            servers: vec![previous],
        };

        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::RepairedLegacy,
            "the prior eight-tool registration must receive diff-impact"
        );
        assert_eq!(
            servers.servers[0].allow_tools.as_deref().unwrap(),
            crate::mcp::codegraph_server::TOOL_NAMES
        );
    }

    #[test]
    fn codegraph_registration_upgrades_trusted_nine_tool_catalogue_with_test_gaps() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut legacy = desired.clone();
        legacy.allow_tools = Some(
            LEGACY_CODEGRAPH_V9_TOOLS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        );
        let mut servers = McpServers {
            smart_loading: true,
            servers: vec![legacy],
        };
        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::RepairedLegacy
        );
        assert_eq!(servers.servers, vec![desired.clone()]);
        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::AlreadyCurrent
        );
    }

    #[test]
    fn codegraph_registration_repairs_trusted_legacy_catalogue_and_preserves_non_codegraph_extras()
    {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut legacy = desired.clone();
        legacy.allow_tools = Some(
            LEGACY_CODEGRAPH_V6_TOOLS
                .iter()
                .map(|name| (*name).to_string())
                .chain(std::iter::once("operator_custom_tool".into()))
                .collect(),
        );
        let before = legacy.clone();
        let mut servers = McpServers {
            smart_loading: true,
            servers: vec![legacy],
        };

        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::RepairedLegacy
        );
        let repaired = servers.servers[0].clone();
        assert_eq!(repaired.description, before.description);
        assert_eq!(repaired.command, before.command);
        assert_eq!(repaired.args, before.args);
        assert_eq!(repaired.env, before.env);
        assert_eq!(repaired.enabled, before.enabled);
        assert_eq!(repaired.trust_all_tools, before.trust_all_tools);
        assert_eq!(repaired.smart_approve, before.smart_approve);
        assert_eq!(repaired.autonomy_gate, before.autonomy_gate);
        let tools = repaired.allow_tools.as_ref().unwrap();
        assert_eq!(
            &tools[..crate::mcp::codegraph_server::TOOL_NAMES.len()],
            crate::mcp::codegraph_server::TOOL_NAMES
        );
        assert_eq!(
            &tools[crate::mcp::codegraph_server::TOOL_NAMES.len()..],
            ["operator_custom_tool"]
        );
        assert_eq!(
            tools.len(),
            crate::mcp::codegraph_server::TOOL_NAMES.len() + 1
        );
        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::Conflict,
            "a repaired allowlist with an operator extra is not exactly current"
        );
        assert_eq!(servers.servers, vec![repaired]);
    }

    #[test]
    fn codegraph_registration_refuses_legacy_lookalike_without_widening_its_security() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut lookalike = desired.clone();
        lookalike.command = "C:/operator/neothd.exe".into();
        lookalike.trust_all_tools = true;
        lookalike.smart_approve = false;
        lookalike.autonomy_gate = Some(crate::permissions::AutonomyLevel::Elevated);
        lookalike.allow_tools = Some(
            LEGACY_CODEGRAPH_V6_TOOLS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        );
        let mut servers = McpServers {
            smart_loading: true,
            servers: vec![lookalike.clone()],
        };

        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::Conflict
        );
        assert_eq!(servers.servers, vec![lookalike]);
    }

    #[test]
    fn codegraph_registration_refuses_unrecognized_codegraph_catalogue() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut custom = desired.clone();
        custom.allow_tools = Some(
            LEGACY_CODEGRAPH_V6_TOOLS
                .iter()
                .map(|name| (*name).to_string())
                .chain(std::iter::once("codegraph_operator_extension".into()))
                .collect(),
        );
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
    fn codegraph_registration_rejects_current_catalogue_with_unknown_codegraph_tool() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut custom = desired.clone();
        custom
            .allow_tools
            .as_mut()
            .unwrap()
            .push("codegraph_operator_extension".into());
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
    fn codegraph_registration_rejects_current_catalogue_with_non_codegraph_extra() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut custom = desired.clone();
        custom
            .allow_tools
            .as_mut()
            .unwrap()
            .push("operator_custom_tool".into());
        assert!(!is_ready_codegraph_registration(&custom, &desired));
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
    fn codegraph_registration_rejects_current_catalogue_with_duplicate_builtin() {
        let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
        let mut duplicated = desired.clone();
        duplicated
            .allow_tools
            .as_mut()
            .unwrap()
            .push("codegraph_outline".into());
        let mut servers = McpServers {
            smart_loading: true,
            servers: vec![duplicated.clone()],
        };

        assert_eq!(
            upsert_codegraph_server(&mut servers, &desired),
            CodegraphRegistrationOutcome::Conflict
        );
        assert_eq!(servers.servers, vec![duplicated]);
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
    fn codegraph_install_refuses_current_catalogue_with_non_codegraph_extra() {
        for output in [OutputFormat::Json, OutputFormat::Table] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("mcp_servers.yaml");
            let desired = codegraph_server_config(std::path::Path::new("neothd"), None);
            let mut custom = desired.clone();
            custom
                .allow_tools
                .as_mut()
                .unwrap()
                .push("operator_custom_tool".into());
            let post_state = inspect_codegraph_post_state(&custom, &desired);
            assert_eq!(post_state.kind, CodegraphPostStateKind::Noncanonical);
            assert!(!post_state.installed);
            assert!(!post_state.exact_tool_allowlist);
            assert_eq!(
                post_state.tool_count,
                crate::mcp::codegraph_server::TOOL_NAMES.len() + 1
            );
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
    fn codegraph_install_refuses_disabled_registration_without_mutating_it() {
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

            let error = install_codegraph_server_at(&path, &desired, &output).unwrap_err();
            assert!(error.to_string().contains("already owned"));
            assert_eq!(
                McpServers::load_from(&path).unwrap().servers,
                vec![disabled]
            );
        }
    }

    #[test]
    fn codegraph_install_refuses_custom_command_or_invocation_without_mutating_it() {
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
        let db_error = install_codegraph_server_at(&db_config_path, &desired, &OutputFormat::Json)
            .unwrap_err();
        assert!(db_error.to_string().contains("already owned"));
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
        let command_error =
            install_codegraph_server_at(&command_config_path, &desired, &OutputFormat::Json)
                .unwrap_err();
        assert!(command_error.to_string().contains("already owned"));
        assert_eq!(
            McpServers::load_from(&command_config_path).unwrap().servers,
            vec![custom_command]
        );
    }

    #[test]
    fn codegraph_install_refuses_noncanonical_launcher_and_security_without_mutating_it() {
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

        let error = install_codegraph_server_at(&path, &desired, &OutputFormat::Json).unwrap_err();
        assert!(error.to_string().contains("already owned"));
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
