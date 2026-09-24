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
use sha2::{Digest as _, Sha256};

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
        #[arg(long, hide = true)]
        impact_max_depth: Option<u32>,
        #[arg(long, hide = true)]
        impact_max_nodes: Option<u32>,
        #[arg(long, hide = true, action = clap::ArgAction::Set)]
        impact_allow_stale: Option<bool>,
        #[arg(long, hide = true)]
        requested_recall_max_files: Option<u32>,
        #[arg(long, hide = true)]
        requested_callers_per_symbol: Option<u32>,
        #[arg(long, hide = true)]
        requested_summary_token_budget: Option<u32>,
        #[arg(long, hide = true)]
        requested_max_bfs_depth: Option<u8>,
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
        McpAction::CodegraphServe {
            db,
            impact_max_depth,
            impact_max_nodes,
            impact_allow_stale,
            requested_recall_max_files,
            requested_callers_per_symbol,
            requested_summary_token_budget,
            requested_max_bfs_depth,
        } => {
            let runtime = crate::mcp::codegraph_server::startup_impact_runtime(
                impact_max_depth,
                impact_max_nodes,
                impact_allow_stale,
            )?;
            let requested_runtime =
                crate::mcp::codegraph_server::startup_requested_context_runtime(
                    requested_recall_max_files,
                    requested_callers_per_symbol,
                    requested_summary_token_budget,
                    requested_max_bfs_depth,
                )?;
            crate::mcp::codegraph_server::serve_stdio_with_runtimes(
                db.unwrap_or_else(crate::code_map::persist::default_path),
                runtime,
                requested_runtime,
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
    let result = match invoke_cli_call_with_spawner_and_trusted_codegraph_descriptor(
        cfg,
        servers.get_enabled("neoth-codegraph"),
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
        // The direct CLI path normally supplies unclassified compatibility
        // provenance, but an IFC denial must remain an explicit fail-closed
        // outcome if a future caller threads a trusted source through here.
        Err(GateError::InformationFlowDenied { reason, .. }) => {
            anyhow::bail!(
                "MCP `{server_id}::{tool}` blocked by information-flow policy: {reason}"
            )
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

/// Production-only direct-CLI path: the selected call and the optional local
/// codegraph descriptor both come from the same already-loaded `McpServers`
/// snapshot. It never reloads the registry while a request is in flight.
async fn invoke_cli_call_with_spawner_and_trusted_codegraph_descriptor<F, Fut>(
    cfg: &crate::mcp::McpServerConfig,
    trusted_codegraph_cfg: Option<&crate::mcp::McpServerConfig>,
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
    invoke_cli_call_with_spawner_at_home_and_trusted_codegraph_descriptor(
        cfg,
        trusted_codegraph_cfg,
        tool,
        arguments,
        policy,
        now_unix,
        &instance_home,
        spawn,
    )
    .await
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
#[cfg(test)]
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
#[cfg(test)]
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

#[allow(clippy::too_many_arguments)]
async fn invoke_cli_call_with_spawner_at_home_and_trusted_codegraph_descriptor<F, Fut>(
    cfg: &crate::mcp::McpServerConfig,
    trusted_codegraph_cfg: Option<&crate::mcp::McpServerConfig>,
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
    let result = invoke_cli_call_with_spawner_and_audit_sink_with_trusted_codegraph_descriptor(
        cfg,
        trusted_codegraph_cfg,
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
#[cfg(test)]
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
    invoke_cli_call_with_spawner_and_audit_sink_with_trusted_codegraph_descriptor(
        cfg,
        None,
        tool,
        arguments,
        policy,
        now_unix,
        sink,
        instance_home,
        spawn,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn invoke_cli_call_with_spawner_and_audit_sink_with_trusted_codegraph_descriptor<F, Fut>(
    cfg: &crate::mcp::McpServerConfig,
    trusted_codegraph_cfg: Option<&crate::mcp::McpServerConfig>,
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
    // Direct calls have no reload controller, but still bind one validated
    // local config snapshot before authorization. A missing optional file uses
    // defaults; an unreadable/invalid file never silently relaxes W59.
    let config = crate::config::FreedomConfig::load_from_path_or_default(
        &instance_home.join("freedom.yaml"),
    )
    .map_err(|error| GateError::PreToolUseBlocked {
        server: cfg.id.clone(),
        tool: tool.to_owned(),
        reason: format!("cannot load requested-context config snapshot: {error:#}"),
    })?;
    let requested_policy = config
        .code_map
        .requested_context_policy()
        .map_err(|error| GateError::PreToolUseBlocked {
            server: cfg.id.clone(),
            tool: tool.to_owned(),
            reason: format!("invalid requested-context policy: {error:#}"),
        })?;
    let exact_generated_descriptor =
        crate::mcp::codegraph_server::is_exact_generated_codegraph_base_for_direct_cli(cfg);
    let effective_cfg =
        crate::mcp::codegraph_server::effective_builtin_codegraph_server_with_requested_policy(
            cfg,
            config.code_map.impact_policy,
            requested_policy,
        )
        .map_err(|error| GateError::PreToolUseBlocked {
            server: cfg.id.clone(),
            tool: tool.to_owned(),
            reason: format!("cannot derive requested-context descriptor: {error:#}"),
        })?;
    let cfg = &effective_cfg;
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
    let outline_enrichment_enabled = config.code_map.outline_enrichment;
    let enrichment_selectors = &config.code_map.enrichment_selectors;
    let pre_tool_use = crate::mcp::gate::admit_pre_tool_use_with_configured_path_read(
        crate::hooks::PreToolUseOrigin::DirectCliMcp,
        cfg,
        trusted_codegraph_cfg,
        tool,
        &arguments,
        instance_home,
        &request_binding_sha256,
        crate::hooks::PreToolUseHookPolicy::Configured(&hooks),
        &once_guard,
        crate::hooks::PreToolUseCancellation::unbound(),
        crate::hooks::PreToolUseReplay::direct_request(),
        outline_enrichment_enabled,
        enrichment_selectors,
    )?;
    let mut client = spawn(cfg.clone()).await?;
    let require_context_binding = exact_generated_descriptor && direct_context_binding_tool(tool);
    let response = crate::mcp::gate::invoke_authorized_with_audit_sink_decoded(
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
        require_context_binding,
    )
    .await?;
    if require_context_binding && !response.result.is_error {
        let payload = final_tool_result_prepared_payload(
            tool,
            &request_binding_sha256,
            response.meta.as_ref(),
            &response.result,
            now_unix,
        )?;
        crate::mcp::gate::append_final_tool_result_prepared(sink, payload).await?;
    }
    Ok(response.result)
}

fn direct_context_binding_tool(tool: &str) -> bool {
    matches!(
        tool,
        "codegraph_recall_v1"
            | "codegraph_relevant_files"
            | "codegraph_callers"
            | "codegraph_callees"
    )
}

fn final_tool_result_prepared_payload(
    tool: &str,
    request_binding_sha256: &str,
    meta: Option<&serde_json::Value>,
    sanitized_result: &ToolCallResult,
    now_unix: i64,
) -> Result<Vec<u8>, GateError> {
    let binding = meta
        .and_then(|value| {
            value.get(crate::mcp::codegraph_server::CODEGRAPH_CONTEXT_BINDING_META_KEY)
        })
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            GateError::Mcp(McpError::Protocol(
                "neoth-codegraph".into(),
                "missing codegraph context-binding metadata".into(),
            ))
        })?;
    let str_field = |key: &str| binding.get(key).and_then(serde_json::Value::as_str);
    let number_field = |key: &str| binding.get(key).and_then(serde_json::Value::as_i64);
    let projection = crate::mcp::client::tool_call_result_projection(sanitized_result);
    let projection = serde_json::to_vec(&projection).map_err(|error| {
        GateError::Mcp(McpError::Protocol(
            "neoth-codegraph".into(),
            error.to_string(),
        ))
    })?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "neoth.code_map.recall.audit.v1",
        "status": "final_tool_result_prepared",
        "surface": "direct_cli_mcp",
        "request_sha256": request_binding_sha256,
        "tool": tool,
        "root_identity_hash_sha256": str_field("root_identity_sha256"),
        "index_generation": number_field("index_generation"),
        "graph_generation": number_field("graph_generation"),
        "child_public_result_sha256": str_field("public_result_sha256"),
        "child_public_result_bytes": binding.get("public_result_bytes").and_then(serde_json::Value::as_u64),
        "final_public_result_sha256": hex::encode(Sha256::digest(&projection)),
        "final_public_result_bytes": projection.len(),
        "ts_unix": now_unix,
    }))
    .map_err(|error| GateError::Mcp(McpError::Protocol("neoth-codegraph".into(), error.to_string())))
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

    /// A libtest binary cannot accept the production `mcp codegraph-serve`
    /// arguments. These W95/W97 direct-CLI fixtures therefore keep the
    /// selected configuration and production gate path intact, but provide the
    /// existing real NDJSON codegraph child at the injected spawn seam.
    async fn spawn_codegraph_stdio_fixture(
        server_id: &str,
        database: &std::path::Path,
        root: &std::path::Path,
    ) -> std::result::Result<McpClient, McpError> {
        let executable = std::env::current_exe()
            .map_err(|error| McpError::Spawn(server_id.into(), error.to_string()))?;
        let mut child = tokio::process::Command::new(executable);
        child
            .args([
                "--exact",
                "mcp::codegraph_server::w53_serve_stdio_marker_child",
                "--nocapture",
            ])
            .env("NEOTH_W53_SERVE_STDIO_DB", database)
            .env("NEOTH_W59_CHILD_CWD", root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        let child = child
            .spawn()
            .map_err(|error| McpError::Spawn(server_id.into(), error.to_string()))?;
        McpClient::from_test_child(server_id, child).await
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

    // One direct-CLI regression owns W95's actual configured-provider path.
    // W53/W79 retain their native built-in gate fixtures. The selected provider
    // and the trusted generated descriptor are both borrowed from `snapshot`.
    #[test]
    fn w95_direct_cli_configured_read_path_keeps_selected_results_and_same_snapshot_descriptor() {
        let _env = crate::test_env::lock();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build W95 direct CLI runtime")
            .block_on(async {
                let home = tempfile::tempdir().expect("W95 direct CLI home");
                let database = home.path().join("code-map.sqlite");
                let root = home.path().join("canonical-root");
                crate::mcp::codegraph_server::w59_seed_real_sqlite_root(&database, &root, "w95");
                let database = database.canonicalize().expect("canonical W95 SQLite map");
                let executable = std::env::current_exe()
                    .expect("W95 executable")
                    .canonicalize()
                    .expect("canonical W95 executable");
                let trusted = codegraph_server_config(&executable, Some(database.clone()));
                let mut selected = trusted.clone();
                selected.id = "w95-cli-read-fixture".into();
                let snapshot = McpServers {
                    smart_loading: true,
                    servers: vec![trusted, selected],
                };
                let selected = snapshot
                    .get_enabled("w95-cli-read-fixture")
                    .expect("selected configured provider from the immutable snapshot");
                let trusted = snapshot
                    .get_enabled("neoth-codegraph")
                    .expect("trusted generated descriptor from that immutable snapshot");
                std::fs::write(
                    home.path().join("freedom.yaml"),
                    r#"
code_map:
  outline_enrichment: true
  enrichment_selectors:
    - server_id: w95-cli-read-fixture
      tool: codegraph_outline
      kind: ReadPath
      path_field: path
"#,
                )
                .expect("write W95 exact selector config");
                let prior_cwd = std::env::current_dir().expect("capture W95 current directory");
                struct RestoreCwd(std::path::PathBuf);
                impl Drop for RestoreCwd {
                    fn drop(&mut self) {
                        std::env::set_current_dir(&self.0).expect("restore W95 current directory");
                    }
                }
                std::env::set_current_dir(&root).expect("enter W95 canonical root");
                let _restore_cwd = RestoreCwd(prior_cwd);
                let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
                    crate::permissions::AutonomyLevel::Full,
                )
                .expect("Full policy authorizes W95 direct CLI fixture");
                let child_database = database.clone();
                let child_root = root.clone();

                let selected_success = invoke_cli_call_with_spawner_and_audit_sink_with_trusted_codegraph_descriptor(
                    selected,
                    Some(trusted),
                    "codegraph_outline",
                    serde_json::json!({"path":"x.rs"}),
                    policy.clone(),
                    1_700_000_095,
                    crate::mcp::gate::McpAuditSink::None,
                    home.path(),
                    move |fixture| {
                        let child_database = child_database.clone();
                        let child_root = child_root.clone();
                        async move {
                            spawn_codegraph_stdio_fixture(&fixture.id, &child_database, &child_root)
                                .await
                        }
                    },
                )
                .await
                .expect("exact selected ReadPath returns its ordinary result and sidecar");
                assert!(!selected_success.is_error);
                assert_eq!(selected_success.content.len(), 2);
                assert!(matches!(&selected_success.content[0], crate::mcp::client::McpContent::Text { text } if text.contains("leaf_w95")));
                assert!(matches!(&selected_success.content[1], crate::mcp::client::McpContent::Text { text } if text.contains("[untrusted configured MCP ReadPath sidecar]") && text.contains("file: x.rs")));

                let child_database = database.clone();
                let child_root = root.clone();
                let unconfigured = invoke_cli_call_with_spawner_and_audit_sink_with_trusted_codegraph_descriptor(
                    selected,
                    Some(trusted),
                    "codegraph_relevant_files",
                    serde_json::json!({"prompt":"leaf_w95","limit":1}),
                    policy.clone(),
                    1_700_000_095,
                    crate::mcp::gate::McpAuditSink::None,
                    home.path(),
                    move |fixture| {
                        let child_database = child_database.clone();
                        let child_root = child_root.clone();
                        async move {
                            spawn_codegraph_stdio_fixture(&fixture.id, &child_database, &child_root)
                                .await
                        }
                    },
                )
                .await
                .expect("unconfigured tool keeps its ordinary result");
                assert!(!unconfigured.is_error);
                assert_eq!(unconfigured.content.len(), 1);
                assert!(!matches!(&unconfigured.content[0], crate::mcp::client::McpContent::Text { text } if text.contains("[untrusted configured MCP ReadPath sidecar]")));

                let child_database = database.clone();
                let child_root = root.clone();
                let malformed = invoke_cli_call_with_spawner_and_audit_sink_with_trusted_codegraph_descriptor(
                    selected,
                    Some(trusted),
                    "codegraph_outline",
                    serde_json::json!({"path":7}),
                    policy,
                    1_700_000_095,
                    crate::mcp::gate::McpAuditSink::None,
                    home.path(),
                    move |fixture| {
                        let child_database = child_database.clone();
                        let child_root = child_root.clone();
                        async move {
                            spawn_codegraph_stdio_fixture(&fixture.id, &child_database, &child_root)
                                .await
                        }
                    },
                )
                .await
                .expect("malformed selected arguments retain the child MCP error result");
                assert!(malformed.is_error);
                assert_eq!(malformed.content.len(), 1);
                assert!(!matches!(&malformed.content[0], crate::mcp::client::McpContent::Text { text } if text.contains("[untrusted configured MCP ReadPath sidecar]")));
            });
    }

    #[test]
    fn w97_direct_cli_selected_read_negatives_preserve_child_result_without_sidecar() {
        let _env = crate::test_env::lock();
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("W97 runtime").block_on(async {
            let home = tempfile::tempdir().expect("W97 home");
            let database = home.path().join("code-map.sqlite");
            let root = home.path().join("root");
            crate::mcp::codegraph_server::w59_seed_real_sqlite_root(&database, &root, "w97");
            let executable = std::env::current_exe().expect("W97 executable").canonicalize().expect("canonical W97 executable");
            let trusted = codegraph_server_config(&executable, Some(database.canonicalize().expect("canonical W97 map")));
            let mut selected = trusted.clone(); selected.id = "w97-cli-configured-read".into();
            let snapshot = McpServers { smart_loading: true, servers: vec![trusted, selected] };
            let selected = snapshot.get_enabled("w97-cli-configured-read").expect("selected snapshot descriptor");
            let trusted = snapshot.get_enabled("neoth-codegraph").expect("trusted snapshot descriptor");
            let prior = std::env::current_dir().expect("W97 cwd");
            struct Restore(std::path::PathBuf); impl Drop for Restore { fn drop(&mut self) { std::env::set_current_dir(&self.0).expect("restore W97 cwd"); } }
            std::env::set_current_dir(&root).expect("enter W97 root"); let _restore = Restore(prior);
            let policy = crate::permissions::AutonomyPolicySnapshot::builtin(crate::permissions::AutonomyLevel::Full).expect("W97 full policy");
            let cases = [
                ("master_off", "code_map:\n  outline_enrichment: false\n  enrichment_selectors:\n    - server_id: w97-cli-configured-read\n      tool: codegraph_outline\n      kind: ReadPath\n      path_field: path\n", serde_json::json!({"path":"x.rs"}), false),
                ("empty_selectors", "code_map:\n  outline_enrichment: true\n  enrichment_selectors: []\n", serde_json::json!({"path":"x.rs"}), false),
                ("pair_mismatch", "code_map:\n  outline_enrichment: true\n  enrichment_selectors:\n    - server_id: w97-cli-configured-read\n      tool: codegraph_outline_other\n      kind: ReadPath\n      path_field: path\n", serde_json::json!({"path":"x.rs"}), false),
                ("extra_path", "code_map:\n  outline_enrichment: true\n  enrichment_selectors:\n    - server_id: w97-cli-configured-read\n      tool: codegraph_outline\n      kind: ReadPath\n      path_field: path\n", serde_json::json!({"path":"x.rs","extra":true}), true),
                ("malformed_path", "code_map:\n  outline_enrichment: true\n  enrichment_selectors:\n    - server_id: w97-cli-configured-read\n      tool: codegraph_outline\n      kind: ReadPath\n      path_field: path\n", serde_json::json!({"path":7}), true),
            ];
            for (label, config, arguments, expected_error) in cases {
                std::fs::write(home.path().join("freedom.yaml"), config).expect("write W97 config");
                let child_database = database.clone();
                let child_root = root.clone();
                let result = invoke_cli_call_with_spawner_and_audit_sink_with_trusted_codegraph_descriptor(selected, Some(trusted), "codegraph_outline", arguments, policy.clone(), 1_700_000_097, crate::mcp::gate::McpAuditSink::None, home.path(), move |fixture| {
                    let child_database = child_database.clone();
                    let child_root = child_root.clone();
                    async move {
                        spawn_codegraph_stdio_fixture(&fixture.id, &child_database, &child_root)
                            .await
                    }
                }).await.expect("negative case retains child MCP result");
                assert_eq!(result.is_error, expected_error, "{label}: child result shape changed");
                assert_eq!(result.content.len(), 1, "{label}: configured sidecar must not be appended");
                assert!(!matches!(&result.content[0], crate::mcp::client::McpContent::Text { text } if text.contains("[untrusted configured MCP ReadPath sidecar]")), "{label}: sidecar leaked");
            }
        });
    }

    // W102 covers the policy boundaries which run before a configured external
    // ReadPath child exists. W95 owns the successful selected child call and
    // W97 owns selector/argument rejection; this test must keep the selected
    // provider on the same immutable snapshot while exercising the real CLI
    // authorization core and its durable audit order.
    #[test]
    fn w102_selected_read_preserves_authority_gates_before_child_start() {
        let _env = crate::test_env::lock();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build W102 selected-read runtime")
            .block_on(async {
                let home = tempfile::tempdir().expect("W102 selected-read home");
                let database = home.path().join("code-map.sqlite");
                let root = home.path().join("root");
                crate::mcp::codegraph_server::w59_seed_real_sqlite_root(
                    &database,
                    &root,
                    "w102",
                );
                let executable = std::env::current_exe()
                    .expect("W102 executable")
                    .canonicalize()
                    .expect("canonical W102 executable");
                let trusted = codegraph_server_config(
                    &executable,
                    Some(database.canonicalize().expect("canonical W102 map")),
                );
                let mut selected = trusted.clone();
                selected.id = "w102-selected-read".into();
                let snapshot = McpServers {
                    smart_loading: true,
                    servers: vec![trusted, selected],
                };
                let selected = snapshot
                    .get_enabled("w102-selected-read")
                    .expect("selected descriptor belongs to immutable snapshot");
                let trusted = snapshot
                    .get_enabled("neoth-codegraph")
                    .expect("trusted descriptor belongs to immutable snapshot");
                let selector_config = "code_map:\n  outline_enrichment: true\n  enrichment_selectors:\n    - server_id: w102-selected-read\n      tool: codegraph_outline\n      kind: ReadPath\n      path_field: path\n";
                let prior = std::env::current_dir().expect("capture W102 cwd");
                struct Restore(std::path::PathBuf);
                impl Drop for Restore {
                    fn drop(&mut self) {
                        std::env::set_current_dir(&self.0).expect("restore W102 cwd");
                    }
                }
                std::env::set_current_dir(&root).expect("enter W102 root");
                let _restore = Restore(prior);
                let arguments = serde_json::json!({"path":"x.rs"});

                for (label, policy, expected) in [
                    (
                        "allowlist",
                        crate::permissions::AutonomyPolicySnapshot::builtin(
                            crate::permissions::AutonomyLevel::Full,
                        )
                        .expect("W102 Full policy"),
                        "allowlist",
                    ),
                    (
                        "confirm",
                        crate::permissions::AutonomyPolicySnapshot::builtin(
                            crate::permissions::AutonomyLevel::Standard,
                        )
                        .expect("W102 Standard policy"),
                        "confirm",
                    ),
                ] {
                    let case_home = tempfile::tempdir().expect("W102 authority case home");
                    std::fs::write(case_home.path().join("freedom.yaml"), selector_config)
                        .expect("write W102 authority selector config");
                    let (writer, join) = home_audit_writer(case_home.path());
                    let mut blocked = selected.clone();
                    if label == "allowlist" {
                        blocked.allow_tools = Some(Vec::new());
                    }
                    let binding = cli_mcp_request_binding(&blocked, "codegraph_outline", &arguments)
                        .expect("bind exact selected request");
                    let attempts = Arc::new(AtomicUsize::new(0));
                    let count = Arc::clone(&attempts);
                    let error = invoke_cli_call_with_spawner_and_audit_sink_with_trusted_codegraph_descriptor(
                        &blocked,
                        Some(trusted),
                        "codegraph_outline",
                        arguments.clone(),
                        policy,
                        1_700_000_102,
                        crate::mcp::gate::McpAuditSink::Writer(&writer),
                        case_home.path(),
                        move |_| {
                            count.fetch_add(1, Ordering::SeqCst);
                            async move { panic!("{label}: authority rejection reached selected child start") }
                        },
                    )
                    .await
                    .expect_err("W102 authority boundary rejects before the selected child");
                    assert_eq!(attempts.load(Ordering::SeqCst), 0, "{label}: no child means no tools/call or sidecar");
                    match expected {
                        "allowlist" => assert!(matches!(error, GateError::NotInAllowlist { .. })),
                        "confirm" => assert!(matches!(error, GateError::ConfirmRequired { .. })),
                        _ => unreachable!("fixed W102 case labels"),
                    }
                    let entries = home_trust_entries(case_home.path(), writer, join).await;
                    assert_eq!(entries.len(), 1, "{label}: one final durable denial");
                    assert_eq!(
                        entries[0].event.outcome,
                        crate::permissions::trust_ledger::TrustOutcome::Denied,
                        "{label}: selected ReadPath keeps the existing denial audit"
                    );
                    assert_eq!(
                        entries[0].event.request_binding_sha256.as_deref(),
                        Some(binding.as_str()),
                        "{label}: audit remains bound to the selected request"
                    );
                }

                let hook_home = tempfile::tempdir().expect("W102 configured hook home");
                std::fs::write(hook_home.path().join("freedom.yaml"), selector_config)
                    .expect("write W102 hook selector config");
                let hooks = hook_home.path().join("hooks");
                std::fs::create_dir_all(&hooks).expect("create W102 hooks directory");
                std::fs::write(
                    hooks.join("block.toml"),
                    "name = \"w102-selected-block\"\nstage = \"pre_tool_use\"\n[action]\nkind = \"block\"\nreason = \"selected ReadPath test block\"\n",
                )
                .expect("write W102 selected PreToolUse block");
                let (writer, join) = home_audit_writer(hook_home.path());
                let binding = cli_mcp_request_binding(selected, "codegraph_outline", &arguments)
                    .expect("bind configured PreToolUse request");
                let attempts = Arc::new(AtomicUsize::new(0));
                let count = Arc::clone(&attempts);
                let error = invoke_cli_call_with_spawner_and_audit_sink_with_trusted_codegraph_descriptor(
                    selected,
                    Some(trusted),
                    "codegraph_outline",
                    arguments,
                    crate::permissions::AutonomyPolicySnapshot::builtin(
                        crate::permissions::AutonomyLevel::Full,
                    )
                    .expect("W102 Full policy for PreToolUse"),
                    1_700_000_102,
                    crate::mcp::gate::McpAuditSink::Writer(&writer),
                    hook_home.path(),
                    move |_| {
                        count.fetch_add(1, Ordering::SeqCst);
                        async { panic!("configured selected ReadPath block reached child start") }
                    },
                )
                .await
                .expect_err("configured selected PreToolUse block is final before child");
                assert!(matches!(error, GateError::PreToolUseBlocked { .. }));
                assert_eq!(attempts.load(Ordering::SeqCst), 0, "PreToolUse block has no child, tools/call, or sidecar");
                let entries = home_trust_entries(hook_home.path(), writer, join).await;
                assert_eq!(entries.len(), 1, "pre-tool boundary keeps one policy audit entry");
                assert_eq!(
                    entries[0].event.outcome,
                    crate::permissions::trust_ledger::TrustOutcome::Allowed,
                    "policy authorization remains auditable before the configured hook boundary"
                );
                assert_eq!(entries[0].event.request_binding_sha256.as_deref(), Some(binding.as_str()));
            });
    }

    const W97_POST_CALL_MUTATE_ROOT: &str = "NEOTH_W97_POST_CALL_MUTATE_ROOT";
    const W97_POST_CALL_COUNT: &str = "NEOTH_W97_POST_CALL_COUNT";

    #[test]
    fn w97_post_call_mutating_wire_child() {
        let (Some(root), Some(count)) = (
            std::env::var_os(W97_POST_CALL_MUTATE_ROOT),
            std::env::var_os(W97_POST_CALL_COUNT),
        ) else {
            return;
        };
        use std::io::{BufRead as _, Write as _};
        println!("NEOTH_W53_STDIO_READY");
        std::io::stdout().flush().expect("W97 ready");
        let mut tool_calls = 0u32;
        for line in std::io::stdin().lock().lines() {
            let request: serde_json::Value =
                serde_json::from_str(&line.expect("W97 request")).expect("W97 JSON");
            if request["method"] == "initialize" {
                println!(
                    "{}",
                    serde_json::json!({"jsonrpc":"2.0","id":request["id"].clone(),"result":{"protocolVersion":crate::mcp::client::MCP_PROTOCOL_VERSION,"capabilities":{}}})
                );
            } else if request["method"] == "tools/call" {
                std::fs::write(
                    std::path::PathBuf::from(&root).join("x.rs"),
                    "fn leaf_w97_mutated() {}\n",
                )
                .expect("mutate indexed source after actual call");
                tool_calls += 1;
                std::fs::write(&count, tool_calls.to_string())
                    .expect("record actual tools/call count");
                println!(
                    "{}",
                    serde_json::json!({"jsonrpc":"2.0","id":request["id"].clone(),"result":{"content":[{"type":"text","text":"ordinary external result survives freshness fence"}],"isError":false}})
                );
            }
            std::io::stdout().flush().expect("flush W97 response");
        }
    }

    #[test]
    fn w97_selected_call_suppresses_sidecar_after_post_call_source_freshness_change() {
        let _env = crate::test_env::lock();
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("W97 freshness runtime").block_on(async {
            let home = tempfile::tempdir().expect("W97 freshness home"); let database = home.path().join("code-map.sqlite"); let root = home.path().join("root");
            crate::mcp::codegraph_server::w59_seed_real_sqlite_root(&database, &root, "w97_freshness");
            let executable = std::env::current_exe().expect("W97 executable").canonicalize().expect("canonical executable");
            let trusted = codegraph_server_config(&executable, Some(database.canonicalize().expect("canonical map"))); let mut selected = trusted.clone(); selected.id = "w97-post-call-read".into();
            let snapshot = McpServers { smart_loading: true, servers: vec![trusted, selected] }; let selected = snapshot.get_enabled("w97-post-call-read").unwrap(); let trusted = snapshot.get_enabled("neoth-codegraph").unwrap();
            std::fs::write(home.path().join("freedom.yaml"), "code_map:\n  outline_enrichment: true\n  enrichment_selectors:\n    - server_id: w97-post-call-read\n      tool: codegraph_outline\n      kind: ReadPath\n      path_field: path\n").unwrap();
            let prior = std::env::current_dir().unwrap(); struct Restore(std::path::PathBuf); impl Drop for Restore { fn drop(&mut self){std::env::set_current_dir(&self.0).unwrap();} } std::env::set_current_dir(&root).unwrap(); let _restore = Restore(prior);
            let count = home.path().join("tools-call-count"); let child_root = root.clone(); let child_count = count.clone(); let policy = crate::permissions::AutonomyPolicySnapshot::builtin(crate::permissions::AutonomyLevel::Full).unwrap();
            let result = invoke_cli_call_with_spawner_and_audit_sink_with_trusted_codegraph_descriptor(selected, Some(trusted), "codegraph_outline", serde_json::json!({"path":"x.rs"}), policy, 1_700_000_097, crate::mcp::gate::McpAuditSink::None, home.path(), |_| async move {
                let mut child = tokio::process::Command::new(std::env::current_exe().unwrap()); child.args(["--exact", "cli::mcp::tests::w97_post_call_mutating_wire_child", "--nocapture"]).env(W97_POST_CALL_MUTATE_ROOT, &child_root).env(W97_POST_CALL_COUNT, &child_count).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()); McpClient::from_test_child("w97-post-call-read", child.spawn().unwrap()).await
            }).await.expect("ordinary child result survives post-call freshness fence");
            assert!(!result.is_error); assert_eq!(result.content.len(), 1); assert!(matches!(&result.content[0], crate::mcp::client::McpContent::Text { text } if text == "ordinary external result survives freshness fence")); assert_eq!(std::fs::read_to_string(count).unwrap(), "1");
        });
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
        assert_eq!(crate::mcp::codegraph_server::TOOL_NAMES.len(), 12);
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
            skill_overrides: std::collections::BTreeMap::new(),
        };
        let policy = crate::permissions::AutonomyPolicySnapshot::new(
            crate::permissions::AutonomyLevel::Custom,
            &custom,
        );
        let (error, attempts) = rejected_cli_call_spawn_attempts(&config, "read", policy).await;
        assert!(matches!(error, GateError::PermissionDenied { .. }));
        assert_eq!(attempts, 0);
    }

    // This is intentionally a real stdio child rather than a constructed
    // ToolCallResult: W61's receipt is only meaningful when the child chose
    // the root/generation witness that travelled on the tools/call response.
    #[test]
    fn w61_direct_cli_generated_stdio_receipts_bind_child_metadata_before_return() {
        let _env = crate::test_env::lock();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build W61 current-thread runtime")
            .block_on(async {
                let home = tempfile::tempdir().expect("W61 home");
                let database = home.path().join("code-map.sqlite");
                let root = home.path().join("canonical-root");
                crate::mcp::codegraph_server::w59_seed_real_sqlite_root(&database, &root, "w61");
                let database = database.canonicalize().expect("canonical W61 SQLite map");
                let executable = std::env::current_exe()
                    .expect("test executable")
                    .canonicalize()
                    .expect("canonical test executable");
                let config = codegraph_server_config(&executable, Some(database));
                let record = home.path().join("w61-child-events.jsonl");
                let old_record = std::env::var_os("NEOTH_W56_CHILD_RECORD");
                let old_cwd = std::env::var_os("NEOTH_W59_CHILD_CWD");
                unsafe {
                    std::env::set_var("NEOTH_W56_CHILD_RECORD", &record);
                    std::env::set_var("NEOTH_W59_CHILD_CWD", &root);
                }
                struct RestoreW61ChildEnv(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
                impl Drop for RestoreW61ChildEnv {
                    fn drop(&mut self) {
                        unsafe {
                            match self.0.take() {
                                Some(value) => std::env::set_var("NEOTH_W56_CHILD_RECORD", value),
                                None => std::env::remove_var("NEOTH_W56_CHILD_RECORD"),
                            }
                            match self.1.take() {
                                Some(value) => std::env::set_var("NEOTH_W59_CHILD_CWD", value),
                                None => std::env::remove_var("NEOTH_W59_CHILD_CWD"),
                            }
                        }
                    }
                }
                let _restore = RestoreW61ChildEnv(old_record, old_cwd);
                let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
                    crate::permissions::AutonomyLevel::Full,
                )
                .expect("Full policy allows the owned direct call");
                let calls = [
                    (
                        "codegraph_recall_v1",
                        serde_json::json!({"prompt":"leaf_w61","limit":1}),
                    ),
                    (
                        "codegraph_relevant_files",
                        serde_json::json!({"prompt":"leaf_w61","limit":1}),
                    ),
                    (
                        "codegraph_callers",
                        serde_json::json!({"symbol":"leaf_w61","depth":2}),
                    ),
                    (
                        "codegraph_callees",
                        serde_json::json!({"file":"x.rs","symbol":"root_w61","depth":2}),
                    ),
                ];
                let mut returned = Vec::new();
                for (tool, arguments) in &calls {
                    let result = invoke_cli_call_with_spawner_at_home(
                        &config,
                        tool,
                        arguments.clone(),
                        policy.clone(),
                        1_700_000_061,
                        home.path(),
                        |fixture| async move { McpClient::spawn(&fixture).await },
                    )
                    .await
                    .unwrap_or_else(|error| {
                        panic!("{tool} must return only after its audited W61 receipt: {error:#}")
                    });
                    assert!(!result.is_error, "{tool} returned an error result");
                    returned.push(result);
                }
                assert!(
                    serde_json::from_str::<serde_json::Value>(match &returned[0].content[0] {
                        crate::mcp::client::McpContent::Text { text } => text,
                        _ => panic!("recall text"),
                    })
                    .unwrap()
                    .is_object()
                );
                for result in returned.iter().skip(1) {
                    assert!(
                        serde_json::from_str::<serde_json::Value>(match &result.content[0] {
                            crate::mcp::client::McpContent::Text { text } => text,
                            _ => panic!("legacy text"),
                        })
                        .unwrap()
                        .is_array()
                    );
                }
                let events: Vec<serde_json::Value> = std::fs::read_to_string(&record)
                    .expect("W61 child record")
                    .lines()
                    .map(|line| serde_json::from_str(line).expect("W61 child event"))
                    .collect();
                let child_calls: Vec<_> = events
                    .iter()
                    .filter(|event| event["event"] == "tools/call")
                    .collect();
                assert_eq!(
                    child_calls.len(),
                    4,
                    "every receipt follows one actual child tools/call"
                );
                for (event, (tool, _)) in child_calls.iter().zip(calls.iter()) {
                    assert_eq!(event["name"].as_str(), Some(*tool));
                }
                let mut receipts = Vec::new();
                let mut called_before_receipt = 0usize;
                let mut durable_allows = 0usize;
                crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
                    home.path(),
                    crate::wal::scan::supported_home_scan_limits(),
                    |_, frame| {
                        if frame.header.event_type == crate::wal::events::EVENT_TYPE_MCP_TOOL_CALLED
                        {
                            called_before_receipt += 1;
                        }
                        if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                            && frame.header.event_subtype
                                == crate::wal::events::ExtendedSubtype::TrustDecision as u8
                        {
                            durable_allows += 1;
                        }
                        if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                            && frame.header.event_subtype
                                == crate::wal::events::ExtendedSubtype::CodeMapRecallResolved as u8
                        {
                            assert!(
                                called_before_receipt > receipts.len(),
                                "called audit precedes prepared receipt"
                            );
                            receipts.push(
                                serde_json::from_slice::<serde_json::Value>(frame.payload)
                                    .expect("prepared result payload"),
                            );
                        }
                        Ok(())
                    },
                )
                .expect("scan authenticated W61 WAL");
                assert_eq!(
                    receipts.len(),
                    4,
                    "one prepared result receipt per returned child result"
                );
                assert_eq!(
                    called_before_receipt, 4,
                    "exactly four real child calls reach the called audit"
                );
                assert_eq!(
                    durable_allows, 4,
                    "the existing required permission allow is durable for every direct call"
                );
                for ((receipt, result), (tool, _)) in
                    receipts.iter().zip(returned.iter()).zip(calls.iter())
                {
                    assert_eq!(receipt["status"], "final_tool_result_prepared");
                    assert_eq!(receipt["tool"], *tool);
                    assert_eq!(receipt["index_generation"], receipt["graph_generation"]);
                    assert_eq!(
                        receipt.as_object().map(|object| object.len()),
                        Some(13),
                        "receipt remains metadata-only with a closed field set"
                    );
                    for forbidden in ["root", "path", "symbol", "prompt", "result", "content"] {
                        assert!(
                            receipt.get(forbidden).is_none(),
                            "receipt leaked {forbidden}"
                        );
                    }
                    assert_eq!(
                        receipt["child_public_result_sha256"].as_str().map(str::len),
                        Some(64)
                    );
                    assert_eq!(
                        receipt["final_public_result_sha256"].as_str().map(str::len),
                        Some(64)
                    );
                    let projection = serde_json::to_vec(
                        &crate::mcp::client::tool_call_result_projection(result),
                    )
                    .expect("serialize sanitized final result projection");
                    assert_eq!(
                        receipt["final_public_result_bytes"].as_u64(),
                        Some(projection.len() as u64)
                    );
                    assert_eq!(
                        receipt["final_public_result_sha256"],
                        hex::encode(Sha256::digest(&projection))
                    );
                }
            });
    }

    #[test]
    fn w61_raw_metadata_wire_child() {
        let Some(mode) = std::env::var_os("NEOTH_W61_RAW_METADATA_MODE") else {
            return;
        };
        use std::io::{BufRead as _, Write as _};
        println!("NEOTH_W53_STDIO_READY");
        std::io::stdout().flush().expect("flush W61 child marker");
        for line in std::io::stdin().lock().lines() {
            let request: serde_json::Value =
                serde_json::from_str(&line.expect("W61 child request"))
                    .expect("valid W61 child request");
            // The concrete `McpClient` owns the regular lifecycle.  This
            // fixture must answer `initialize` faithfully before it can
            // exercise a deliberately malformed *tools/call* result.
            if request["method"] == "initialize" {
                println!(
                    "{}",
                    serde_json::json!({
                        "jsonrpc":"2.0",
                        "id":request["id"].clone(),
                        "result":{"protocolVersion": crate::mcp::client::MCP_PROTOCOL_VERSION, "capabilities":{}}
                    })
                );
                std::io::stdout()
                    .flush()
                    .expect("flush W61 initialize response");
                continue;
            }
            if request["method"] == "notifications/initialized" {
                continue;
            }
            let mode = mode.to_string_lossy();
            let mut result = serde_json::json!({"content":[{"type":"text","text":"[]"}],"isError":mode == "is_error"});
            if mode == "malformed" {
                let mut meta = serde_json::Map::new();
                meta.insert(
                    crate::mcp::codegraph_server::CODEGRAPH_CONTEXT_BINDING_META_KEY.to_owned(),
                    serde_json::json!({"schema":"wrong"}),
                );
                result["_meta"] = serde_json::Value::Object(meta);
            }
            if matches!(
                mode.as_ref(),
                "digest_mismatch" | "extra_own_field" | "unequal_generations"
            ) {
                let typed: ToolCallResult =
                    serde_json::from_value(result.clone()).expect("W61 typed raw child result");
                let projection =
                    serde_json::to_vec(&crate::mcp::client::tool_call_result_projection(&typed))
                        .expect("W61 raw child projection");
                let mut binding = serde_json::json!({
                    "schema":"io.neoth.codegraph.context_binding.v1",
                    "tool":"codegraph_relevant_files",
                    "root_identity_sha256":"a".repeat(64),
                    "index_generation":7,
                    "graph_generation":7,
                    "public_result_sha256":hex::encode(Sha256::digest(&projection)),
                    "public_result_bytes":projection.len(),
                });
                if mode == "digest_mismatch" {
                    binding["public_result_sha256"] = serde_json::json!("b".repeat(64));
                }
                if mode == "extra_own_field" {
                    binding["unexpected"] = serde_json::json!(true);
                }
                if mode == "unequal_generations" {
                    binding["graph_generation"] = serde_json::json!(8);
                }
                let mut meta = serde_json::Map::new();
                meta.insert(
                    crate::mcp::codegraph_server::CODEGRAPH_CONTEXT_BINDING_META_KEY.to_owned(),
                    binding,
                );
                result["_meta"] = serde_json::Value::Object(meta);
            }
            println!(
                "{}",
                serde_json::json!({"jsonrpc":"2.0","id":request["id"].clone(),"result":result})
            );
            std::io::stdout().flush().expect("flush W61 child response");
        }
    }

    async fn w61_raw_metadata_child(mode: &str) -> Result<McpClient, McpError> {
        let mut child =
            tokio::process::Command::new(std::env::current_exe().expect("W61 test executable"));
        child
            .args([
                "--exact",
                "cli::mcp::tests::w61_raw_metadata_wire_child",
                "--nocapture",
            ])
            .env("NEOTH_W61_RAW_METADATA_MODE", mode)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        McpClient::from_test_child(
            "neoth-codegraph",
            child.spawn().expect("spawn W61 wire child"),
        )
        .await
    }

    async fn w61_frame_types(
        home: &std::path::Path,
        writer: crate::wal::writer::WalWriterHandle,
        join: tokio::task::JoinHandle<()>,
    ) -> Vec<(u8, u8)> {
        drop(writer);
        join.await.expect("W61 WAL writer exits");
        let mut frames = Vec::new();
        crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
            home,
            crate::wal::scan::supported_home_scan_limits(),
            |_, frame| {
                frames.push((frame.header.event_type, frame.header.event_subtype));
                Ok(())
            },
        )
        .expect("scan authenticated W61 WAL frames");
        frames
    }

    #[tokio::test]
    async fn w61_direct_cli_invalid_child_binding_fails_after_called_without_receipt() {
        for mode in [
            "missing",
            "malformed",
            "digest_mismatch",
            "extra_own_field",
            "unequal_generations",
        ] {
            let home = tempfile::tempdir().expect("W61 negative home");
            let (writer, join) = home_audit_writer(home.path());
            let database = home.path().join("code-map.sqlite");
            std::fs::write(&database, b"W61 fixture database").expect("W61 fixture DB");
            let config = codegraph_server_config(
                &std::env::current_exe().expect("W61 executable"),
                Some(database),
            );
            let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
                crate::permissions::AutonomyLevel::Full,
            )
            .expect("W61 Full policy");
            let error = invoke_cli_call_with_spawner_and_audit_sink(
                &config,
                "codegraph_relevant_files",
                serde_json::json!({"prompt":"wire","limit":1}),
                policy,
                1_700_000_061,
                crate::mcp::gate::McpAuditSink::Writer(&writer),
                home.path(),
                move |_| async move { w61_raw_metadata_child(mode).await },
            )
            .await
            .expect_err("invalid required child metadata must fail before a public result returns");
            assert!(matches!(error, GateError::Mcp(_)), "{mode}: {error:#}");
            let frames = w61_frame_types(home.path(), writer, join).await;
            assert_eq!(
                frames
                    .iter()
                    .filter(|(kind, _)| *kind == crate::wal::events::EVENT_TYPE_MCP_TOOL_CALLED)
                    .count(),
                1,
                "{mode}: called audit remains durable"
            );
            assert!(
                !frames.iter().any(|(kind, subtype)| *kind
                    == crate::wal::events::EVENT_TYPE_EXTENDED
                    && *subtype
                        == crate::wal::events::ExtendedSubtype::CodeMapRecallResolved as u8),
                "{mode}: no false prepared success receipt"
            );
        }
    }

    #[tokio::test]
    async fn w61_direct_cli_generated_is_error_returns_only_the_child_error_without_final_claim() {
        let home = tempfile::tempdir().expect("W61 generated error home");
        let (writer, join) = home_audit_writer(home.path());
        let database = home.path().join("code-map.sqlite");
        std::fs::write(&database, b"W61 fixture database").expect("W61 fixture DB");
        let config = codegraph_server_config(
            &std::env::current_exe().expect("W61 executable"),
            Some(database),
        );
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Full,
        )
        .expect("W61 Full policy");
        let result = invoke_cli_call_with_spawner_and_audit_sink(
            &config,
            "codegraph_relevant_files",
            serde_json::json!({"prompt":"wire","limit":1}),
            policy,
            1_700_000_061,
            crate::mcp::gate::McpAuditSink::Writer(&writer),
            home.path(),
            |_| async move { w61_raw_metadata_child("is_error").await },
        )
        .await
        .expect("generated isError remains a returned MCP error result");
        assert!(
            result.is_error,
            "only a child isError returns successfully; invalid metadata is a typed Err"
        );
        let frames = w61_frame_types(home.path(), writer, join).await;
        assert_eq!(
            frames
                .iter()
                .filter(|(kind, _)| *kind == crate::wal::events::EVENT_TYPE_MCP_TOOL_CALLED)
                .count(),
            1
        );
        assert!(!frames.iter().any(|(kind, subtype)| *kind
            == crate::wal::events::EVENT_TYPE_EXTENDED
            && *subtype == crate::wal::events::ExtendedSubtype::CodeMapRecallResolved as u8));
    }

    #[tokio::test]
    async fn w61_direct_cli_nongenerated_child_success_retains_legacy_no_receipt_behavior() {
        let home = tempfile::tempdir().expect("W61 external home");
        let (writer, join) = home_audit_writer(home.path());
        let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
            crate::permissions::AutonomyLevel::Full,
        )
        .expect("W61 Full policy");
        let result = invoke_cli_call_with_spawner_and_audit_sink(
            &callable_server(),
            "read",
            serde_json::json!({"legacy":true}),
            policy,
            1_700_000_061,
            crate::mcp::gate::McpAuditSink::Writer(&writer),
            home.path(),
            |_| async move { w61_raw_metadata_child("missing").await },
        )
        .await
        .expect("non-generated child result keeps ordinary direct CLI success");
        assert!(!result.is_error);
        let frames = w61_frame_types(home.path(), writer, join).await;
        assert_eq!(
            frames
                .iter()
                .filter(|(kind, _)| *kind == crate::wal::events::EVENT_TYPE_MCP_TOOL_CALLED)
                .count(),
            1
        );
        assert!(!frames.iter().any(|(kind, subtype)| *kind
            == crate::wal::events::EVENT_TYPE_EXTENDED
            && *subtype == crate::wal::events::ExtendedSubtype::CodeMapRecallResolved as u8));
    }

    #[test]
    fn w61_direct_cli_final_receipt_append_failure_returns_error_after_real_child_called_audit() {
        let _env = crate::test_env::lock();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("W61 runtime")
            .block_on(async {
                let home = tempfile::tempdir().expect("W61 final failure home");
                let database = home.path().join("code-map.sqlite");
                let root = home.path().join("canonical-root");
                crate::mcp::codegraph_server::w59_seed_real_sqlite_root(&database, &root, "final");
                let config = codegraph_server_config(
                    &std::env::current_exe().expect("W61 executable"),
                    Some(database),
                );
                let record = home.path().join("w61-final-child.jsonl");
                let previous_record = std::env::var_os("NEOTH_W56_CHILD_RECORD");
                let previous_cwd = std::env::var_os("NEOTH_W59_CHILD_CWD");
                unsafe {
                    std::env::set_var("NEOTH_W56_CHILD_RECORD", &record);
                    std::env::set_var("NEOTH_W59_CHILD_CWD", &root);
                }
                struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
                impl Drop for Restore {
                    fn drop(&mut self) {
                        unsafe {
                            match self.0.take() {
                                Some(value) => std::env::set_var("NEOTH_W56_CHILD_RECORD", value),
                                None => std::env::remove_var("NEOTH_W56_CHILD_RECORD"),
                            };
                            match self.1.take() {
                                Some(value) => std::env::set_var("NEOTH_W59_CHILD_CWD", value),
                                None => std::env::remove_var("NEOTH_W59_CHILD_CWD"),
                            };
                        }
                    }
                }
                let _restore = Restore(previous_record, previous_cwd);
                let (writer, join) = home_audit_writer(home.path());
                let policy = crate::permissions::AutonomyPolicySnapshot::builtin(
                    crate::permissions::AutonomyLevel::Full,
                )
                .expect("W61 Full policy");
                let error = invoke_cli_call_with_spawner_and_audit_sink(
                    &config,
                    "codegraph_relevant_files",
                    serde_json::json!({"prompt":"leaf_final","limit":1}),
                    policy,
                    1_700_000_061,
                    crate::mcp::gate::McpAuditSink::WriterFailFinal(
                        &writer,
                        "forced W61 final receipt append failure",
                    ),
                    home.path(),
                    |fixture| async move { McpClient::spawn(&fixture).await },
                )
                .await
                .expect_err("final receipt failure must prevent a successful public result");
                assert!(matches!(error, GateError::Wal(_)), "{error:#}");
                let events: Vec<serde_json::Value> = std::fs::read_to_string(&record)
                    .expect("real child record")
                    .lines()
                    .map(|line| serde_json::from_str(line).expect("child event"))
                    .collect();
                assert_eq!(
                    events
                        .iter()
                        .filter(|event| event["event"] == "tools/call")
                        .count(),
                    1,
                    "the actual child returned before final append failed"
                );
                let frames = w61_frame_types(home.path(), writer, join).await;
                assert_eq!(
                    frames
                        .iter()
                        .filter(|(kind, _)| *kind == crate::wal::events::EVENT_TYPE_MCP_TOOL_CALLED)
                        .count(),
                    1,
                    "called evidence is durable"
                );
                assert!(
                    !frames.iter().any(|(kind, subtype)| *kind
                        == crate::wal::events::EVENT_TYPE_EXTENDED
                        && *subtype
                            == crate::wal::events::ExtendedSubtype::CodeMapRecallResolved as u8),
                    "failed append cannot create a false receipt"
                );
            });
    }

    #[test]
    fn w61_direct_cli_receipt_uses_the_child_selected_root_for_empty_and_nonempty_results() {
        let _env = crate::test_env::lock();
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("W61 runtime").block_on(async {
            let home = tempfile::tempdir().expect("W61 two-root home"); let database = home.path().join("code-map.sqlite");
            let populated = home.path().join("populated-root"); let empty = home.path().join("empty-root");
            crate::mcp::codegraph_server::w59_seed_real_sqlite_root(&database, &populated, "populated");
            crate::mcp::codegraph_server::w59_seed_real_sqlite_root(&database, &empty, "empty");
            let config = codegraph_server_config(&std::env::current_exe().expect("W61 executable"), Some(database));
            let record = home.path().join("w61-two-root-child.jsonl"); let old_record = std::env::var_os("NEOTH_W56_CHILD_RECORD"); let old_cwd = std::env::var_os("NEOTH_W59_CHILD_CWD");
            unsafe { std::env::set_var("NEOTH_W56_CHILD_RECORD", &record); std::env::set_var("NEOTH_W59_CHILD_CWD", &populated); }
            struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
            impl Drop for Restore { fn drop(&mut self) { unsafe { match self.0.take() { Some(value) => std::env::set_var("NEOTH_W56_CHILD_RECORD", value), None => std::env::remove_var("NEOTH_W56_CHILD_RECORD") }; match self.1.take() { Some(value) => std::env::set_var("NEOTH_W59_CHILD_CWD", value), None => std::env::remove_var("NEOTH_W59_CHILD_CWD") }; } } }
            let _restore = Restore(old_record, old_cwd); let (writer, join) = home_audit_writer(home.path());
            let policy = crate::permissions::AutonomyPolicySnapshot::builtin(crate::permissions::AutonomyLevel::Full).expect("W61 Full policy");
            let populated_result = invoke_cli_call_with_spawner_and_audit_sink(&config, "codegraph_relevant_files", serde_json::json!({"prompt":"leaf_populated","limit":1}), policy.clone(), 1_700_000_061, crate::mcp::gate::McpAuditSink::Writer(&writer), home.path(), |fixture| async move { McpClient::spawn(&fixture).await }).await.expect("populated root result");
            unsafe { std::env::set_var("NEOTH_W59_CHILD_CWD", &empty); }
            let empty_result = invoke_cli_call_with_spawner_and_audit_sink(&config, "codegraph_relevant_files", serde_json::json!({"prompt":"not-present-anywhere","limit":1}), policy, 1_700_000_062, crate::mcp::gate::McpAuditSink::Writer(&writer), home.path(), |fixture| async move { McpClient::spawn(&fixture).await }).await.expect("empty root result");
            fn text(result: &ToolCallResult) -> &str {
                match &result.content[0] {
                    crate::mcp::client::McpContent::Text { text } => text,
                    _ => panic!("W61 text result"),
                }
            }
            assert!(!serde_json::from_str::<serde_json::Value>(text(&populated_result)).unwrap().as_array().unwrap().is_empty());
            assert!(serde_json::from_str::<serde_json::Value>(text(&empty_result)).unwrap().as_array().unwrap().is_empty(), "second actual root returns its empty map result");
            drop(writer); join.await.expect("W61 two-root writer exits");
            let mut roots = Vec::new();
            crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
                home.path(),
                crate::wal::scan::supported_home_scan_limits(),
                |_, frame| {
                    if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                        && frame.header.event_subtype == crate::wal::events::ExtendedSubtype::CodeMapRecallResolved as u8
                    {
                        roots.push(
                            serde_json::from_slice::<serde_json::Value>(frame.payload)
                                .expect("W61 receipt")["root_identity_hash_sha256"].clone(),
                        );
                    }
                    Ok(())
                },
            )
            .expect("scan authenticated W61 two-root WAL");
            assert_eq!(roots.len(), 2); assert_ne!(roots[0], roots[1], "receipt follows the actual child-selected canonical root, including empty result");
        });
    }
}
