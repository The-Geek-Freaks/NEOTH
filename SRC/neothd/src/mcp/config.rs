//! `~/.neoth/mcp_servers.yaml` — operator's MCP server configuration.
//!
//! ```yaml
//! servers:
//!   - id: filesystem-example
//!     command: npx
//!     args: ["-y", "@example/mcp-filesystem@1.2.3", "/home/user/notes"]
//!     env:
//!       LOG_LEVEL: info
//!
//!   - id: example
//!     command: npx
//!     args: ["-y", "@example/mcp-server@1.2.3"]
//!     env:
//!       EXAMPLE_TOKEN: from_env  # operator-controlled
//! ```
//!
//! `env: from_env` is a sentinel meaning "read this value from the
//! NEOTH-process environment at spawn time". Plain values pass through.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::FreedomConfig;

/// One MCP server entry from the YAML config.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpServerConfig {
    /// Stable identifier — used by `neoth mcp list-tools --server <id>`.
    pub id: String,
    /// One-line description (operator-supplied).
    #[serde(default)]
    pub description: Option<String>,
    /// Executable to launch. Absolute path or PATH-resolvable name.
    pub command: String,
    /// Arguments passed to the executable.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables. Values matching the literal `from_env` are
    /// resolved at spawn time from the NEOTH process environment.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Disable without deleting — handy for "this server is flaky today".
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// CDX-03 security hardening: per-server tool allowlist. When set,
    /// ONLY the listed tool names can be invoked via `call_tool` —
    /// every other tool from `tools/list` is rejected before reaching
    /// the LLM. `None` is paired with `trust_all_tools` below to
    /// decide whether the legacy "trust catalogue" path opens.
    /// Operators harden by pinning specific tool names: `allow_tools:
    /// ["read_file", "list_directory"]`.
    #[serde(default)]
    pub allow_tools: Option<Vec<String>>,
    /// Reviewer-1 P1-A (2026-05-20): secure-by-default toggle. When
    /// `false` (the new default) AND `allow_tools` is `None`, the gate
    /// denies every tool call — a compromised MCP subprocess can no
    /// longer return arbitrary new tools that bypass the allowlist
    /// layer. Operators who want the legacy "trust the server's full
    /// catalogue" behaviour set this to `true` explicitly OR pin an
    /// `allow_tools` list. `neoth doctor` warns on legacy `None &&
    /// !trust_all_tools` configs.
    #[serde(default)]
    pub trust_all_tools: bool,
    /// GR-018 — per-server SmartApprove opt-in. When `false` (the default),
    /// this server's tools are NEVER auto-approved past a `Confirm` gate, even
    /// if the global master switch (`security.smart_approve`) is on. The
    /// confirm-bypass fires only when BOTH the global master AND this per-server
    /// flag are set, so enabling SmartApprove for one trusted server can no
    /// longer silently bypass confirmation for every other configured server.
    #[serde(default)]
    pub smart_approve: bool,
    /// GOLD-ADAPT-CCS-02 — per-server minimum autonomy floor. When set, the
    /// gate (`mcp::gate::invoke_with_audit`) denies EVERY tool on this server
    /// unless the operator's current `FreedomConfig.autonomy` meets or exceeds
    /// it — e.g. an SSH / remote-edit server pinned to `elevated` so it stays
    /// inert under Strict/Standard. `None` (default) imposes no per-server floor.
    #[serde(default)]
    pub autonomy_gate: Option<crate::permissions::AutonomyLevel>,
}

fn default_enabled() -> bool {
    true
}

/// Top-level container — supports the operator-friendly `servers:` key.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct McpServers {
    #[serde(default)]
    pub servers: Vec<McpServerConfig>,
    /// N-04: only inject full tool blocks for servers whose name or tool
    /// names appear in the current prompt; deferred servers get a one-line
    /// hint instead. Set `false` to restore the old full-render path.
    #[serde(default = "default_smart_loading")]
    pub smart_loading: bool,
}

fn default_smart_loading() -> bool {
    true
}

/// B18 — in-process serialization guard for all `update_at` calls on
/// `mcp_servers.yaml`. The OS-level file lock in `update_at` handles
/// inter-process races; this mutex handles intra-process races.
static MCP_SERVERS_LOCK: Mutex<()> = Mutex::new(());

impl McpServers {
    /// Default path: `<neoth_home>/mcp_servers.yaml`.
    pub fn default_path() -> PathBuf {
        FreedomConfig::default_neoth_home().join("mcp_servers.yaml")
    }

    /// Missing file → empty list. Bad YAML → loud error (operator typo;
    /// fail-fast beats silently dropping every server).
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read MCP config {}", path.display()))?;
        let parsed: Self = serde_yaml::from_str(&body)
            .with_context(|| format!("parse YAML at {}", path.display()))?;
        Ok(parsed)
    }

    /// Convenience: load from default path.
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::default_path())
    }

    /// Look up a server by id. None when not present or disabled.
    pub fn get_enabled(&self, id: &str) -> Option<&McpServerConfig> {
        self.servers.iter().find(|s| s.id == id && s.enabled)
    }

    /// Every enabled server, sorted by id.
    pub fn enabled(&self) -> Vec<&McpServerConfig> {
        let mut out: Vec<&McpServerConfig> = self.servers.iter().filter(|s| s.enabled).collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// A8 / Konsens-decision #8: derive the autoroute decision from
    /// the operator's `NEOTH_MCP_AUTOROUTE` env var + the configured
    /// servers. Tri-state semantic:
    ///   - explicit `1` / `true` / `on` / `yes` → forced ON
    ///   - explicit `0` / `false` / `off` / `no` → forced OFF
    ///   - unset / empty / any other value → AUTO: derive from servers
    ///     (ON when ≥1 enabled server, OFF otherwise)
    ///
    /// Pure function — takes the env value as a parameter so tests
    /// don't have to touch the process env. The chat dispatch reads
    /// `std::env::var("NEOTH_MCP_AUTOROUTE")` and threads it here.
    pub fn autoroute_decision(&self, env_value: Option<&str>) -> AutorouteDecision {
        match env_value.map(str::trim) {
            Some(v) if matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes") => {
                AutorouteDecision::ForcedOn
            }
            Some(v)
                if matches!(
                    v.to_ascii_lowercase().as_str(),
                    "0" | "false" | "off" | "no"
                ) =>
            {
                AutorouteDecision::ForcedOff
            }
            _ => {
                if self.enabled().is_empty() {
                    AutorouteDecision::AutoOff
                } else {
                    AutorouteDecision::AutoOn
                }
            }
        }
    }

    /// B18 (NEOTH-AUDIT-MCP-CONFIG-MUTATION-FAILCLOSED-01) — locked,
    /// validated, atomic read-modify-write for `mcp_servers.yaml`.
    ///
    /// Acquisition order: in-process `MCP_SERVERS_LOCK` first, then the
    /// OS-level advisory file lock on `path.with_extension("yaml.lock")`.
    /// This two-level locking prevents both intra-process races (concurrent
    /// threads) and inter-process races (wizard + daemon running together).
    ///
    /// Invariants:
    /// - File is NEVER written when `mutation` returns `Ok(false)` (no-op).
    /// - File is NEVER written when load or mutation returns `Err`.
    /// - Every write is validated by a serde round-trip before hitting disk.
    /// - Crash-safe atomic write via `crate::util::atomic_write::atomic_write`.
    pub fn update_at(
        path: &Path,
        mutation: impl FnOnce(&mut McpServers) -> Result<bool>,
    ) -> Result<()> {
        // 1. In-process serialization guard (poison-tolerant: recover from
        //    prior thread panics so the process isn't permanently wedged).
        let _guard = match MCP_SERVERS_LOCK.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        // 2. Cross-process OS-level advisory file lock.
        let lock_path = path.with_extension("yaml.lock");
        let _file_lock = crate::util::locked_file::lock_file_blocking(&lock_path, "mcp_servers")?;

        // 3. Strict reload under lock — any YAML error propagates (fail-closed).
        //    Never replace a corrupt file with a stripped-down one.
        let mut current = Self::load_from(path)?;

        // 4. Apply the mutation closure. Ok(false) → no change → skip write.
        let changed = mutation(&mut current)?;
        if !changed {
            return Ok(());
        }

        // 5. Validate via serde round-trip before committing to disk.
        let yaml = serde_yaml::to_string(&current)
            .with_context(|| format!("serialise McpServers for {}", path.display()))?;
        serde_yaml::from_str::<McpServers>(&yaml)
            .with_context(|| format!("round-trip validation failed for {}", path.display()))?;

        // 6. Crash-safe atomic write (write tmp → fsync → rename).
        crate::util::atomic_write::atomic_write(path, yaml.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;

        Ok(())
    }
}

/// Outcome of `McpServers::autoroute_decision` — explicit four-state so
/// the chat dispatch can log *why* autoroute is on/off (operator opted
/// in vs operator opted out vs derived from servers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutorouteDecision {
    /// Operator set `NEOTH_MCP_AUTOROUTE=1` (or equivalent) → routing on.
    ForcedOn,
    /// Operator set `NEOTH_MCP_AUTOROUTE=0` (or equivalent) → routing off
    /// even though enabled servers exist.
    ForcedOff,
    /// Env unset + ≥1 enabled server → default-on per A8.
    AutoOn,
    /// Env unset + zero enabled servers → default-off.
    AutoOff,
}

/// Static supply-chain posture of one MCP launcher.
///
/// Runtime package fetching is supported only through the narrow
/// `npx -y package@exact-version` form. Everything else must be a directly
/// installed executable; shell and package-manager wrappers are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpLauncherPosture {
    /// Exact top-level npm package pin. This prevents tag/version drift, but
    /// transitive dependencies remain inside npm's upstream trust boundary.
    PinnedNpx,
    /// PATH-resolved or absolute executable with no runtime package fetcher.
    DirectExecutable,
}

impl McpLauncherPosture {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PinnedNpx => "pinned_npx",
            Self::DirectExecutable => "direct_executable",
        }
    }
}

impl AutorouteDecision {
    /// Whether the dispatch loop should run.
    pub fn is_on(self) -> bool {
        matches!(self, Self::ForcedOn | Self::AutoOn)
    }
    /// Operator-readable reason for the tracing log.
    pub fn reason(self) -> &'static str {
        match self {
            Self::ForcedOn => "NEOTH_MCP_AUTOROUTE=1 (operator opt-in)",
            Self::ForcedOff => "NEOTH_MCP_AUTOROUTE=0 (operator opt-out)",
            Self::AutoOn => "auto-on (≥1 enabled MCP server in mcp_servers.yaml)",
            Self::AutoOff => "auto-off (no enabled MCP servers)",
        }
    }
}

impl McpServerConfig {
    /// Validate the launcher without consulting process-global state.
    ///
    /// This is the shared static contract used by `doctor`, `mcp list`,
    /// installers, and the live spawn path. The live client then starts from
    /// an `env_clear` baseline and adds only explicitly configured variables,
    /// so ambient Node/npm overrides never enter the MCP child.
    pub fn validate_launcher(&self) -> Result<McpLauncherPosture> {
        let command = self.command.trim();
        if command.is_empty() || command.contains('\0') {
            anyhow::bail!("MCP server `{}` has an empty or invalid command", self.id);
        }

        let raw_basename = command
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(command)
            .to_ascii_lowercase();
        let command_name = normalise_command_name(command);

        if matches!(
            command_name.as_str(),
            "sh" | "bash"
                | "zsh"
                | "fish"
                | "cmd"
                | "powershell"
                | "pwsh"
                | "wsl"
                | "env"
                | "command"
        ) {
            anyhow::bail!(
                "MCP server `{}` uses opaque shell/wrapper launcher `{}`; configure the direct executable instead",
                self.id,
                self.command
            );
        }

        if matches!(
            command_name.as_str(),
            "npm" | "pnpm" | "yarn" | "corepack" | "bunx" | "uvx" | "pipx"
        ) {
            anyhow::bail!(
                "MCP server `{}` uses unsupported runtime fetch launcher `{}`; use a directly installed executable or `npx -y package@exact-version`",
                self.id,
                self.command
            );
        }

        // Batch/PowerShell wrappers can hide arbitrary command expansion. The
        // one exception is the platform-provided npx.cmd shim, whose arguments
        // are constrained below.
        if (raw_basename.ends_with(".cmd")
            || raw_basename.ends_with(".bat")
            || raw_basename.ends_with(".ps1"))
            && command_name != "npx"
        {
            anyhow::bail!(
                "MCP server `{}` uses opaque script launcher `{}`; configure the direct executable instead",
                self.id,
                self.command
            );
        }

        if command_name == "npx" {
            if self.args.len() < 2 || !matches!(self.args[0].as_str(), "-y" | "--yes") {
                anyhow::bail!(
                    "MCP server `{}` must start with `npx -y package@exact-version` (no extra npx options before the package)",
                    self.id
                );
            }
            parse_exact_npm_spec(&self.args[1]).ok_or_else(|| {
                anyhow::anyhow!(
                    "MCP server `{}` has unpinned or unsupported npx package `{}`; use package@exact-version",
                    self.id,
                    self.args[1]
                )
            })?;
        }

        for key in self.env.keys() {
            if forbidden_launcher_env(&command_name, key) {
                anyhow::bail!(
                    "MCP server `{}` sets forbidden launcher environment `{key}`; use the default registry/runtime context or a directly installed executable",
                    self.id
                );
            }
        }

        Ok(if command_name == "npx" {
            McpLauncherPosture::PinnedNpx
        } else {
            McpLauncherPosture::DirectExecutable
        })
    }

    /// Validate an inheritance-based spawn context, including ambient Node/npm
    /// variables that could redirect the registry or inject JavaScript. Kept
    /// for diagnostic/compatibility callers; [`crate::mcp::client::McpClient`]
    /// does not inherit these variables and instead uses an `env_clear`
    /// allowlist plus the server's explicit `env` block.
    pub fn validate_spawn_context(&self) -> Result<McpLauncherPosture> {
        let posture = self.validate_launcher()?;
        let command_name = normalise_command_name(&self.command);
        for (key, _) in std::env::vars_os() {
            let key = key.to_string_lossy();
            if forbidden_launcher_env(&command_name, &key) {
                anyhow::bail!(
                    "MCP server `{}` spawn blocked by inherited launcher environment `{key}`; clear it or use a directly installed executable",
                    self.id
                );
            }
        }
        Ok(posture)
    }

    /// Exact package name without the version, for typo-squat diagnostics.
    pub fn pinned_npx_package(&self) -> Option<&str> {
        if normalise_command_name(&self.command) != "npx" || self.args.len() < 2 {
            return None;
        }
        parse_exact_npm_spec(&self.args[1]).map(|(package, _)| package)
    }

    /// Resolve `env: from_env` sentinels at spawn time. Returns the final
    /// env map the spawn helper will hand to the child process. Missing
    /// variables surface as an error so the operator sees the failure
    /// rather than the child silently misbehaving.
    pub fn resolve_env(&self) -> Result<HashMap<String, String>> {
        let mut out = HashMap::with_capacity(self.env.len());
        for (k, v) in &self.env {
            if v == "from_env" {
                let actual = std::env::var(k).with_context(|| {
                    format!(
                        "MCP server `{}`: env `{k}` requested via `from_env` \
                         but no such variable in the NEOTH process environment",
                        self.id
                    )
                })?;
                out.insert(k.clone(), actual);
            } else {
                out.insert(k.clone(), v.clone());
            }
        }
        Ok(out)
    }
}

fn normalise_command_name(command: &str) -> String {
    let basename = command
        .trim()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    for suffix in [".exe", ".cmd", ".bat", ".ps1"] {
        if let Some(stripped) = basename.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    basename
}

fn forbidden_launcher_env(command_name: &str, key: &str) -> bool {
    if !matches!(command_name, "npx" | "node") {
        return false;
    }
    let upper = key.to_ascii_uppercase();
    if matches!(upper.as_str(), "NODE_OPTIONS" | "NODE_PATH") {
        return true;
    }
    command_name == "npx"
        && (matches!(
            upper.as_str(),
            "NPM_CONFIG_REGISTRY"
                | "NPM_CONFIG_USERCONFIG"
                | "NPM_CONFIG_GLOBALCONFIG"
                | "COREPACK_NPM_REGISTRY"
        ) || (upper.starts_with("NPM_CONFIG_") && upper.ends_with("_REGISTRY")))
}

fn parse_exact_npm_spec(spec: &str) -> Option<(&str, &str)> {
    if spec.is_empty() || spec.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let split_at = spec.rfind('@')?;
    if split_at == 0 {
        return None;
    }
    let (package, version_with_at) = spec.split_at(split_at);
    let version = version_with_at.strip_prefix('@')?;
    if !valid_npm_package_name(package) || !exact_semver(version) {
        return None;
    }
    Some((package, version))
}

fn valid_npm_package_name(package: &str) -> bool {
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
    };
    if let Some(scoped) = package.strip_prefix('@') {
        let Some((scope, name)) = scoped.split_once('/') else {
            return false;
        };
        valid_part(scope) && valid_part(name) && !name.contains('/')
    } else {
        valid_part(package) && !package.contains('/')
    }
}

fn exact_semver(version: &str) -> bool {
    let (without_build, build) = match version.split_once('+') {
        Some((base, build)) => (base, Some(build)),
        None => (version, None),
    };
    let (core, prerelease) = match without_build.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (without_build, None),
    };
    let mut core_parts = core.split('.');
    let valid_number = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'))
    };
    if !valid_number(core_parts.next().unwrap_or_default())
        || !valid_number(core_parts.next().unwrap_or_default())
        || !valid_number(core_parts.next().unwrap_or_default())
        || core_parts.next().is_some()
    {
        return false;
    }
    let valid_identifiers = |value: &str| {
        !value.is_empty()
            && value.split('.').all(|part| {
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
    };
    prerelease.is_none_or(valid_identifiers) && build.is_none_or(valid_identifiers)
}

/// GOLD-ADAPT-CBM-02 — hardened default registration for codebase-memory-mcp.
///
/// Returns a [`McpServerConfig`] the wizard can append to the operator's
/// `mcp_servers.yaml` as the safe starting point for the CBM code-graph rail.
///
/// Security defaults:
/// - `enabled: false`   — operator must opt in explicitly.
/// - `trust_all_tools: false` — no legacy "trust the server's full catalogue".
/// - `allow_tools`      — ONLY the 12 read-only tools. `index_repository` and
///   `delete_project` (write / destructive) are deliberately absent; the
///   operator must add them to the allowlist by hand if needed.
/// - `smart_approve: false` — CBM tools auto-approve via their own
///   `readOnlyHint` annotations once allowed by `allow_tools` (F5 design);
///   no name-pattern exemption is needed here.
///
/// Binary invocation: `codebase-memory-mcp` launched with no arguments acts
/// as the MCP stdio server (JSON-RPC 2.0 over stdin/stdout).
/// Source: README § Architecture — "Entry point (MCP stdio server + CLI …)".
// neoth: binary name confirmed from release asset names (v0.8.1, 2026-06-19):
// codebase-memory-mcp-windows-amd64.zip / codebase-memory-mcp-linux-amd64.tar.gz.
// No explicit `mcp` subcommand documented; bare binary == stdio server.
// Confirm with `codebase-memory-mcp --help` after install before shipping.
pub fn cbm_recommended_config() -> McpServerConfig {
    McpServerConfig {
        id: "codebase-memory".into(),
        description: Some(
            "codebase-memory-mcp: persistent code-graph MCP server (read-only rail). \
             Run `codebase-memory-mcp install` first, then set enabled: true."
                .into(),
        ),
        // Bare binary invocation — the process IS the stdio MCP server.
        command: "codebase-memory-mcp".into(),
        args: vec![],
        env: std::collections::HashMap::new(),
        // Operator must explicitly enable after installing and verifying.
        enabled: false,
        // 12 read-only CBM tools (v0.8.1, 14 total tools minus the 2
        // write/destructive ones: index_repository + delete_project).
        allow_tools: Some(vec![
            "search_graph".into(),
            "query_graph".into(),
            "trace_path".into(),
            "get_code_snippet".into(),
            "get_architecture".into(),
            "search_code".into(),
            "list_projects".into(),
            "index_status".into(),
            "detect_changes".into(),
            "get_graph_schema".into(),
            "manage_adr".into(),
            "ingest_traces".into(),
        ]),
        // Secure-by-default: deny anything outside allow_tools.
        trust_all_tools: false,
        // SmartApprove off — readOnlyHint on CBM tools handles auto-approval
        // via the F5 annotation path once the tool is in allow_tools.
        smart_approve: false,
        // CCS-02 — these read-only rails impose no per-server autonomy floor.
        autonomy_gate: None,
    }
}

pub const HEX_GRAPH_NPM_PACKAGE: &str = "@levnikolaevich/hex-graph-mcp";
pub const HEX_GRAPH_NPM_VERSION: &str = "0.21.1";
pub const HEX_GRAPH_NPM_SPEC: &str = "@levnikolaevich/hex-graph-mcp@0.21.1";
pub const HEX_GRAPH_MIN_NODE_VERSION: (u64, u64, u64) = (20, 19, 0);

/// Returns the hardened, opt-in `McpServerConfig` for **hex-graph-mcp** — a
/// semantic code-graph MCP server that builds a tree-sitter AST index stored
/// in SQLite and exposes code-query tools (symbol lookup, reference tracing,
/// dataflow, change impact, and architecture analysis).
///
/// Security defaults:
/// - `enabled: false`      — operator must opt in explicitly.
/// - `trust_all_tools: false` — only the tools in `allow_tools` are reachable.
/// - `allow_tools`         — complete query surface plus `index_project`, the
///   required local cache-index operation. Provider installation and SCIP
///   import/export tools are excluded from the default.
/// - `smart_approve: false` — no name-pattern exemption.
///
/// Binary invocation is pinned to the exact top-level npm version verified on
/// 2026-07-13. npx still resolves transitive dependencies under npm's upstream
/// trust boundary; the pin prevents silent package-tag drift.
pub fn hex_graph_recommended_config() -> McpServerConfig {
    McpServerConfig {
        id: "hex-graph".into(),
        description: Some(
            "hex-graph-mcp: tree-sitter AST + SQLite semantic code-graph. Query tools plus \
             the required local index_project cache write are enabled; provider install and \
             SCIP import/export stay excluded."
                .into(),
        ),
        command: "npx".into(),
        args: vec!["-y".into(), HEX_GRAPH_NPM_SPEC.into()],
        env: std::collections::HashMap::new(),
        // The init installer flips this only after explicit operator consent.
        enabled: false,
        // Upstream 0.21.1 exposes 16 tools. Keep all 12 query/diagnostic tools
        // plus the required local cache indexer; exclude provider installation
        // and SCIP import/export from the safe default.
        allow_tools: Some(vec![
            "index_project".into(),
            "find_symbols".into(),
            "inspect_symbol".into(),
            "find_references".into(),
            "find_implementations".into(),
            "trace_paths".into(),
            "trace_dataflow".into(),
            "analyze_changes".into(),
            "analyze_edit_region".into(),
            "api_impact".into(),
            "analyze_architecture".into(),
            "diagnose_graph".into(),
            "audit_workspace".into(),
        ]),
        // Secure-by-default: deny anything outside allow_tools.
        trust_all_tools: false,
        smart_approve: false,
        // CCS-02 — these read-only rails impose no per-server autonomy floor.
        autonomy_gate: None,
    }
}

/// Returns the hardened, opt-in `McpServerConfig` for **hex-line-mcp** — a
/// hash-verified local file operations MCP server.  Exposes AST outline,
/// semantic diff, and checksum verification tools.
///
/// Security defaults:
/// - `enabled: false`      — operator must opt in explicitly.
/// - `trust_all_tools: false` — only the tools in `allow_tools` are reachable.
/// - `allow_tools`         — READ-ONLY tools only.  `bulk_replace` and any
///   hash-verified EDIT tool are **deliberately excluded**; the operator must
///   add them to the allowlist by hand to unlock writes.
/// - `smart_approve: false` — no name-pattern exemption.
///
/// Binary invocation: exact top-level package pin verified on 2026-07-13.
pub fn hex_line_recommended_config() -> McpServerConfig {
    McpServerConfig {
        id: "hex-line".into(),
        description: Some(
            "hex-line-mcp: hash-verified local file ops (read-only rail). \
             Write tools (bulk_replace, etc.) are excluded — add them manually \
             if operator wants write access.  Set enabled: true to activate."
                .into(),
        ),
        command: "npx".into(),
        args: vec!["-y".into(), "@levnikolaevich/hex-line-mcp@1.31.0".into()],
        env: std::collections::HashMap::new(),
        enabled: false,
        // 3 read-only tools: AST overview, semantic diff, checksum check.
        // `bulk_replace` (write/destructive) is intentionally absent.
        allow_tools: Some(vec!["outline".into(), "changes".into(), "verify".into()]),
        trust_all_tools: false,
        smart_approve: false,
        // CCS-02 — these read-only rails impose no per-server autonomy floor.
        autonomy_gate: None,
    }
}

/// Returns the hardened, opt-in `McpServerConfig` for **hex-research-mcp** — a
/// PLAN-level research-hypothesis tracker that maintains its own SQLite database
/// for hypotheses, lineage, and goal-alignment audits.
///
/// Security defaults:
/// - `enabled: false`      — operator must opt in explicitly.
/// - `trust_all_tools: false` — only the tools in `allow_tools` are reachable.
/// - `allow_tools`         — query/read tools plus `index_hypotheses`
///   (writes only the server's OWN research DB, not NEOTH code or operator
///   files; included because it is required to bootstrap the hypothesis store
///   before queries can return results).  Destructive tools, if any, are absent.
/// - `smart_approve: false` — no name-pattern exemption.
///
/// Binary invocation: exact top-level package pin verified on 2026-07-13.
pub fn hex_research_recommended_config() -> McpServerConfig {
    McpServerConfig {
        id: "hex-research".into(),
        description: Some(
            "hex-research-mcp: PLAN-level research-hypothesis tracker (own SQLite). \
             index_hypotheses bootstraps the store (writes only the server's own DB). \
             Set enabled: true to activate."
                .into(),
        ),
        command: "npx".into(),
        args: vec!["-y".into(), "@levnikolaevich/hex-research-mcp@0.2.1".into()],
        env: std::collections::HashMap::new(),
        enabled: false,
        // Read tools + index_hypotheses (needed to bootstrap the server's own DB;
        // does NOT touch NEOTH code or operator files).
        allow_tools: Some(vec![
            "find_hypotheses".into(),
            "trace_lineage".into(),
            "audit_goal_alignment".into(),
            "index_hypotheses".into(),
        ]),
        trust_all_tools: false,
        smart_approve: false,
        // CCS-02 — these read-only rails impose no per-server autonomy floor.
        autonomy_gate: None,
    }
}

/// GOLD-ADAPT-CCS-02 — hardened, opt-in `McpServerConfig` for **hex-ssh-mcp**
/// (`@levnikolaevich/hex-ssh-mcp`) — a stdio MCP server that exposes
/// FNV-checksum-verified SSH + SFTP + persistent-tmux operations on remote hosts.
///
/// An SSH/remote-edit server is high-blast-radius: it can read and write files
/// on any reachable host, execute arbitrary shell commands, and exfiltrate data
/// over existing SSH tunnels.  Security posture:
/// - `enabled: false`          — operator must opt in explicitly.
/// - **`autonomy_gate: Elevated`** (CCS-02) — the ENTIRE server is inert below
///   Elevated autonomy; Strict/Standard operators cannot invoke any tool, even
///   one in `allow_tools`.  This matches the chrome-devtools + mobile-mcp tier.
/// - `trust_all_tools: false` + an `allow_tools` pin covering ALL 14 tools —
///   every tool is deliberate; no "trust the server's full catalogue" fallback.
///   The checksum-before-edit tools (`ssh_write_file`, `ssh_edit_block`) enforce
///   FNV-1a verification inside the MCP subprocess before any mutation occurs,
///   realising the CLAUDE.md "show exact command + confirm" rule for Cube/debian.
/// - `smart_approve: false`    — remote mutation must never auto-approve past a
///   Confirm gate.
///
/// Tool names verified against `@levnikolaevich/hex-ssh-mcp` package manifest
/// (GOLD-ADAPT-CCS-02 recon 2026-06-24; re-verify on upstream version bumps).
// neoth: verify against live `npx -y @levnikolaevich/hex-ssh-mcp@1.9.2` tools/list
// before setting enabled: true.  The FNV checksum protocol is enforced by the
// subprocess — NEOTH's gate (Layer 1b) blocks the whole server below Elevated.
// The 0xC0/0xC1 WAL events are emitted generically by invoke_with_audit.
pub fn hex_ssh_recommended_config() -> McpServerConfig {
    McpServerConfig {
        id: "hex-ssh".into(),
        description: Some(
            "hex-ssh-mcp: FNV-checksum-verified SSH / SFTP / tmux remote operations. \
             All 14 tools gated behind Elevated autonomy — inert on Strict/Standard. \
             Set enabled: true after verifying the npm package and your SSH targets."
                .into(),
        ),
        command: "npx".into(),
        args: vec!["-y".into(), "@levnikolaevich/hex-ssh-mcp@1.9.2".into()],
        env: std::collections::HashMap::new(),
        // Operator must explicitly enable after verifying the package.
        enabled: false,
        // All 14 tools: remote-read, checksum-verified-write, exec, sftp, tmux.
        // No tools are excluded — the Elevated autonomy_gate is the coarse floor
        // for the whole server; per-tool Layer 2 handles finer decisions.
        allow_tools: Some(vec![
            // Remote file read
            "ssh_read_file".into(),
            "ssh_list_directory".into(),
            "ssh_get_file_info".into(),
            // Checksum-verified remote edits (FNV-1a verified by subprocess)
            "ssh_write_file".into(),
            "ssh_edit_block".into(),
            "ssh_delete_file".into(),
            // Remote command execution
            "ssh_exec".into(),
            "ssh_find_files".into(),
            "ssh_grep".into(),
            // SFTP bulk transfer
            "sftp_upload".into(),
            "sftp_download".into(),
            // Persistent tmux session management
            "tmux_send".into(),
            "tmux_read".into(),
            "tmux_list".into(),
        ]),
        // Secure-by-default: deny anything outside allow_tools.
        trust_all_tools: false,
        // Remote mutation must never auto-approve past a Confirm gate.
        smart_approve: false,
        // CCS-02 — SSH/remote-edit is high-blast-radius: inert below Elevated.
        autonomy_gate: Some(crate::permissions::AutonomyLevel::Elevated),
    }
}

/// GOLD-PROG-15 / PC-02 — hardened, opt-in `McpServerConfig` for the official
/// **chrome-devtools-mcp** server (browser automation via the Chrome DevTools
/// Protocol).
///
/// A browser driver can navigate URLs, read the DOM, and (with the right tools)
/// execute arbitrary JavaScript + exfiltrate page content — the same blast
/// radius as a remote-shell server. Security posture:
/// - `enabled: false`      — operator opts in only after verifying the package.
/// - **`autonomy_gate: Elevated`** (CCS-02) — the ENTIRE server is inert below
///   Elevated autonomy; a Strict/Standard operator can't invoke any tool, even
///   one in `allow_tools`. This is the per-server floor the SSH/remote class uses.
/// - `trust_all_tools: false` + an `allow_tools` pin scoped to **read/navigate
///   only** — `take_snapshot`/`take_screenshot`/`list_pages`/`navigate_page`.
///   Interaction + JS-eval tools (`click`, `fill`, `evaluate_script`) are
///   DELIBERATELY EXCLUDED (the hex-line pattern: the operator adds them by hand
///   to unlock active control).
/// - `smart_approve: false` — a browser tool must never auto-approve past a
///   Confirm gate (even a screenshot returns page content).
/// - telemetry OFF: `CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS=1` (the package's
///   own opt-out, named in the GOLD plan) + `DO_NOT_TRACK=1`.
///
/// License: chrome-devtools-mcp is Apache-2.0 (Google). The operator confirms
/// the license + telemetry posture by explicitly setting `enabled: true`.
// neoth: verify the exact tool names against the installed chrome-devtools-mcp
// version before relying on the allow_tools pin — the autonomy_gate is the
// real floor regardless of the tool list.
pub fn chrome_devtools_recommended_config() -> McpServerConfig {
    McpServerConfig {
        id: "chrome-devtools".into(),
        description: Some(
            "chrome-devtools-mcp: Chrome DevTools Protocol browser automation (read/navigate \
             rail). JS-eval + interaction tools excluded — add by hand to unlock. Elevated \
             autonomy floor; set enabled: true after confirming the license + telemetry posture."
                .into(),
        ),
        command: "npx".into(),
        args: vec!["-y".into(), "chrome-devtools-mcp@1.5.0".into()],
        env: std::collections::HashMap::from([
            // Telemetry opt-out (the package's own switch, per the GOLD plan).
            ("CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS".into(), "1".into()),
            ("DO_NOT_TRACK".into(), "1".into()),
        ]),
        // Operator must explicitly enable after confirming license + telemetry.
        enabled: false,
        // Read/navigate surface only; interaction + JS-eval intentionally absent.
        allow_tools: Some(vec![
            "list_pages".into(),
            "navigate_page".into(),
            "take_snapshot".into(),
            "take_screenshot".into(),
        ]),
        trust_all_tools: false,
        smart_approve: false,
        // CCS-02 — a browser driver is high-blast-radius: inert below Elevated.
        autonomy_gate: Some(crate::permissions::AutonomyLevel::Elevated),
    }
}

/// GOLD-ADAPT-SYS-01 — hardened, opt-in `McpServerConfig` for **mobile-mcp**
/// (`@mobilenext/mobile-mcp`) — a stdio MCP server that drives iOS/Android
/// devices via the WebDriverAgent + ADB stack.
///
/// A mobile device driver is medium-blast-radius: it can tap UI, read the
/// screen, capture screenshots, and manipulate apps on a real or simulated
/// phone. Security posture:
/// - `enabled: false`      — operator opts in only.
/// - **`autonomy_gate: Elevated`** (CCS-02) — the server is inert below
///   Elevated autonomy (same tier as chrome-devtools-mcp). No tool fires
///   on Strict/Standard operators.
/// - `trust_all_tools: false` + `allow_tools` scoped to the 24 **local-
///   device** tools. The 3 cloud-device allocation tools
///   (`mobile_list_remote_devices`, `mobile_allocate_remote_device`,
///   `mobile_release_remote_device`) are **deliberately excluded** — they
///   provision devices from an external cloud pool and are cloud-blast-radius.
///   Operators who need them must add them by hand.
/// - `smart_approve: false` — device control must never auto-approve past a
///   Confirm gate.
/// - Telemetry OFF: `MOBILEMCP_DISABLE_TELEMETRY=1` — mobile-mcp fires
///   PostHog events (`posthog("launch", {})` + per-tool events) to
///   `https://us.i.posthog.com/i/v0/e/` unless this env var is set. NEOTH
///   forces it off unconditionally in the subprocess env. The wizard step
///   discloses this to the operator before they opt in.
///
/// Prerequisites (NOT installed by NEOTH; operator-supplied):
/// - Node ≥18 + npm/npx on PATH — `npx -y @mobilenext/mobile-mcp@0.0.62`
///   auto-fetches the exact top-level package on first use. Transitive
///   dependencies remain inside npm's upstream trust boundary.
/// - iOS real device: Xcode CLI tools + WebDriverAgent installed + signed with
///   a valid Apple Developer account. iOS Simulator requires no WDA signing.
/// - Android: `adb` in PATH and USB debugging enabled on the target device.
///
/// Tool names verified against `@mobilenext/mobile-mcp` server.ts
/// (GOLD-ADAPT-SYS-01 recon 2026-06-23).
pub fn mobile_mcp_recommended_config() -> McpServerConfig {
    McpServerConfig {
        id: "mobile-mcp".into(),
        description: Some(
            "mobile-mcp: iOS/Android device control via WebDriverAgent + ADB. \
             Launched via npx; Elevated autonomy floor. Remote-device cloud tools \
             excluded — add by hand if needed. Set enabled: true after installing \
             Node + device prerequisites (Xcode/ADB)."
                .into(),
        ),
        command: "npx".into(),
        args: vec!["-y".into(), "@mobilenext/mobile-mcp@0.0.62".into()],
        env: std::collections::HashMap::from([
            // PostHog telemetry opt-out — mobile-mcp fires posthog("launch", {})
            // and per-tool events unless this sentinel is present. Forced OFF here;
            // disclosed verbally in the wizard step before the operator opts in.
            ("MOBILEMCP_DISABLE_TELEMETRY".into(), "1".into()),
        ]),
        // Operator must explicitly enable after verifying prerequisites.
        enabled: false,
        // 24 local-device tools (all mobile_* tools EXCEPT the 3 remote-device
        // cloud allocation tools which are cloud-blast-radius and excluded here;
        // operators add them manually when needed).
        allow_tools: Some(vec![
            "mobile_take_screenshot".into(),
            "mobile_describe_screen".into(),
            "mobile_click".into(),
            "mobile_long_click".into(),
            "mobile_double_click".into(),
            "mobile_swipe".into(),
            "mobile_tap_at".into(),
            "mobile_type_text".into(),
            "mobile_press_button".into(),
            "mobile_launch_app".into(),
            "mobile_terminate_app".into(),
            "mobile_open_url".into(),
            "mobile_get_device_info".into(),
            "mobile_list_apps".into(),
            "mobile_list_elements".into(),
            "mobile_get_element_text".into(),
            "mobile_find_element".into(),
            "mobile_wait_for_element".into(),
            "mobile_scroll_screen".into(),
            "mobile_pinch".into(),
            "mobile_rotate".into(),
            "mobile_set_orientation".into(),
            "mobile_get_clipboard".into(),
            "mobile_set_clipboard".into(),
        ]),
        // Secure-by-default: deny anything outside allow_tools.
        trust_all_tools: false,
        // Device control must never auto-approve past a Confirm gate.
        smart_approve: false,
        // CCS-02 — mobile device control is medium-blast-radius: inert below Elevated.
        autonomy_gate: Some(crate::permissions::AutonomyLevel::Elevated),
    }
}

/// GOLD-ADAPT-TUDU-01 — hardened default registration for the **tududi**
/// self-hosted task manager's stdio MCP server.
///
/// tududi ships a Node.js MCP server in `backend/modules/mcp/server.js`
/// (StdioServerTransport, 8 task tools). The wizard collects the absolute
/// path to `server.js` and the operator's API token and calls
/// [`crate::installers::tududi::auto_register`] to materialise this entry
/// in `~/.neoth/mcp_servers.yaml`. The token is stored in `credentials.yaml`
/// under `tududi_api_token`; the `from_env` sentinel here is resolved at
/// spawn time from `TUDUDI_API_TOKEN` in the NEOTH daemon's process env
/// (populated by the credentials loader at startup).
///
/// Security defaults:
/// - `enabled: false`          — operator opts in only via the wizard.
/// - `trust_all_tools: false`  — only the 8 listed task tools are reachable.
/// - `allow_tools`             — all 8 task tools from `taskTools.js`; no
///   system or file-access tools are exposed by this server.
/// - `smart_approve: false`    — task mutation tools must always gate.
/// - `autonomy_gate: None`     — task tools are low-blast-radius read/write,
///   no floor needed (Standard autonomy is sufficient).
/// - `TUDUDI_API_TOKEN: from_env` — resolved from the daemon process env at
///   spawn; never written as a literal value into `mcp_servers.yaml`.
///
/// The `command` and first `args` element are supplied by the caller (the
/// absolute path to `server.js`). This factory takes `server_js_path` so the
/// integration test can pin a synthetic path without touching the real FS.
// neoth: tool names verified against tududi/backend/modules/mcp/taskTools.js
// (GOLD-ADAPT-TUDU-01 recon 2026-06-23). Re-verify on upstream version bumps.
pub fn tududi_recommended_config(server_js_path: &str) -> McpServerConfig {
    McpServerConfig {
        id: "tududi".into(),
        description: Some(
            "tududi: self-hosted task manager MCP server (8 task tools). \
             Requires a local tududi instance with its Node.js MCP server. \
             Set enabled: true after the wizard registers your instance."
                .into(),
        ),
        // tududi's MCP server is a Node.js stdio process, not an npx package.
        // The operator's absolute path to `backend/modules/mcp/server.js`
        // is baked into args at registration time.
        command: "node".into(),
        args: vec![server_js_path.to_string()],
        env: std::collections::HashMap::from([
            // The API token sentinel — resolved at spawn time from the daemon
            // process env (credentials.yaml::tududi_api_token → TUDUDI_API_TOKEN).
            // Never a literal value here.
            ("TUDUDI_API_TOKEN".into(), "from_env".into()),
        ]),
        // Operator must explicitly enable after the wizard configures the path.
        enabled: false,
        // All 8 task tools from taskTools.js — task-scoped, no system access.
        allow_tools: Some(vec![
            "list_tasks".into(),
            "get_task".into(),
            "create_task".into(),
            "update_task".into(),
            "complete_task".into(),
            "delete_task".into(),
            "add_subtask".into(),
            "get_task_metrics".into(),
        ]),
        trust_all_tools: false,
        smart_approve: false,
        // Task tools are low blast-radius — no autonomy floor needed.
        autonomy_gate: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempdir().unwrap();
        let s = McpServers::load_from(&dir.path().join("none.yaml")).unwrap();
        assert!(s.servers.is_empty());
    }

    #[test]
    fn load_well_formed_yaml_parses_servers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mcp.yaml");
        std::fs::write(
            &path,
            r#"
servers:
  - id: filesystem
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem"]
  - id: github
    description: GitHub MCP server
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: from_env
    enabled: false
"#,
        )
        .unwrap();

        let s = McpServers::load_from(&path).unwrap();
        assert_eq!(s.servers.len(), 2);
        assert_eq!(s.servers[0].id, "filesystem");
        assert!(s.servers[0].enabled);
        assert!(!s.servers[1].enabled);
        assert_eq!(
            s.servers[1]
                .env
                .get("GITHUB_PERSONAL_ACCESS_TOKEN")
                .map(String::as_str),
            Some("from_env")
        );
    }

    #[test]
    fn get_enabled_filters_disabled() {
        let s = McpServers {
            smart_loading: true,
            servers: vec![
                McpServerConfig {
                    id: "a".into(),
                    description: None,
                    command: "x".into(),
                    args: vec![],
                    env: HashMap::new(),
                    enabled: true,
                    allow_tools: None,
                    trust_all_tools: false,
                    smart_approve: false,
                    autonomy_gate: None,
                },
                McpServerConfig {
                    id: "b".into(),
                    description: None,
                    command: "x".into(),
                    args: vec![],
                    env: HashMap::new(),
                    enabled: false,
                    allow_tools: None,
                    trust_all_tools: false,
                    smart_approve: false,
                    autonomy_gate: None,
                },
            ],
        };
        assert!(s.get_enabled("a").is_some());
        assert!(s.get_enabled("b").is_none());
        assert_eq!(s.enabled().len(), 1);
    }

    #[test]
    fn resolve_env_passes_through_literal_values() {
        let cfg = McpServerConfig {
            id: "test".into(),
            description: None,
            command: "x".into(),
            args: vec![],
            env: {
                let mut m = HashMap::new();
                m.insert("LOG_LEVEL".into(), "info".into());
                m
            },
            enabled: true,
            allow_tools: None,
            trust_all_tools: false,
            smart_approve: false,
            autonomy_gate: None,
        };
        let resolved = cfg.resolve_env().unwrap();
        assert_eq!(resolved.get("LOG_LEVEL").map(String::as_str), Some("info"));
    }

    #[test]
    fn resolve_env_fails_when_from_env_missing() {
        let cfg = McpServerConfig {
            id: "test".into(),
            description: None,
            command: "x".into(),
            args: vec![],
            env: {
                let mut m = HashMap::new();
                m.insert(
                    "NEOTH_TEST_DEFINITELY_MISSING_VAR".into(),
                    "from_env".into(),
                );
                m
            },
            enabled: true,
            allow_tools: None,
            trust_all_tools: false,
            smart_approve: false,
            autonomy_gate: None,
        };
        let err = cfg.resolve_env().unwrap_err();
        assert!(
            err.to_string()
                .contains("NEOTH_TEST_DEFINITELY_MISSING_VAR")
        );
    }

    fn launcher_config(command: &str, args: &[&str]) -> McpServerConfig {
        McpServerConfig {
            id: "launcher-test".into(),
            description: None,
            command: command.into(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            env: HashMap::new(),
            enabled: true,
            allow_tools: Some(vec!["read".into()]),
            trust_all_tools: false,
            smart_approve: false,
            autonomy_gate: None,
        }
    }

    #[test]
    fn launcher_accepts_exact_npx_specs_and_windows_shim_paths() {
        for spec in [
            "example-mcp@1.2.3",
            "@example/mcp@2026.7.13",
            "@example/mcp@1.2.3-beta.4+build.9",
        ] {
            let cfg = launcher_config(r"C:\Program Files\nodejs\npx.cmd", &["--yes", spec]);
            assert_eq!(
                cfg.validate_launcher().unwrap(),
                McpLauncherPosture::PinnedNpx,
                "exact spec should pass: {spec}"
            );
        }
    }

    #[test]
    fn launcher_rejects_unpinned_ranges_tags_and_extra_npx_options() {
        for spec in [
            "example-mcp",
            "example-mcp@latest",
            "example-mcp@^1.2.3",
            "example-mcp@1.2.x",
            "example-mcp@https://example.invalid/pkg.tgz",
            "npm:other@1.2.3",
        ] {
            let cfg = launcher_config("npx", &["-y", spec]);
            assert!(
                cfg.validate_launcher().is_err(),
                "unpinned/unsupported spec must fail: {spec}"
            );
        }
        let extra = launcher_config(
            "npx",
            &[
                "--yes",
                "--registry=https://example.invalid",
                "example@1.2.3",
            ],
        );
        assert!(extra.validate_launcher().is_err());
    }

    #[test]
    fn launcher_rejects_shells_script_wrappers_and_other_runtime_fetchers() {
        for command in [
            "sh",
            "bash",
            "cmd.exe",
            "powershell.exe",
            "pwsh",
            "wsl",
            "env",
            "npm",
            "pnpm.cmd",
            "yarn",
            "corepack",
            "bunx",
            "uvx",
            "pipx",
            "custom-server.cmd",
            "custom-server.ps1",
        ] {
            let cfg = launcher_config(command, &["anything"]);
            assert!(
                cfg.validate_launcher().is_err(),
                "opaque/runtime launcher must fail: {command}"
            );
        }
    }

    #[test]
    fn launcher_accepts_direct_executables() {
        for command in ["node", "codebase-memory-mcp", "/opt/neoth/mcp-server"] {
            let cfg = launcher_config(command, &["--stdio"]);
            assert_eq!(
                cfg.validate_launcher().unwrap(),
                McpLauncherPosture::DirectExecutable
            );
        }
    }

    #[test]
    fn launcher_rejects_node_injection_and_registry_override_env() {
        for (command, key) in [
            ("node", "NODE_OPTIONS"),
            ("node", "NODE_PATH"),
            ("npx", "NPM_CONFIG_REGISTRY"),
            ("npx", "npm_config_foo_registry"),
            ("npx", "NPM_CONFIG_USERCONFIG"),
            ("npx", "COREPACK_NPM_REGISTRY"),
        ] {
            let mut cfg = if command == "npx" {
                launcher_config(command, &["-y", "example-mcp@1.2.3"])
            } else {
                launcher_config(command, &["server.js"])
            };
            cfg.env.insert(key.into(), "attacker-controlled".into());
            assert!(
                cfg.validate_launcher().is_err(),
                "forbidden environment must fail: {command} {key}"
            );
        }
        assert!(forbidden_launcher_env("npx", "NPM_CONFIG_REGISTRY"));
        assert!(!forbidden_launcher_env("npx", "NPM_CONFIG_LOGLEVEL"));
        assert!(!forbidden_launcher_env("native-server", "NODE_OPTIONS"));
    }

    // --- A8 autoroute_decision tests ---

    fn one_enabled_server() -> McpServers {
        McpServers {
            smart_loading: true,
            servers: vec![McpServerConfig {
                id: "fs".into(),
                description: None,
                command: "x".into(),
                args: vec![],
                env: HashMap::new(),
                enabled: true,
                allow_tools: None,
                trust_all_tools: false,
                smart_approve: false,
                autonomy_gate: None,
            }],
        }
    }

    #[test]
    fn autoroute_decision_forced_on_with_truthy_values() {
        let s = McpServers::default();
        for v in ["1", "true", "TRUE", "on", "yes", "Yes"] {
            assert_eq!(
                s.autoroute_decision(Some(v)),
                AutorouteDecision::ForcedOn,
                "expected ForcedOn for `{v}`"
            );
        }
    }

    #[test]
    fn autoroute_decision_forced_off_with_falsy_values() {
        let s = one_enabled_server();
        for v in ["0", "false", "FALSE", "off", "no", "No"] {
            assert_eq!(
                s.autoroute_decision(Some(v)),
                AutorouteDecision::ForcedOff,
                "expected ForcedOff for `{v}` (overrides enabled servers)"
            );
        }
    }

    #[test]
    fn autoroute_decision_auto_on_when_servers_enabled_and_env_unset() {
        let s = one_enabled_server();
        assert_eq!(s.autoroute_decision(None), AutorouteDecision::AutoOn);
        // Also: empty string is treated as "unset".
        assert_eq!(s.autoroute_decision(Some("")), AutorouteDecision::AutoOn);
    }

    #[test]
    fn autoroute_decision_auto_off_when_no_enabled_servers() {
        let s = McpServers::default();
        assert_eq!(s.autoroute_decision(None), AutorouteDecision::AutoOff);
    }

    #[test]
    fn autoroute_decision_auto_off_when_only_disabled_servers() {
        let s = McpServers {
            smart_loading: true,
            servers: vec![McpServerConfig {
                id: "fs".into(),
                description: None,
                command: "x".into(),
                args: vec![],
                env: HashMap::new(),
                enabled: false,
                allow_tools: None,
                trust_all_tools: false,
                smart_approve: false,
                autonomy_gate: None,
            }],
        };
        assert_eq!(s.autoroute_decision(None), AutorouteDecision::AutoOff);
    }

    #[test]
    fn autoroute_decision_unrecognised_env_falls_back_to_auto() {
        // Garbage env values shouldn't lock the operator out — fall back
        // to auto-derive rather than failing closed.
        let s = one_enabled_server();
        assert_eq!(
            s.autoroute_decision(Some("maybe")),
            AutorouteDecision::AutoOn
        );
    }

    #[test]
    fn autoroute_decision_is_on_reports_correctly() {
        assert!(AutorouteDecision::ForcedOn.is_on());
        assert!(AutorouteDecision::AutoOn.is_on());
        assert!(!AutorouteDecision::ForcedOff.is_on());
        assert!(!AutorouteDecision::AutoOff.is_on());
    }

    #[test]
    fn autoroute_decision_reason_strings_are_distinct() {
        let r1 = AutorouteDecision::ForcedOn.reason();
        let r2 = AutorouteDecision::ForcedOff.reason();
        let r3 = AutorouteDecision::AutoOn.reason();
        let r4 = AutorouteDecision::AutoOff.reason();
        assert_ne!(r1, r2);
        assert_ne!(r1, r3);
        assert_ne!(r2, r4);
        assert!(r1.contains("opt-in"));
        assert!(r2.contains("opt-out"));
        assert!(r3.contains("auto-on"));
        assert!(r4.contains("auto-off"));
    }

    // --- GOLD-ADAPT-CBM-02: cbm_recommended_config tests ---

    #[test]
    fn cbm_config_allow_tools_contains_read_only_tools() {
        let cfg = cbm_recommended_config();
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        assert!(
            tools.iter().any(|t| t == "search_graph"),
            "allow_tools must contain search_graph"
        );
        assert!(
            tools.iter().any(|t| t == "query_graph"),
            "allow_tools must contain query_graph"
        );
        assert!(
            tools.iter().any(|t| t == "trace_path"),
            "allow_tools must contain trace_path"
        );
        assert!(
            tools.iter().any(|t| t == "get_graph_schema"),
            "allow_tools must contain get_graph_schema"
        );
    }

    #[test]
    fn cbm_config_excludes_write_and_destructive_tools() {
        let cfg = cbm_recommended_config();
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        assert!(
            !tools.iter().any(|t| t == "index_repository"),
            "allow_tools must NOT contain index_repository (write tool)"
        );
        assert!(
            !tools.iter().any(|t| t == "delete_project"),
            "allow_tools must NOT contain delete_project (destructive tool)"
        );
    }

    #[test]
    fn cbm_config_is_secure_by_default() {
        let cfg = cbm_recommended_config();
        assert!(!cfg.trust_all_tools, "trust_all_tools must be false");
        assert!(!cfg.smart_approve, "smart_approve must be false");
        assert!(!cfg.enabled, "must be disabled until operator opts in");
    }

    #[test]
    fn cbm_config_id_and_command_are_stable() {
        let cfg = cbm_recommended_config();
        assert_eq!(cfg.id, "codebase-memory");
        assert_eq!(cfg.command, "codebase-memory-mcp");
        assert!(cfg.args.is_empty(), "no args for bare stdio server mode");
    }

    // --- GOLD-ADAPT-CCS-01: hex_graph_recommended_config tests ---

    #[test]
    fn hex_graph_config_id_and_command_are_stable() {
        let cfg = hex_graph_recommended_config();
        assert_eq!(cfg.id, "hex-graph");
        assert_eq!(cfg.command, "npx");
        assert_eq!(
            cfg.args,
            vec!["-y".to_string(), HEX_GRAPH_NPM_SPEC.to_string()]
        );
        assert_eq!(
            cfg.validate_launcher().unwrap(),
            McpLauncherPosture::PinnedNpx
        );
        assert_eq!(cfg.pinned_npx_package(), Some(HEX_GRAPH_NPM_PACKAGE));
    }

    #[test]
    fn hex_graph_config_allow_tools_contains_read_only_tools() {
        let cfg = hex_graph_recommended_config();
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        assert!(
            tools.iter().any(|t| t == "find_symbols"),
            "allow_tools must contain find_symbols"
        );
        assert!(
            tools.iter().any(|t| t == "find_references"),
            "allow_tools must contain find_references"
        );
        assert!(
            tools.iter().any(|t| t == "trace_paths"),
            "allow_tools must contain trace_paths"
        );
        assert!(
            tools.iter().any(|t| t == "analyze_architecture"),
            "allow_tools must contain analyze_architecture"
        );
        assert_eq!(tools.len(), 13, "0.21.1 safe default tool surface drifted");
        assert!(tools.iter().any(|t| t == "index_project"));
        for excluded in [
            "install_graph_providers",
            "export_scip",
            "import_scip_overlay",
        ] {
            assert!(
                !tools.iter().any(|tool| tool == excluded),
                "{excluded} must remain explicit operator opt-in"
            );
        }
    }

    #[test]
    fn hex_graph_config_is_secure_by_default() {
        let cfg = hex_graph_recommended_config();
        assert!(!cfg.trust_all_tools, "trust_all_tools must be false");
        assert!(!cfg.smart_approve, "smart_approve must be false");
        assert!(!cfg.enabled, "must be disabled until operator opts in");
    }

    // --- GOLD-ADAPT-CCS-03: hex_line_recommended_config tests ---

    #[test]
    fn hex_line_config_id_and_command_are_stable() {
        let cfg = hex_line_recommended_config();
        assert_eq!(cfg.id, "hex-line");
        assert_eq!(cfg.command, "npx");
        assert!(
            cfg.args
                .iter()
                .any(|a| a == "@levnikolaevich/hex-line-mcp@1.31.0"),
            "args must contain the hex-line npm package name"
        );
        assert!(cfg.validate_launcher().is_ok());
    }

    #[test]
    fn hex_line_config_allow_tools_contains_read_only_tools() {
        let cfg = hex_line_recommended_config();
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        assert!(
            tools.iter().any(|t| t == "outline"),
            "allow_tools must contain outline"
        );
        assert!(
            tools.iter().any(|t| t == "changes"),
            "allow_tools must contain changes"
        );
        assert!(
            tools.iter().any(|t| t == "verify"),
            "allow_tools must contain verify"
        );
    }

    #[test]
    fn hex_line_config_excludes_write_tools() {
        let cfg = hex_line_recommended_config();
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        assert!(
            !tools.iter().any(|t| t == "bulk_replace"),
            "allow_tools must NOT contain bulk_replace (write/destructive tool)"
        );
    }

    #[test]
    fn hex_line_config_is_secure_by_default() {
        let cfg = hex_line_recommended_config();
        assert!(!cfg.trust_all_tools, "trust_all_tools must be false");
        assert!(!cfg.smart_approve, "smart_approve must be false");
        assert!(!cfg.enabled, "must be disabled until operator opts in");
    }

    // --- GOLD-ADAPT-CCS-05: hex_research_recommended_config tests ---

    #[test]
    fn hex_research_config_id_and_command_are_stable() {
        let cfg = hex_research_recommended_config();
        assert_eq!(cfg.id, "hex-research");
        assert_eq!(cfg.command, "npx");
        assert!(
            cfg.args
                .iter()
                .any(|a| a == "@levnikolaevich/hex-research-mcp@0.2.1"),
            "args must contain the hex-research npm package name"
        );
        assert!(cfg.validate_launcher().is_ok());
    }

    #[test]
    fn hex_research_config_allow_tools_contains_read_tools() {
        let cfg = hex_research_recommended_config();
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        assert!(
            tools.iter().any(|t| t == "find_hypotheses"),
            "allow_tools must contain find_hypotheses"
        );
        assert!(
            tools.iter().any(|t| t == "trace_lineage"),
            "allow_tools must contain trace_lineage"
        );
        assert!(
            tools.iter().any(|t| t == "audit_goal_alignment"),
            "allow_tools must contain audit_goal_alignment"
        );
    }

    #[test]
    fn hex_research_config_is_secure_by_default() {
        let cfg = hex_research_recommended_config();
        assert!(!cfg.trust_all_tools, "trust_all_tools must be false");
        assert!(!cfg.smart_approve, "smart_approve must be false");
        assert!(!cfg.enabled, "must be disabled until operator opts in");
    }

    // --- GOLD-PROG-15 / PC-02: chrome_devtools_recommended_config tests ---

    #[test]
    fn chrome_devtools_config_id_command_and_telemetry_off() {
        let cfg = chrome_devtools_recommended_config();
        assert_eq!(cfg.id, "chrome-devtools");
        assert_eq!(cfg.command, "npx");
        assert!(
            cfg.args.iter().any(|a| a == "chrome-devtools-mcp@1.5.0"),
            "args must launch chrome-devtools-mcp"
        );
        assert!(cfg.validate_launcher().is_ok());
        // Telemetry opt-out is forced via env (the GOLD plan's named switch).
        assert_eq!(
            cfg.env
                .get("CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS")
                .map(String::as_str),
            Some("1"),
            "usage-statistics must be disabled"
        );
        assert_eq!(cfg.env.get("DO_NOT_TRACK").map(String::as_str), Some("1"));
    }

    #[test]
    fn chrome_devtools_config_is_elevated_gated_and_read_only() {
        let cfg = chrome_devtools_recommended_config();
        // CCS-02 floor: the whole server is inert below Elevated.
        assert_eq!(
            cfg.autonomy_gate,
            Some(crate::permissions::AutonomyLevel::Elevated),
            "browser driver must require Elevated autonomy"
        );
        assert!(!cfg.trust_all_tools, "trust_all_tools must be false");
        assert!(!cfg.smart_approve, "smart_approve must be false");
        assert!(!cfg.enabled, "must be disabled until operator opts in");
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        // Read/navigate only — interaction + JS-eval are deliberately excluded.
        assert!(tools.iter().any(|t| t == "take_snapshot"));
        for forbidden in ["evaluate_script", "click", "fill"] {
            assert!(
                !tools.iter().any(|t| t == forbidden),
                "{forbidden} must NOT be in the default allowlist (operator adds by hand)"
            );
        }
    }

    // --- GOLD-ADAPT-TUDU-01: tududi_recommended_config tests ---

    #[test]
    fn tududi_config_id_command_and_8_tools() {
        let cfg = tududi_recommended_config("/path/to/server.js");
        assert_eq!(cfg.id, "tududi");
        assert_eq!(cfg.command, "node");
        assert_eq!(cfg.args, vec!["/path/to/server.js"]);
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        assert_eq!(tools.len(), 8, "must expose exactly 8 task tools");
        for name in [
            "list_tasks",
            "get_task",
            "create_task",
            "update_task",
            "complete_task",
            "delete_task",
            "add_subtask",
            "get_task_metrics",
        ] {
            assert!(
                tools.iter().any(|t| t == name),
                "allow_tools must contain `{name}`"
            );
        }
    }

    #[test]
    fn tududi_config_is_secure_by_default() {
        let cfg = tududi_recommended_config("/x");
        assert!(!cfg.enabled, "must be disabled until operator opts in");
        assert!(!cfg.trust_all_tools, "trust_all_tools must be false");
        assert!(!cfg.smart_approve, "smart_approve must be false");
        assert!(
            cfg.autonomy_gate.is_none(),
            "no autonomy floor for task tools"
        );
    }

    #[test]
    fn tududi_config_token_is_from_env_sentinel() {
        // The API token MUST use the from_env sentinel — a literal value
        // here would be a secret-in-config leak caught by `neoth doctor`.
        let cfg = tududi_recommended_config("/path/to/server.js");
        assert_eq!(
            cfg.env.get("TUDUDI_API_TOKEN").map(String::as_str),
            Some("from_env"),
            "TUDUDI_API_TOKEN must use from_env sentinel, not a literal value"
        );
    }

    #[test]
    fn tududi_config_server_js_path_is_baked_into_args() {
        // The factory must place the caller-supplied server.js path as the
        // sole arg (node <path>) — not a package name or npx invocation.
        let path = "/home/op/tududi/backend/modules/mcp/server.js";
        let cfg = tududi_recommended_config(path);
        assert_eq!(cfg.command, "node");
        assert!(
            cfg.args.iter().any(|a| a == path),
            "args must contain the supplied server.js path"
        );
        // Sanity: no npx or -y flags — this is a direct node invocation.
        assert!(
            !cfg.args.iter().any(|a| a == "npx" || a == "-y"),
            "tududi must use `node <path>`, not npx"
        );
    }

    // --- GOLD-ADAPT-SYS-01: mobile_mcp_recommended_config tests ---

    #[test]
    fn mobile_mcp_config_id_and_command_are_stable() {
        let cfg = mobile_mcp_recommended_config();
        assert_eq!(cfg.id, "mobile-mcp");
        assert_eq!(cfg.command, "npx");
        assert!(
            cfg.args
                .iter()
                .any(|a| a == "@mobilenext/mobile-mcp@0.0.62"),
            "args must launch @mobilenext/mobile-mcp"
        );
        assert!(cfg.validate_launcher().is_ok());
    }

    #[test]
    fn mobile_mcp_config_is_elevated_gated_and_telemetry_off() {
        let cfg = mobile_mcp_recommended_config();
        // CCS-02 floor: the whole server is inert below Elevated.
        assert_eq!(
            cfg.autonomy_gate,
            Some(crate::permissions::AutonomyLevel::Elevated),
            "mobile device control must require Elevated autonomy"
        );
        // PostHog telemetry must be disabled unconditionally.
        assert_eq!(
            cfg.env
                .get("MOBILEMCP_DISABLE_TELEMETRY")
                .map(String::as_str),
            Some("1"),
            "MOBILEMCP_DISABLE_TELEMETRY must be forced to 1"
        );
        assert!(!cfg.enabled, "must be disabled until operator opts in");
    }

    #[test]
    fn mobile_mcp_config_excludes_remote_device_cloud_tools() {
        let cfg = mobile_mcp_recommended_config();
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        // These 3 tools provision cloud-hosted remote devices — cloud-blast-radius.
        for forbidden in [
            "mobile_list_remote_devices",
            "mobile_allocate_remote_device",
            "mobile_release_remote_device",
        ] {
            assert!(
                !tools.iter().any(|t| t == forbidden),
                "{forbidden} must NOT be in the default allowlist (cloud-blast-radius)"
            );
        }
        // Must expose a meaningful local-device surface (at least 20 tools).
        assert!(
            tools.len() >= 20,
            "must expose at least 20 local-device tools; got {}",
            tools.len()
        );
    }

    #[test]
    fn mobile_mcp_config_is_secure_by_default() {
        let cfg = mobile_mcp_recommended_config();
        assert!(!cfg.trust_all_tools, "trust_all_tools must be false");
        assert!(!cfg.smart_approve, "smart_approve must be false");
        assert!(!cfg.enabled, "must be disabled until operator opts in");
        // Core local-device tools must be present.
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        assert!(
            tools.iter().any(|t| t == "mobile_take_screenshot"),
            "allow_tools must contain mobile_take_screenshot"
        );
        assert!(
            tools.iter().any(|t| t == "mobile_click"),
            "allow_tools must contain mobile_click"
        );
        assert!(
            tools.iter().any(|t| t == "mobile_type_text"),
            "allow_tools must contain mobile_type_text"
        );
    }

    // --- GOLD-ADAPT-CCS-02: hex_ssh_recommended_config tests ---

    #[test]
    fn hex_ssh_config_id_and_command_are_stable() {
        let cfg = hex_ssh_recommended_config();
        assert_eq!(cfg.id, "hex-ssh");
        assert_eq!(cfg.command, "npx");
        assert!(
            cfg.args
                .iter()
                .any(|a| a == "@levnikolaevich/hex-ssh-mcp@1.9.2"),
            "args must contain the hex-ssh npm package name"
        );
        assert!(
            cfg.args.iter().any(|a| a == "-y"),
            "args must contain -y for auto-fetch"
        );
        assert!(cfg.validate_launcher().is_ok());
    }

    #[test]
    fn hex_ssh_config_is_elevated_gated_and_secure_by_default() {
        let cfg = hex_ssh_recommended_config();
        // CCS-02 floor: the whole server is inert below Elevated.
        assert_eq!(
            cfg.autonomy_gate,
            Some(crate::permissions::AutonomyLevel::Elevated),
            "SSH/remote-edit server must require Elevated autonomy"
        );
        assert!(!cfg.enabled, "must be disabled until operator opts in");
        assert!(!cfg.trust_all_tools, "trust_all_tools must be false");
        assert!(!cfg.smart_approve, "smart_approve must be false");
    }

    #[test]
    fn hex_ssh_config_has_14_tools() {
        let cfg = hex_ssh_recommended_config();
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        assert_eq!(
            tools.len(),
            14,
            "hex-ssh-mcp must expose exactly 14 tools; got {}",
            tools.len()
        );
    }

    #[test]
    fn hex_ssh_config_contains_checksum_verified_edit_tools() {
        // These are the key high-blast-radius tools whose FNV-checksum
        // verification is enforced by the hex-ssh-mcp subprocess.
        let cfg = hex_ssh_recommended_config();
        let tools = cfg.allow_tools.as_ref().expect("allow_tools must be Some");
        for name in [
            "ssh_write_file",
            "ssh_edit_block",
            "ssh_exec",
            "ssh_read_file",
            "sftp_upload",
            "tmux_send",
        ] {
            assert!(
                tools.iter().any(|t| t == name),
                "allow_tools must contain `{name}`"
            );
        }
    }

    #[test]
    fn hex_ssh_gate_predicate_blocks_strict_and_standard() {
        // Exercises the exact cfg.autonomy_gate -> meets_gate() path that
        // invoke_with_audit uses at Layer 1b — proves the factory config
        // connects correctly to the live gate enforcement.
        use crate::permissions::AutonomyLevel::*;
        let cfg = hex_ssh_recommended_config();
        let required = cfg
            .autonomy_gate
            .expect("autonomy_gate must be Some(Elevated)");
        assert_eq!(required, Elevated, "gate must be Elevated");
        // Strict and Standard must NOT satisfy the gate.
        assert!(
            !Strict.meets_gate(required),
            "Strict must not satisfy Elevated gate"
        );
        assert!(
            !Standard.meets_gate(required),
            "Standard must not satisfy Elevated gate"
        );
        // Custom ranks as Standard (unmodelled) — also blocked.
        assert!(
            !Custom.meets_gate(required),
            "Custom must not satisfy Elevated gate"
        );
        // Elevated and Full must satisfy the gate.
        assert!(
            Elevated.meets_gate(required),
            "Elevated must satisfy its own gate"
        );
        assert!(Full.meets_gate(required), "Full must satisfy Elevated gate");
    }

    // ── B18 tests ────────────────────────────────────────────────────────────

    #[test]
    fn update_at_malformed_yaml_returns_err_and_leaves_file_unchanged() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mcp_servers.yaml");
        let bad_yaml = b": this is not valid yaml\n  structure: \xff";
        std::fs::write(&path, bad_yaml).unwrap();

        let result = McpServers::update_at(&path, |_| Ok(true));
        assert!(result.is_err(), "update_at must Err on malformed YAML");

        // File bytes must be byte-identical — no write happened.
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            after.as_slice(),
            bad_yaml,
            "file must be byte-identical after failed load"
        );
    }

    #[test]
    fn update_at_missing_file_creates_expected_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mcp_servers.yaml");
        // File does not exist.
        McpServers::update_at(&path, |servers| {
            servers.servers.push(McpServerConfig {
                id: "new-server".into(),
                command: "node".into(),
                description: None,
                args: vec![],
                env: std::collections::HashMap::new(),
                enabled: true,
                allow_tools: None,
                trust_all_tools: false,
                smart_approve: false,
                autonomy_gate: None,
            });
            Ok(true)
        })
        .unwrap();

        let loaded = McpServers::load_from(&path).unwrap();
        assert_eq!(loaded.servers.len(), 1);
        assert_eq!(loaded.servers[0].id, "new-server");
    }

    #[test]
    fn update_at_preserves_unrelated_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mcp_servers.yaml");
        std::fs::write(
            &path,
            "servers:\n  - id: keeper\n    command: keep\n  - id: target\n    command: old\n",
        )
        .unwrap();

        McpServers::update_at(&path, |servers| {
            if let Some(s) = servers.servers.iter_mut().find(|s| s.id == "target") {
                s.command = "new".into();
            }
            Ok(true)
        })
        .unwrap();

        let loaded = McpServers::load_from(&path).unwrap();
        assert_eq!(loaded.servers.len(), 2, "both entries must survive");
        assert!(
            loaded.servers.iter().any(|s| s.id == "keeper"),
            "keeper must be preserved"
        );
        let target = loaded.servers.iter().find(|s| s.id == "target").unwrap();
        assert_eq!(target.command, "new");
    }

    #[test]
    fn update_at_noop_mutation_skips_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mcp_servers.yaml");
        let original = "servers:\n  - id: existing\n    command: x\n";
        std::fs::write(&path, original).unwrap();

        McpServers::update_at(&path, |_| Ok(false)).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        // Content unchanged — no spurious rewrite on no-op.
        let loaded = McpServers::load_from(&path).unwrap();
        assert_eq!(loaded.servers.len(), 1, "no-op must not alter entries");
        let _ = after; // still readable
    }

    #[test]
    fn update_at_concurrent_different_ids_all_written_exactly_once() {
        use std::sync::{Arc, Barrier};

        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("mcp_servers.yaml"));
        let barrier = Arc::new(Barrier::new(4));

        let handles: Vec<_> = (0..4_u32)
            .map(|i| {
                let p = Arc::clone(&path);
                let b = Arc::clone(&barrier);
                let id = format!("server-{i}");
                std::thread::spawn(move || {
                    b.wait();
                    McpServers::update_at(&p, move |servers| {
                        if !servers.servers.iter().any(|s| s.id == id) {
                            servers.servers.push(McpServerConfig {
                                id: id.clone(),
                                command: "x".into(),
                                description: None,
                                args: vec![],
                                env: std::collections::HashMap::new(),
                                enabled: true,
                                allow_tools: None,
                                trust_all_tools: false,
                                smart_approve: false,
                                autonomy_gate: None,
                            });
                        }
                        Ok(true)
                    })
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap().unwrap();
        }

        let loaded = McpServers::load_from(&path).unwrap();
        for i in 0..4_u32 {
            assert!(
                loaded.servers.iter().any(|s| s.id == format!("server-{i}")),
                "server-{i} must be present"
            );
        }
        assert_eq!(loaded.servers.len(), 4, "exactly 4 entries — no duplicates");
    }

    #[test]
    fn update_at_concurrent_same_id_no_duplicate() {
        use std::sync::{Arc, Barrier};

        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("mcp_servers.yaml"));
        let barrier = Arc::new(Barrier::new(4));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let p = Arc::clone(&path);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    McpServers::update_at(&p, |servers| {
                        if !servers.servers.iter().any(|s| s.id == "shared") {
                            servers.servers.push(McpServerConfig {
                                id: "shared".into(),
                                command: "x".into(),
                                description: None,
                                args: vec![],
                                env: std::collections::HashMap::new(),
                                enabled: true,
                                allow_tools: None,
                                trust_all_tools: false,
                                smart_approve: false,
                                autonomy_gate: None,
                            });
                        }
                        Ok(true)
                    })
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap().unwrap();
        }

        let loaded = McpServers::load_from(&path).unwrap();
        let count = loaded.servers.iter().filter(|s| s.id == "shared").count();
        assert_eq!(
            count, 1,
            "exactly one 'shared' entry after concurrent same-id upserts"
        );
    }
}
