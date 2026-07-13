//! GOLD-ADAPT-GOOSE-02 — pluggable tool-inspection chain.
//!
//! Port of goose's `ToolInspector` trait + inspector vector
//! (`crates/goose/src/agents/tool_inspection.rs`): the pre-dispatch safety
//! checks run as an ordered chain of [`ToolInspector`]s instead of a
//! hand-wired sequence inside [`crate::mcp::dispatch_loop`]. Each inspector
//! returns a typed [`InspectorVerdict`]; the chain returns the FIRST block.
//! Unliftable guards run before the lease-liftable risk policy so an operator
//! risk lease can never bypass secret-egress or manifest-scan enforcement.
//!
//! ## Scope (deliberate, security-reviewed)
//!
//! The chain DECIDES "is this call blocked, and why" — it computes the
//! repetition verdict (GOLD-ADOPT-20), the dangerous-command/egress risk
//! verdict (GOLD-ADOPT-23), and the pre-send secret-egress verdict
//! (GOLD-ADAPT-CAF-01). It does NOT perform the NEOTH-specific
//! risk-confirm LEASE lift or the distinct WAL audit emits: those are async +
//! stateful authorization side-effects (filesystem leases, the WAL writer),
//! not a pure inspection, so they stay in the dispatch loop, driven by the
//! [`BlockKind::Risk`] payload the chain hands back. The allowlist / autonomy
//! / SmartApprove checks likewise stay in [`crate::mcp::gate::invoke_with_audit`]
//! (they need the live `McpClient`). A new PURE safety check bolts on by
//! implementing [`ToolInspector`] and pushing it into the chain.

use crate::config::SecurityPolicy;
use crate::mcp::repetition_guard::{GuardVerdict, ToolRepetitionGuard};
use crate::mcp::tool_call_parser::ParsedToolCall;
use crate::security::risk_gate::{RiskGate, evaluate_tool_risk};
use crate::security::secrets_scan::scan_text;
use crate::security::{ToolCallRisk, inspect_tool_args};

/// One inspector's decision for a prospective tool call.
pub enum InspectorVerdict {
    /// No objection from this inspector.
    Allow,
    /// Block the call. `inspector` names the source for logging/audit.
    Block {
        inspector: &'static str,
        kind: BlockKind,
    },
}

/// One registry coordinate extracted from the exact package-manager command.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegistryPackageRequest {
    pub name: String,
    pub ecosystem: &'static str,
    pub version: Option<String>,
}

/// A fully-resolved local package-manager action. The binding includes the
/// complete tool-argument object plus every normalized value that can change
/// what is installed; raw command text never leaves this module or reaches the
/// WAL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallIntent {
    pub server: String,
    pub tool: String,
    pub manager: &'static str,
    pub operation: &'static str,
    pub target_dir: String,
    pub command_sha256: String,
    pub binding_sha256: String,
    /// Resolver inputs bound into the final one-shot permit (source manifest
    /// plus immutable lockfile).
    pub manifests: Vec<String>,
    /// Exact transitive lockfiles that receive the OSV scan. Source manifests
    /// may contain ranges and are validation+hash inputs, not OSV coordinates.
    pub resolution_locks: Vec<String>,
    pub packages: Vec<RegistryPackageRequest>,
}

/// Fail-closed result for a package-manager-looking command that cannot be
/// safely mapped to one local install target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedInstallIntent {
    pub code: &'static str,
    pub command_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallGateRequest {
    Scan(InstallIntent),
    Unverified(UnverifiedInstallIntent),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSnapshotApproval {
    pub path: String,
    pub sha256: String,
}

/// One-shot approval for one exact install intent and its manifest snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallApproval {
    pub binding_sha256: String,
    pub manifests: Vec<ManifestSnapshotApproval>,
}

/// The typed payload behind a block, so the dispatch loop can act with the
/// full context the original inline code had.
pub enum BlockKind {
    /// Stuck-loop guard tripped — carries the verdict for the LLM notice.
    Repetition(GuardVerdict),
    /// Dangerous-command / egress risk gate tripped — carries the findings +
    /// the base gate so the loop can run the lease-lift + distinct WAL emit.
    Risk { risk: ToolCallRisk, gate: RiskGate },
    /// Secret / credential pattern detected in outbound tool-call arguments
    /// (GOLD-ADAPT-CAF-01). `pattern` is the regex rule name; `redacted` is
    /// the masked excerpt — safe to surface in logs and LLM error replies.
    SecretEgress {
        /// Name of the matched secret pattern (e.g. `"openai_key"`).
        pattern: &'static str,
        /// Matched value with first/last 4 chars visible, middle masked.
        redacted: String,
    },
    /// GOLD-ADAPT-SNYK-02 — package-manager calls classified by the strict
    /// parser are blocked. Only immutable, lock-backed resolution commands can
    /// earn a one-shot retry; direct fetch/mutation remains fail-closed.
    ManifestGate { request: InstallGateRequest },
}

/// A pre-dispatch safety check. `Send` so the chain can be held across the
/// dispatch loop's `.await` points.
pub trait ToolInspector: Send {
    /// Stable name for logs/audit.
    fn name(&self) -> &'static str;
    /// Judge ONE prospective call. Called exactly once per dispatch attempt
    /// (a stateful inspector, e.g. the repetition guard, records the attempt).
    fn inspect(&mut self, call: &ParsedToolCall, policy: &SecurityPolicy) -> InspectorVerdict;
    /// Called only after every registry coordinate and manifest snapshot for
    /// one exact install intent received a conclusive policy-clean result.
    fn on_install_scan_proven(&mut self, _approval: InstallApproval) {}
    /// Revalidate and consume the one-shot permit at the final dispatch edge.
    fn consume_install_permit(&mut self, _call: &ParsedToolCall) -> Result<(), &'static str> {
        Ok(())
    }
}

/// Stuck-loop guard as an inspector (GOLD-ADOPT-20).
pub struct RepetitionInspector(pub ToolRepetitionGuard);

impl ToolInspector for RepetitionInspector {
    fn name(&self) -> &'static str {
        "repetition"
    }
    fn inspect(&mut self, call: &ParsedToolCall, _policy: &SecurityPolicy) -> InspectorVerdict {
        let v = self.0.check(call);
        if v.is_blocked() {
            InspectorVerdict::Block {
                inspector: "repetition",
                kind: BlockKind::Repetition(v),
            }
        } else {
            InspectorVerdict::Allow
        }
    }
}

/// Dangerous-command + egress risk policy as an inspector (GOLD-ADOPT-23).
/// Computes the verdict + surfaces every finding (tracing warn) exactly as the
/// pre-chain loop did; the lease-lift + WAL emits stay in the loop.
pub struct RiskPolicyInspector;

impl ToolInspector for RiskPolicyInspector {
    fn name(&self) -> &'static str {
        "risk_policy"
    }
    fn inspect(&mut self, call: &ParsedToolCall, policy: &SecurityPolicy) -> InspectorVerdict {
        let risk = inspect_tool_args(&call.arguments);
        if risk.is_empty() {
            return InspectorVerdict::Allow;
        }
        // GOLD-ADOPT-23 P0 — ALWAYS surface dangerous + egress findings, even
        // when the policy is warn-only and the gate ends up Allow.
        for d in &risk.dangerous {
            tracing::warn!(
                server = %call.server, tool = %call.tool,
                rule = d.id, severity = d.severity.as_str(),
                "dangerous-command pattern in tool call: {}", d.reason
            );
        }
        for e in &risk.egress {
            tracing::warn!(
                server = %call.server, tool = %call.tool,
                kind = %e.kind, domain = %e.domain,
                "outbound egress destination in tool call"
            );
        }
        let gate = evaluate_tool_risk(&risk, policy);
        if gate.is_blocked() {
            InspectorVerdict::Block {
                inspector: "risk_policy",
                kind: BlockKind::Risk { risk, gate },
            }
        } else {
            InspectorVerdict::Allow
        }
    }
}

/// Pre-send credential / secret scanner (GOLD-ADAPT-CAF-01).
///
/// Serialises the full `arguments` payload to JSON text and runs
/// [`scan_text`] from [`crate::security::secrets_scan`] over it. If any
/// credential-shape regex matches, the call is blocked immediately with
/// [`BlockKind::SecretEgress`] carrying a redacted excerpt. The raw secret
/// value never appears in logs or LLM replies.
///
/// This runs BEFORE the lease-liftable risk-policy inspector. Secret
/// exfiltration is an unconditional block and must not disappear merely
/// because the same call also matches a risk rule with an operator lease.
pub struct SecretEgressInspector;

impl ToolInspector for SecretEgressInspector {
    fn name(&self) -> &'static str {
        "secret_egress"
    }

    fn inspect(&mut self, call: &ParsedToolCall, _policy: &SecurityPolicy) -> InspectorVerdict {
        // Serialise arguments to text. serde_json::to_string can only fail
        // for types with custom serialisers that return an error; Value
        // never does.
        let text = call.arguments.to_string();
        let findings = scan_text(&text);
        if let Some(f) = findings.into_iter().next() {
            tracing::warn!(
                server = %call.server,
                tool   = %call.tool,
                pattern = f.pattern,
                redacted = %f.redacted,
                "secret-egress: credential pattern in outbound tool-call arguments — call blocked"
            );
            InspectorVerdict::Block {
                inspector: "secret_egress",
                kind: BlockKind::SecretEgress {
                    pattern: f.pattern,
                    redacted: f.redacted,
                },
            }
        } else {
            InspectorVerdict::Allow
        }
    }
}

/// GOLD-ADAPT-SNYK-02 — immutable lock-backed package-manager actions are a
/// two-step operation: first attempt scans the exact transitive lock graph,
/// then one exact retry may dispatch. Direct mutation/fetch commands and
/// unresolved actions stay fail-closed. A new loop always scans again.
pub struct ManifestInstallInspector {
    approved: Option<InstallApproval>,
    ready: Option<InstallApproval>,
}

impl ManifestInstallInspector {
    pub fn new() -> Self {
        Self {
            approved: None,
            ready: None,
        }
    }
}

impl Default for ManifestInstallInspector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Npm,
    Yarn,
    Pnpm,
    Bun,
    Cargo,
    Pip,
    Uv,
    Poetry,
    Go,
}

enum ParsedInstall {
    NotInstall,
    Scan(InstallIntent),
    Unverified(UnverifiedInstallIntent),
}

fn sha256_text(value: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn unique_string_arg<'a>(
    args: &'a serde_json::Value,
    keys: &[&str],
    conflict_code: &'static str,
) -> Result<Option<&'a str>, &'static str> {
    let Some(object) = args.as_object() else {
        return Err("tool_arguments_not_object");
    };
    let present = keys
        .iter()
        .filter_map(|key| object.get(*key))
        .collect::<Vec<_>>();
    match present.as_slice() {
        [] => Ok(None),
        [value] => value.as_str().map(Some).ok_or(conflict_code),
        _ => Err(conflict_code),
    }
}

fn looks_like_package_manager(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    let parts = lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
        .collect::<Vec<_>>();
    let manager = [
        "npm", "npx", "yarn", "pnpm", "bun", "bunx", "cargo", "pip", "pipx", "python", "uv", "uvx",
        "poetry", "go",
    ]
    .iter()
    .any(|needle| {
        parts.iter().any(|part| {
            let stem = [".exe", ".cmd", ".bat", ".ps1"]
                .iter()
                .find_map(|suffix| part.strip_suffix(suffix))
                .unwrap_or(part);
            stem == *needle
        })
    });
    let implicit_launcher = ["npx", "bunx", "uvx"].iter().any(|needle| {
        parts.iter().any(|part| {
            let stem = [".exe", ".cmd", ".bat", ".ps1"]
                .iter()
                .find_map(|suffix| part.strip_suffix(suffix))
                .unwrap_or(part);
            stem == *needle
        })
    });
    let action = [
        "install",
        "i",
        "add",
        "ci",
        "exec",
        "dlx",
        "run",
        "doc",
        "bench",
        "clippy",
        "fetch",
        "update",
        "up",
        "upgrade",
        "upgrade-all",
        "build",
        "check",
        "test",
        "sync",
        "get",
        "tidy",
        "download",
        "wheel",
        "inject",
        "pack",
        "rebuild",
        "create",
        "init",
        "metadata",
        "lock",
    ]
    .iter()
    .any(|needle| parts.contains(needle));
    implicit_launcher || manager && action
}

fn tokenize_command(raw: &str) -> Result<Vec<String>, &'static str> {
    if raw.contains(['\n', '\r', ';', '|', '&', '>', '<', '`']) || raw.contains("$(") {
        return Err("combined_or_remote_command");
    }
    if raw.contains(['$', '%', '!', '^', '*', '?', '{', '}', '[', ']', '~']) {
        return Err("shell_expansion_unsupported");
    }
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            let escapes_next = chars.peek().is_some_and(|next| {
                matches!(next, '\\' | '\'' | '"') || quote.is_none() && next.is_whitespace()
            });
            if escapes_next {
                escaped = true;
            } else {
                current.push(ch);
            }
            continue;
        }
        if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if escaped || quote.is_some() {
        return Err("ambiguous_command_quoting");
    }
    if !current.is_empty() {
        out.push(current);
    }
    Ok(out)
}

fn executable_name(raw: &str) -> String {
    let file_name = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let lower = file_name.to_ascii_lowercase();
    [".exe", ".cmd", ".bat", ".ps1"]
        .iter()
        .find_map(|suffix| lower.strip_suffix(suffix))
        .unwrap_or(&lower)
        .to_string()
}

fn canonical_dir(base: Option<&std::path::Path>, raw: &str) -> Result<String, &'static str> {
    let path = std::path::Path::new(raw);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.ok_or("relative_target_without_base")?.join(path)
    };
    let canonical = std::fs::canonicalize(path).map_err(|_| "install_target_unavailable")?;
    if !canonical.is_dir() {
        return Err("install_target_not_directory");
    }
    Ok(canonical.to_string_lossy().into_owned())
}

fn canonical_file(base: &std::path::Path, raw: &str) -> Result<String, &'static str> {
    let path = std::path::Path::new(raw);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let canonical = std::fs::canonicalize(path).map_err(|_| "manifest_unavailable")?;
    if !canonical.is_file() {
        return Err("manifest_not_file");
    }
    Ok(canonical.to_string_lossy().into_owned())
}

fn option_value(tokens: &[String], names: &[&str]) -> Result<Option<String>, &'static str> {
    let mut found: Option<String> = None;
    let mut i = 0;
    while i < tokens.len() {
        let token = &tokens[i];
        if token == "--" {
            break;
        }
        let mut value = None;
        for name in names {
            if token == name {
                value = tokens.get(i + 1).cloned();
                if value.is_none() {
                    return Err("option_missing_value");
                }
                break;
            }
            if let Some(rest) = token.strip_prefix(&format!("{name}=")) {
                value = Some(rest.to_string());
                break;
            }
        }
        if let Some(value) = value {
            if found.as_ref().is_some_and(|old| old != &value) {
                return Err("conflicting_install_targets");
            }
            found = Some(value);
        }
        i += 1;
    }
    Ok(found)
}

fn exact_version(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches("==");
    let numeric = value.strip_prefix('v').unwrap_or(value);
    let core_end = numeric.find(['-', '+']).unwrap_or(numeric.len());
    let core = &numeric[..core_end];
    let core_segments = core.split('.').collect::<Vec<_>>();
    let exact_numeric_core = core_segments.len() >= 3
        && core_segments
            .iter()
            .all(|segment| !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()));
    let suffix_is_nonempty = core_end == numeric.len() || core_end + 1 < numeric.len();
    (exact_numeric_core
        && suffix_is_nonempty
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_')))
    .then(|| value.to_string())
}

fn exact_pypi_version(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches("==");
    if value.is_empty()
        || value.contains(['*', '<', '>', '~', '=', ';', '@', '/', '\\'])
        || value.chars().any(char::is_whitespace)
    {
        return None;
    }
    let (epoch, release_and_suffix) = value
        .split_once('!')
        .map_or((None, value), |(epoch, rest)| (Some(epoch), rest));
    if epoch.is_some_and(|epoch| epoch.is_empty() || !epoch.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }
    let release_end = release_and_suffix
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(release_and_suffix.len());
    let release = &release_and_suffix[..release_end];
    if release.is_empty()
        || release
            .split('.')
            .any(|segment| segment.is_empty() || !segment.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    let suffix = &release_and_suffix[release_end..];
    let normalized_suffix = suffix
        .trim_start_matches(['.', '-', '_'])
        .to_ascii_lowercase();
    let suffix_ok = suffix.is_empty()
        || suffix.starts_with('+') && suffix.len() > 1
        || [
            "a", "b", "rc", "alpha", "beta", "pre", "preview", "post", "rev", "r", "dev",
        ]
        .iter()
        .any(|prefix| normalized_suffix.starts_with(prefix));
    (suffix_ok
        && suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_')))
    .then(|| value.to_string())
}

fn registry_request(
    manager: PackageManager,
    raw: &str,
) -> Result<RegistryPackageRequest, &'static str> {
    let lower = raw.to_ascii_lowercase();
    if raw
        .chars()
        .next()
        .is_some_and(|first| matches!(first, '.' | '/' | '\\' | '~'))
        || raw.contains("\\")
        || lower.contains("://")
        || lower.starts_with("git+")
        || ["file:", "link:", "workspace:", "path:", "github:"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
    {
        return Err("non_registry_dependency");
    }
    let (ecosystem, name, version) = match manager {
        PackageManager::Npm | PackageManager::Yarn | PackageManager::Pnpm | PackageManager::Bun => {
            if lower.contains("@npm:") || lower.starts_with("npm:") || raw.contains('#') {
                return Err("ambiguous_registry_alias");
            }
            let split = if raw.starts_with('@') {
                raw.rfind('@').filter(|index| raw[..*index].contains('/'))
            } else {
                raw.rfind('@').filter(|index| *index > 0)
            };
            let (name, version) = split
                .map(|index| (&raw[..index], exact_version(&raw[index + 1..])))
                .unwrap_or((raw, None));
            ("npm", name, version)
        }
        PackageManager::Cargo => {
            let split = raw.rfind('@').filter(|index| *index > 0);
            let (name, version) = split
                .map(|index| (&raw[..index], exact_version(&raw[index + 1..])))
                .unwrap_or((raw, None));
            ("crates.io", name, version)
        }
        PackageManager::Pip | PackageManager::Uv | PackageManager::Poetry => {
            if raw.contains('@') {
                return Err("non_registry_dependency");
            }
            let name_end = raw
                .find(|c: char| matches!(c, '[' | '<' | '>' | '=' | '!' | '~' | ';'))
                .unwrap_or(raw.len());
            let name = &raw[..name_end];
            let version = raw
                .get(name_end..)
                .and_then(|spec| spec.strip_prefix("=="))
                .and_then(exact_pypi_version);
            ("PyPI", name, version)
        }
        PackageManager::Go => {
            let split = raw.rfind('@').filter(|index| *index > 0);
            let (name, version) = split
                .map(|index| (&raw[..index], exact_version(&raw[index + 1..])))
                .unwrap_or((raw, None));
            ("Go", name, version)
        }
    };
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '/' | '_' | '-' | '.'))
    {
        return Err("invalid_registry_coordinate");
    }
    if version.is_none() {
        return Err("exact_registry_version_required");
    }
    Ok(RegistryPackageRequest {
        name: name.to_string(),
        ecosystem,
        version,
    })
}

fn ambient_resolution_context_is_clean(
    manager: PackageManager,
    target_dir: &str,
) -> Result<(), &'static str> {
    let base = std::path::Path::new(target_dir);
    let env_override = std::env::vars_os().any(|(key, _)| {
        let key = key.to_string_lossy().to_ascii_uppercase();
        match manager {
            PackageManager::Npm
            | PackageManager::Yarn
            | PackageManager::Pnpm
            | PackageManager::Bun => {
                key == "NPM_CONFIG_REGISTRY"
                    || key == "NPM_CONFIG_USERCONFIG"
                    || key == "NPM_CONFIG_PREFIX"
                    || key == "NPM_CONFIG_GLOBAL"
                    || key == "NPM_CONFIG_WORKSPACE"
                    || key == "NPM_CONFIG_WORKSPACES"
                    || key == "YARN_NPM_REGISTRY_SERVER"
                    || key == "YARN_RC_FILENAME"
                    || key == "COREPACK_NPM_REGISTRY"
            }
            PackageManager::Cargo => {
                key == "CARGO_REGISTRY_DEFAULT"
                    || key.starts_with("CARGO_REGISTRIES_") && key.ends_with("_INDEX")
            }
            PackageManager::Pip | PackageManager::Uv | PackageManager::Poetry => {
                matches!(
                    key.as_str(),
                    "PIP_CONFIG_FILE"
                        | "PIP_INDEX_URL"
                        | "PIP_EXTRA_INDEX_URL"
                        | "PIP_FIND_LINKS"
                        | "UV_CONFIG_FILE"
                        | "UV_DEFAULT_INDEX"
                        | "UV_INDEX_URL"
                        | "UV_EXTRA_INDEX_URL"
                        | "UV_FIND_LINKS"
                        | "POETRY_REPOSITORIES"
                )
            }
            PackageManager::Go => matches!(
                key.as_str(),
                "GOPROXY"
                    | "GONOPROXY"
                    | "GOPRIVATE"
                    | "GONOSUMDB"
                    | "GOSUMDB"
                    | "GOENV"
                    | "GOWORK"
            ),
        }
    });
    if env_override {
        return Err("ambient_registry_override");
    }

    let config_present_at = |root: &std::path::Path| match manager {
        PackageManager::Npm | PackageManager::Yarn | PackageManager::Pnpm | PackageManager::Bun => {
            [
                ".npmrc",
                ".yarnrc",
                ".yarnrc.yml",
                ".pnpmfile.cjs",
                ".pnpmfile.js",
                "bunfig.toml",
            ]
            .iter()
            .any(|name| root.join(name).exists())
        }
        PackageManager::Cargo => ["config", "config.toml"]
            .iter()
            .any(|name| root.join(".cargo").join(name).exists()),
        PackageManager::Pip | PackageManager::Uv | PackageManager::Poetry => [
            root.join("pip.conf"),
            root.join("pip.ini"),
            root.join("uv.toml"),
            root.join("poetry.toml"),
            root.join(".config").join("pip").join("pip.conf"),
            root.join(".config").join("uv").join("uv.toml"),
        ]
        .iter()
        .any(|path| path.exists()),
        PackageManager::Go => false,
    };
    if std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .is_some_and(|home| config_present_at(std::path::Path::new(&home)))
        || manager == PackageManager::Cargo
            && std::env::var_os("CARGO_HOME").is_some_and(|home| {
                ["config", "config.toml"]
                    .iter()
                    .any(|name| std::path::Path::new(&home).join(name).exists())
            })
    {
        return Err("ambient_package_manager_config");
    }

    for ancestor in base.ancestors() {
        if config_present_at(ancestor) {
            return Err("ambient_package_manager_config");
        }

        match manager {
            PackageManager::Npm
            | PackageManager::Yarn
            | PackageManager::Pnpm
            | PackageManager::Bun => {
                if ["pnpm-workspace.yaml", "lerna.json"]
                    .iter()
                    .any(|name| ancestor.join(name).exists())
                {
                    return Err("ambient_workspace_context");
                }
                let package_json = ancestor.join("package.json");
                if package_json.exists() {
                    let body = std::fs::read_to_string(package_json)
                        .map_err(|_| "ambient_context_unreadable")?;
                    let doc: serde_json::Value =
                        serde_json::from_str(&body).map_err(|_| "ambient_context_unreadable")?;
                    if doc.get("workspaces").is_some() {
                        return Err("ambient_workspace_context");
                    }
                }
            }
            PackageManager::Cargo => {
                let manifest = ancestor.join("Cargo.toml");
                if manifest.exists() {
                    let body = std::fs::read_to_string(manifest)
                        .map_err(|_| "ambient_context_unreadable")?;
                    let doc: toml::Value =
                        toml::from_str(&body).map_err(|_| "ambient_context_unreadable")?;
                    if doc.get("workspace").is_some() {
                        return Err("ambient_workspace_context");
                    }
                }
            }
            PackageManager::Go if ancestor.join("go.work").exists() => {
                return Err("ambient_workspace_context");
            }
            _ => {}
        }
    }
    Ok(())
}

struct LockedResolutionInputs {
    bound: Vec<String>,
    locks: Vec<String>,
}

fn locked_resolution_inputs(
    manager: PackageManager,
    operation: &str,
    manager_args: &[String],
    target_dir: &str,
) -> Result<LockedResolutionInputs, &'static str> {
    let base = std::path::Path::new(target_dir);
    let has_flag = |flags: &[&str]| {
        manager_args
            .iter()
            .any(|arg| flags.iter().any(|flag| arg == flag))
    };
    let (source_name, lock_names): (&str, &[&str]) = match (manager, operation) {
        (PackageManager::Npm, "ci") => {
            if base.join("npm-shrinkwrap.json").exists() {
                ("package.json", &["npm-shrinkwrap.json"])
            } else {
                ("package.json", &["package-lock.json"])
            }
        }
        (PackageManager::Yarn, "install") if has_flag(&["--frozen-lockfile", "--immutable"]) => {
            ("package.json", &["yarn.lock"])
        }
        (PackageManager::Pnpm, "install") if has_flag(&["--frozen-lockfile"]) => {
            ("package.json", &["pnpm-lock.yaml"])
        }
        (
            PackageManager::Cargo,
            "fetch" | "build" | "check" | "test" | "run" | "doc" | "bench" | "clippy",
        ) if has_flag(&["--locked", "--frozen"]) => ("Cargo.toml", &["Cargo.lock"]),
        (PackageManager::Uv, "sync") if has_flag(&["--frozen", "--locked"]) => {
            ("pyproject.toml", &["uv.lock"])
        }
        _ => return Err("transitive_resolution_unproven"),
    };
    let source =
        canonical_file(base, source_name).map_err(|_| "required_source_manifest_missing")?;
    crate::security::dep_health::validate_resolution_source_manifest(std::path::Path::new(&source))
        .map_err(|_| "source_manifest_unverified")?;
    let mut locks = Vec::with_capacity(lock_names.len());
    for name in lock_names {
        locks.push(canonical_file(base, name).map_err(|_| "required_lockfile_missing")?);
    }
    locks.sort();
    locks.dedup();
    let mut bound = locks.clone();
    bound.push(source);
    bound.sort();
    bound.dedup();
    Ok(LockedResolutionInputs { bound, locks })
}

fn parse_install(call: &ParsedToolCall) -> ParsedInstall {
    let arguments_sha256 = sha256_text(&call.arguments.to_string());
    let raw = match unique_string_arg(
        &call.arguments,
        &["command", "cmd", "script", "exec_command"],
        "ambiguous_command_fields",
    ) {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            let serialized = call.arguments.to_string();
            if looks_like_package_manager(&serialized) {
                return ParsedInstall::Unverified(UnverifiedInstallIntent {
                    code: "command_field_unrecognized",
                    command_sha256: sha256_text(&serialized),
                });
            }
            return ParsedInstall::NotInstall;
        }
        Err(code) => {
            let serialized = call.arguments.to_string();
            if looks_like_package_manager(&serialized) {
                return ParsedInstall::Unverified(UnverifiedInstallIntent {
                    code,
                    command_sha256: sha256_text(&serialized),
                });
            }
            return ParsedInstall::NotInstall;
        }
    };
    let command_sha256 = sha256_text(raw);
    let tokens = match tokenize_command(raw) {
        Ok(tokens) => tokens,
        Err(code) if looks_like_package_manager(raw) => {
            return ParsedInstall::Unverified(UnverifiedInstallIntent {
                code,
                command_sha256,
            });
        }
        Err(_) => return ParsedInstall::NotInstall,
    };
    if tokens.is_empty() {
        return ParsedInstall::NotInstall;
    }
    let mut start = 0;
    while tokens.get(start).is_some_and(|token| {
        token
            .split_once('=')
            .is_some_and(|(name, _)| !name.is_empty() && !name.starts_with('-'))
    }) {
        start += 1;
    }
    if start > 0 {
        return if looks_like_package_manager(raw) {
            ParsedInstall::Unverified(UnverifiedInstallIntent {
                code: "environment_override_unsupported",
                command_sha256,
            })
        } else {
            ParsedInstall::NotInstall
        };
    }
    let Some(executable) = tokens.get(start).map(|token| executable_name(token)) else {
        return ParsedInstall::NotInstall;
    };
    let mut args_start = start + 1;
    let mut forced_operation: Option<&'static str> = None;
    let manager = match executable.as_str() {
        "npm" => PackageManager::Npm,
        "npx" => {
            forced_operation = Some("exec");
            PackageManager::Npm
        }
        "yarn" => PackageManager::Yarn,
        "pnpm" => PackageManager::Pnpm,
        "bun" => PackageManager::Bun,
        "bunx" => {
            forced_operation = Some("exec");
            PackageManager::Bun
        }
        "cargo" => PackageManager::Cargo,
        "pip" | "pip3" => PackageManager::Pip,
        "pipx" => PackageManager::Pip,
        "uv" => PackageManager::Uv,
        "uvx" => {
            forced_operation = Some("run");
            PackageManager::Uv
        }
        "poetry" => PackageManager::Poetry,
        "go" => PackageManager::Go,
        "python" | "python3" | "py" => {
            if tokens.get(args_start).map(String::as_str) != Some("-m")
                || !matches!(
                    tokens.get(args_start + 1).map(String::as_str),
                    Some("pip" | "pip3")
                )
            {
                if looks_like_package_manager(raw) {
                    return ParsedInstall::Unverified(UnverifiedInstallIntent {
                        code: "unsupported_package_manager_wrapper",
                        command_sha256,
                    });
                }
                return ParsedInstall::NotInstall;
            }
            args_start += 2;
            PackageManager::Pip
        }
        _ if looks_like_package_manager(raw) => {
            return ParsedInstall::Unverified(UnverifiedInstallIntent {
                code: "unsupported_package_manager_wrapper",
                command_sha256,
            });
        }
        _ => return ParsedInstall::NotInstall,
    };

    let raw_cwd = match unique_string_arg(
        &call.arguments,
        &["cwd", "workdir", "working_directory", "directory"],
        "ambiguous_cwd_fields",
    ) {
        Ok(Some(cwd)) => cwd,
        Ok(None) => {
            return ParsedInstall::Unverified(UnverifiedInstallIntent {
                code: "explicit_cwd_required",
                command_sha256,
            });
        }
        Err(code) => {
            return ParsedInstall::Unverified(UnverifiedInstallIntent {
                code,
                command_sha256,
            });
        }
    };
    // Arbitrary extra MCP arguments can alter the process environment, shell,
    // registry, workspace or executable in server-specific ways that this
    // cross-server parser cannot prove. Permit only the one command field and
    // one cwd field that were parsed above; everything else stays fail-closed.
    if call.arguments.as_object().map(|object| object.len()) != Some(2) {
        return ParsedInstall::Unverified(UnverifiedInstallIntent {
            code: "unsupported_tool_execution_context",
            command_sha256,
        });
    }
    let base_dir = match canonical_dir(None, raw_cwd) {
        Ok(path) if std::path::Path::new(&path).is_absolute() => path,
        Ok(_) => unreachable!(),
        Err(code) => {
            return ParsedInstall::Unverified(UnverifiedInstallIntent {
                code,
                command_sha256,
            });
        }
    };
    let args = &tokens[args_start..];
    let manager_arg_end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let manager_args = &args[..manager_arg_end];
    let target_option = match manager {
        PackageManager::Npm => option_value(manager_args, &["--prefix"]),
        PackageManager::Yarn => option_value(manager_args, &["--cwd"]),
        PackageManager::Pnpm => option_value(manager_args, &["-C", "--dir", "--prefix"]),
        PackageManager::Poetry => option_value(manager_args, &["-C", "--directory"]),
        PackageManager::Uv => option_value(manager_args, &["--project"]),
        _ => Ok(None),
    };
    let target_dir = match target_option {
        Ok(Some(target)) => canonical_dir(Some(std::path::Path::new(&base_dir)), &target),
        Ok(None) => Ok(base_dir.clone()),
        Err(code) => Err(code),
    };
    let target_dir = match target_dir {
        Ok(path) => path,
        Err(code) => {
            return ParsedInstall::Unverified(UnverifiedInstallIntent {
                code,
                command_sha256,
            });
        }
    };
    if let Err(code) = ambient_resolution_context_is_clean(manager, &target_dir) {
        return ParsedInstall::Unverified(UnverifiedInstallIntent {
            code,
            command_sha256,
        });
    }

    let lower_args: Vec<String> = manager_args
        .iter()
        .map(|arg| arg.to_ascii_lowercase())
        .collect();
    const IMPLICIT_OPERATION: usize = usize::MAX - 1;
    const NO_POSITIONALS: usize = usize::MAX;
    let (operation, op_index) = if let Some(operation) = forced_operation {
        (operation, IMPLICIT_OPERATION)
    } else if manager == PackageManager::Go {
        if let Some(index) = lower_args.iter().position(|arg| arg == "get") {
            ("get", index)
        } else if let Some(index) = lower_args
            .iter()
            .position(|arg| matches!(arg.as_str(), "install" | "run"))
        {
            match lower_args[index].as_str() {
                "install" => ("install", index),
                "run" => ("run", index),
                _ => unreachable!(),
            }
        } else if let Some(index) = lower_args.iter().position(|arg| arg == "mod") {
            match lower_args.get(index + 1).map(String::as_str) {
                Some("tidy") => ("mod_tidy", index + 1),
                Some("download") => ("mod_download", index + 1),
                _ => return ParsedInstall::NotInstall,
            }
        } else {
            return if looks_like_package_manager(raw) {
                ParsedInstall::Unverified(UnverifiedInstallIntent {
                    code: "unsupported_package_manager_action",
                    command_sha256,
                })
            } else {
                ParsedInstall::NotInstall
            };
        }
    } else if manager == PackageManager::Uv
        && lower_args.iter().position(|arg| arg == "pip").is_some()
    {
        let Some(index) = lower_args.iter().position(|arg| arg == "install") else {
            return ParsedInstall::Unverified(UnverifiedInstallIntent {
                code: "unsupported_package_manager_action",
                command_sha256,
            });
        };
        ("install", index)
    } else {
        let operations: &[&str] = match manager {
            PackageManager::Npm => &["install", "i", "add", "ci", "exec"],
            PackageManager::Yarn => &["install", "add"],
            PackageManager::Pnpm => &["install", "i", "add", "dlx"],
            PackageManager::Bun => &["install", "add"],
            PackageManager::Cargo => &[
                "add", "install", "fetch", "update", "build", "check", "test", "run", "doc",
                "bench", "clippy",
            ],
            PackageManager::Pip => &["install", "run"],
            PackageManager::Uv => &["add", "sync"],
            PackageManager::Poetry => &["add", "install"],
            PackageManager::Go => unreachable!(),
        };
        match lower_args.iter().enumerate().find_map(|(index, arg)| {
            operations
                .iter()
                .copied()
                .find(|operation| *operation == arg.as_str())
                .map(|operation| (index, operation))
        }) {
            Some((index, operation)) => {
                let normalized = match operation {
                    "i" => "install",
                    other => other,
                };
                (normalized, index)
            }
            None => {
                let bare_yarn_install = if manager == PackageManager::Yarn {
                    let mut index = 0;
                    let mut valid = true;
                    while index < lower_args.len() {
                        match lower_args[index].as_str() {
                            "--cwd" => index += 2,
                            "--frozen-lockfile" | "--immutable" | "--immutable-cache"
                            | "--check-cache" | "--offline" | "--ignore-scripts" => index += 1,
                            _ => {
                                valid = false;
                                break;
                            }
                        }
                    }
                    valid && index <= lower_args.len()
                } else {
                    false
                };
                if bare_yarn_install {
                    ("install", NO_POSITIONALS)
                } else if looks_like_package_manager(raw) {
                    return ParsedInstall::Unverified(UnverifiedInstallIntent {
                        code: "unsupported_package_manager_action",
                        command_sha256,
                    });
                } else {
                    return ParsedInstall::NotInstall;
                }
            }
        }
    };

    if matches!(
        manager,
        PackageManager::Npm | PackageManager::Pnpm | PackageManager::Bun
    ) && manager_args.iter().enumerate().any(|(index, arg)| {
        let lower = arg.to_ascii_lowercase();
        lower.starts_with("-g")
            || lower.starts_with("--global")
            || lower == "--location=global"
            || lower == "--location"
                && manager_args
                    .get(index + 1)
                    .is_some_and(|value| value.eq_ignore_ascii_case("global"))
    }) {
        return ParsedInstall::Unverified(UnverifiedInstallIntent {
            code: "unsupported_global_install_context",
            command_sha256,
        });
    }

    let dangerous_flags = [
        "--git",
        "--path",
        "--registry",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--no-index",
        "--filter",
        "-f",
        "--workspace",
        "--workspace-root",
        "-c",
        "--constraint",
    ];
    let unsafe_flag_fragments = [
        "registry",
        "index",
        "userconfig",
        "globalconfig",
        "config",
        "source",
        "proxy",
        "cert",
        "keyfile",
        "trusted-host",
        "modfile",
        "lockfile-dir",
    ];
    if manager_args.iter().any(|arg| {
        let lower = arg.to_ascii_lowercase();
        dangerous_flags
            .iter()
            .any(|flag| arg == flag || arg.starts_with(&format!("{flag}=")))
            || lower.starts_with('-')
                && unsafe_flag_fragments
                    .iter()
                    .any(|fragment| lower.contains(fragment))
            || manager == PackageManager::Cargo
                && matches!(lower.as_str(), "-p" | "--package" | "--manifest-path")
    }) {
        return ParsedInstall::Unverified(UnverifiedInstallIntent {
            code: "unsupported_source_or_workspace_selector",
            command_sha256,
        });
    }

    let value_options = [
        "--prefix",
        "--cwd",
        "-C",
        "--dir",
        "--directory",
        "--project",
        "--manifest-path",
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "--target",
        "--root",
        "--tag",
        "--omit",
        "--include",
        "--package",
        "-p",
        "--jobs",
        "-j",
        "--features",
    ];
    let explicit_runner_package = match (manager, operation) {
        (PackageManager::Npm, "exec") => option_value(manager_args, &["--package", "-p"]),
        (PackageManager::Uv, "run") => option_value(manager_args, &["--from"]),
        (PackageManager::Pip, "run") => option_value(manager_args, &["--spec"]),
        _ => Ok(None),
    };
    let explicit_runner_package = match explicit_runner_package {
        Ok(package) => package,
        Err(code) => {
            return ParsedInstall::Unverified(UnverifiedInstallIntent {
                code,
                command_sha256,
            });
        }
    };

    let mut positionals = Vec::new();
    let mut i = match op_index {
        IMPLICIT_OPERATION => 0,
        NO_POSITIONALS => args.len(),
        index => index + 1,
    };
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            positionals.extend(args[i + 1..].iter().cloned());
            break;
        }
        if value_options.contains(&arg.as_str()) {
            i += 2;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        positionals.push(arg.clone());
        i += 1;
    }

    let direct = matches!(
        (manager, operation),
        (PackageManager::Npm, "install" | "add" | "exec")
            | (PackageManager::Yarn, "add")
            | (PackageManager::Pnpm, "install" | "add" | "dlx")
            | (PackageManager::Bun, "install" | "add" | "exec")
            | (PackageManager::Cargo, "add" | "install")
            | (PackageManager::Pip, "install" | "run")
            | (PackageManager::Uv, "add" | "install" | "run")
            | (PackageManager::Poetry, "add")
            | (PackageManager::Go, "get" | "install" | "run")
    );
    let coordinate_manager = if manager == PackageManager::Uv && operation == "install" {
        PackageManager::Pip
    } else {
        manager
    };
    let mut packages = Vec::new();
    if direct {
        let single_package_runner = matches!(
            (manager, operation),
            (PackageManager::Npm, "exec")
                | (PackageManager::Pnpm, "dlx")
                | (PackageManager::Bun, "exec")
                | (PackageManager::Pip, "run")
                | (PackageManager::Uv, "run")
                | (PackageManager::Go, "run")
        );
        let requested = if let Some(package) = explicit_runner_package.as_ref() {
            vec![package]
        } else if single_package_runner {
            positionals.iter().take(1).collect()
        } else {
            positionals.iter().collect()
        };
        for positional in requested {
            match registry_request(coordinate_manager, positional) {
                Ok(package) => packages.push(package),
                Err(code) => {
                    return ParsedInstall::Unverified(UnverifiedInstallIntent {
                        code,
                        command_sha256,
                    });
                }
            }
        }
        if single_package_runner && packages.is_empty() {
            return ParsedInstall::Unverified(UnverifiedInstallIntent {
                code: "exact_registry_coordinate_required",
                command_sha256,
            });
        }
    } else if !positionals.is_empty() {
        return ParsedInstall::Unverified(UnverifiedInstallIntent {
            code: "unexpected_package_manager_arguments",
            command_sha256,
        });
    }
    packages.sort();
    packages.dedup();
    if !packages.is_empty() {
        return ParsedInstall::Unverified(UnverifiedInstallIntent {
            code: "transitive_resolution_unproven",
            command_sha256,
        });
    }

    let resolution = match locked_resolution_inputs(manager, operation, manager_args, &target_dir) {
        Ok(inputs) => inputs,
        Err(code) => {
            return ParsedInstall::Unverified(UnverifiedInstallIntent {
                code,
                command_sha256,
            });
        }
    };
    let manager_name = match executable.as_str() {
        "npx" => "npx",
        "bunx" => "bunx",
        "pipx" => "pipx",
        "uvx" => "uvx",
        _ => match manager {
            PackageManager::Npm => "npm",
            PackageManager::Yarn => "yarn",
            PackageManager::Pnpm => "pnpm",
            PackageManager::Bun => "bun",
            PackageManager::Cargo => "cargo",
            PackageManager::Pip => "pip",
            PackageManager::Uv => "uv",
            PackageManager::Poetry => "poetry",
            PackageManager::Go => "go",
        },
    };
    let binding_sha256 = sha256_text(&format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}",
        call.server,
        call.tool,
        manager_name,
        operation,
        target_dir,
        command_sha256,
        arguments_sha256,
    ));
    ParsedInstall::Scan(InstallIntent {
        server: call.server.clone(),
        tool: call.tool.clone(),
        manager: manager_name,
        operation,
        target_dir,
        command_sha256,
        binding_sha256,
        manifests: resolution.bound,
        resolution_locks: resolution.locks,
        packages,
    })
}

fn validate_approval(
    approval: &InstallApproval,
    intent: &InstallIntent,
) -> Result<(), &'static str> {
    let approved_paths = approval
        .manifests
        .iter()
        .map(|manifest| manifest.path.as_str())
        .collect::<Vec<_>>();
    let intent_paths = intent
        .manifests
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if approval.binding_sha256 != intent.binding_sha256 {
        return Err("install_permit_binding_mismatch");
    }
    if approved_paths != intent_paths {
        return Err("install_permit_manifest_set_mismatch");
    }
    if !approval.manifests.iter().all(|manifest| {
        crate::security::dep_health::manifest_sha256(std::path::Path::new(&manifest.path))
            .is_ok_and(|current| current == manifest.sha256)
    }) {
        return Err("manifest_changed_after_approval");
    }
    Ok(())
}

impl ToolInspector for ManifestInstallInspector {
    fn name(&self) -> &'static str {
        "manifest_install"
    }

    fn inspect(&mut self, call: &ParsedToolCall, _policy: &SecurityPolicy) -> InspectorVerdict {
        self.ready = None;
        match parse_install(call) {
            ParsedInstall::NotInstall => InspectorVerdict::Allow,
            ParsedInstall::Unverified(intent) => InspectorVerdict::Block {
                inspector: "manifest_install",
                kind: BlockKind::ManifestGate {
                    request: InstallGateRequest::Unverified(intent),
                },
            },
            ParsedInstall::Scan(intent) => {
                if let Some(approval) = self.approved.take() {
                    if validate_approval(&approval, &intent).is_ok() {
                        self.ready = Some(approval);
                        return InspectorVerdict::Allow;
                    }
                }
                InspectorVerdict::Block {
                    inspector: "manifest_install",
                    kind: BlockKind::ManifestGate {
                        request: InstallGateRequest::Scan(intent),
                    },
                }
            }
        }
    }

    fn on_install_scan_proven(&mut self, approval: InstallApproval) {
        self.approved = Some(approval);
    }

    fn consume_install_permit(&mut self, call: &ParsedToolCall) -> Result<(), &'static str> {
        match parse_install(call) {
            ParsedInstall::NotInstall => Ok(()),
            ParsedInstall::Unverified(_) => Err("install_intent_became_unverified"),
            ParsedInstall::Scan(intent) => {
                let Some(approval) = self.ready.take() else {
                    return Err("install_permit_missing");
                };
                validate_approval(&approval, &intent)
            }
        }
    }
}

/// Ordered chain of inspectors. The FIRST block wins. Hard, unliftable guards
/// must precede the risk-policy inspector because the dispatch loop may lift a
/// risk block with an operator lease and then execute the call without another
/// inspection pass.
pub struct ToolInspectorChain {
    inspectors: Vec<Box<dyn ToolInspector>>,
}

impl ToolInspectorChain {
    /// The shipped chain: repetition guard + unconditional secret-egress and
    /// manifest guards + the lease-liftable risk policy last.
    pub fn with_defaults() -> Self {
        Self {
            inspectors: vec![
                Box::new(RepetitionInspector(ToolRepetitionGuard::with_defaults())),
                Box::new(SecretEgressInspector),
                Box::new(ManifestInstallInspector::new()),
                Box::new(RiskPolicyInspector),
            ],
        }
    }

    /// Build from an explicit inspector list (tests / future custom chains).
    pub fn new(inspectors: Vec<Box<dyn ToolInspector>>) -> Self {
        Self { inspectors }
    }

    /// Record one conclusive, exact-intent install approval.
    pub fn on_install_scan_proven(&mut self, approval: InstallApproval) {
        for insp in self.inspectors.iter_mut() {
            insp.on_install_scan_proven(approval.clone());
        }
    }

    /// Consume and revalidate any package-manager permit immediately before
    /// dispatch. Non-install calls are no-ops in every inspector.
    pub fn consume_install_permit(&mut self, call: &ParsedToolCall) -> Result<(), &'static str> {
        for inspector in self.inspectors.iter_mut() {
            inspector.consume_install_permit(call)?;
        }
        Ok(())
    }

    /// Run inspectors in order; return the FIRST block, else `Allow`. Every
    /// inspector up to (and including) the first blocker is run, so stateful
    /// inspectors before the blocker still record the attempt.
    pub fn inspect(&mut self, call: &ParsedToolCall, policy: &SecurityPolicy) -> InspectorVerdict {
        for insp in self.inspectors.iter_mut() {
            match insp.inspect(call, policy) {
                InspectorVerdict::Allow => continue,
                block => return block,
            }
        }
        InspectorVerdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(server: &str, tool: &str, args: serde_json::Value) -> ParsedToolCall {
        ParsedToolCall {
            server: server.into(),
            tool: tool.into(),
            arguments: args,
        }
    }

    fn policy() -> SecurityPolicy {
        SecurityPolicy::default()
    }

    #[test]
    fn clean_call_passes_the_whole_chain() {
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call("fs", "read", serde_json::json!({ "path": "notes.md" }));
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Allow
        ));
    }

    #[test]
    fn repetition_inspector_blocks_a_repeated_call() {
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call("fs", "read", serde_json::json!({ "path": "a" }));
        // Defaults: a 4th identical call in a row blocks.
        for _ in 0..3 {
            assert!(matches!(
                chain.inspect(&c, &policy()),
                InspectorVerdict::Allow
            ));
        }
        match chain.inspect(&c, &policy()) {
            InspectorVerdict::Block {
                inspector,
                kind: BlockKind::Repetition(_),
            } => {
                assert_eq!(inspector, "repetition")
            }
            _ => panic!("expected a repetition block on the 4th identical call"),
        }
    }

    #[test]
    fn risk_inspector_blocks_a_dangerous_command_under_default_deny() {
        let mut chain = ToolInspectorChain::with_defaults();
        // The default dangerous-command policy is Deny.
        let c = call("sh", "exec", serde_json::json!({ "command": "rm -rf /" }));
        match chain.inspect(&c, &policy()) {
            InspectorVerdict::Block {
                inspector,
                kind: BlockKind::Risk { gate, .. },
            } => {
                assert_eq!(inspector, "risk_policy");
                assert!(gate.is_blocked());
            }
            _ => panic!("expected a risk block for a dangerous command"),
        }
    }

    #[test]
    fn repetition_is_checked_before_risk() {
        // A call that is BOTH repeated past the threshold AND dangerous must
        // surface as a Repetition block (repetition runs first), never Risk.
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call("sh", "exec", serde_json::json!({ "command": "rm -rf /" }));
        // First three are risk-blocks (dangerous), but they also tick the
        // repetition counter; the 4th identical call trips repetition first.
        for _ in 0..3 {
            assert!(matches!(
                chain.inspect(&c, &policy()),
                InspectorVerdict::Block {
                    kind: BlockKind::Risk { .. },
                    ..
                }
            ));
        }
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Block {
                kind: BlockKind::Repetition(_),
                ..
            }
        ));
    }

    #[test]
    fn unconditional_secret_guard_precedes_lease_liftable_risk() {
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call(
            "sh",
            "exec",
            serde_json::json!({
                "command": "rm -rf /",
                "token": "sk-testFAKEkey1234567890ABCDEFGHIJ"
            }),
        );
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Block {
                inspector: "secret_egress",
                kind: BlockKind::SecretEgress { .. },
            }
        ));
    }

    #[test]
    fn manifest_guard_precedes_lease_liftable_risk() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        std::fs::write(&manifest, "{\"dependencies\":{\"serde\":\"1\"}}").unwrap();
        let manifest = manifest.to_string_lossy().into_owned();
        let mut chain = ToolInspectorChain::with_defaults();
        let edit = call(
            "fs",
            "write_file",
            serde_json::json!({ "path": &manifest, "content": "{}" }),
        );
        assert!(matches!(
            chain.inspect(&edit, &policy()),
            InspectorVerdict::Allow
        ));
        let risky_install = call(
            "sh",
            "exec",
            serde_json::json!({ "command": "npm install && rm -rf /" }),
        );
        assert!(matches!(
            chain.inspect(&risky_install, &policy()),
            InspectorVerdict::Block {
                inspector: "manifest_install",
                kind: BlockKind::ManifestGate { .. },
            }
        ));
    }

    #[test]
    fn custom_pure_inspector_bolts_on_without_a_loop_edit() {
        // Demonstrates the extensibility seam: a new inspector just implements
        // the trait + joins the chain; the dispatch loop never changes.
        struct DenyAll;
        impl ToolInspector for DenyAll {
            fn name(&self) -> &'static str {
                "deny_all"
            }
            fn inspect(&mut self, _c: &ParsedToolCall, _p: &SecurityPolicy) -> InspectorVerdict {
                InspectorVerdict::Block {
                    inspector: "deny_all",
                    kind: BlockKind::Repetition(GuardVerdict::Allow),
                }
            }
        }
        let mut chain = ToolInspectorChain::new(vec![Box::new(DenyAll)]);
        let c = call("fs", "read", serde_json::json!({}));
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Block {
                inspector: "deny_all",
                ..
            }
        ));
    }

    // ── GOLD-ADAPT-CAF-01: SecretEgressInspector ─────────────────────────────

    #[test]
    fn secret_egress_blocks_openai_key_in_payload() {
        // A fetch/http tool whose body carries a fake OpenAI key must be
        // blocked before dispatch. The key matches the `openai_key` pattern
        // (sk- prefix, ≥20 alphanum chars).
        let mut insp = SecretEgressInspector;
        let c = call(
            "http",
            "fetch",
            serde_json::json!({
                "url": "https://example.com/api",
                "headers": { "Authorization": "Bearer sk-testFAKEkey1234567890ABCDEFGHIJ" }
            }),
        );
        match insp.inspect(&c, &policy()) {
            InspectorVerdict::Block {
                inspector,
                kind: BlockKind::SecretEgress { pattern, redacted },
            } => {
                assert_eq!(inspector, "secret_egress");
                assert_eq!(pattern, "openai_key");
                // Redacted must not contain the full secret (first 4 + last 4
                // visible; middle masked). The full key is 30+ chars so the
                // redacted form must include the masking ellipsis.
                assert!(
                    redacted.contains('…'),
                    "expected masked redaction, got: {redacted}"
                );
            }
            _ => panic!("expected secret_egress block for payload containing an OpenAI key"),
        }
    }

    #[test]
    fn secret_egress_blocks_aws_access_key_in_payload() {
        // AWS access key IDs follow the AKIA[0-9A-Z]{16} shape.
        let mut insp = SecretEgressInspector;
        let c = call(
            "channel",
            "send",
            serde_json::json!({
                "body": "My key is AKIAIOSFODNN7EXAMPLE and I need help"
            }),
        );
        match insp.inspect(&c, &policy()) {
            InspectorVerdict::Block {
                inspector,
                kind: BlockKind::SecretEgress { pattern, .. },
            } => {
                assert_eq!(inspector, "secret_egress");
                assert_eq!(pattern, "aws_access_key_id");
            }
            _ => panic!("expected secret_egress block for payload containing an AWS key"),
        }
    }

    #[test]
    fn secret_egress_allows_clean_payload() {
        // A normal tool call with no credential-shaped values must pass.
        let mut insp = SecretEgressInspector;
        let c = call(
            "fs",
            "read_file",
            serde_json::json!({ "path": "/home/user/notes.md" }),
        );
        assert!(
            matches!(insp.inspect(&c, &policy()), InspectorVerdict::Allow),
            "clean payload must not be blocked by secret_egress inspector"
        );
    }

    // ── GOLD-ADAPT-SNYK-02: ManifestInstallInspector ─────────────────────────

    fn scan_intent(insp: &mut ManifestInstallInspector, install: &ParsedToolCall) -> InstallIntent {
        match insp.inspect(install, &policy()) {
            InspectorVerdict::Block {
                inspector: "manifest_install",
                kind:
                    BlockKind::ManifestGate {
                        request: InstallGateRequest::Scan(intent),
                    },
            } => intent,
            _ => panic!("expected exact install scan request"),
        }
    }

    fn unverified_code(
        insp: &mut ManifestInstallInspector,
        install: &ParsedToolCall,
    ) -> &'static str {
        match insp.inspect(install, &policy()) {
            InspectorVerdict::Block {
                inspector: "manifest_install",
                kind:
                    BlockKind::ManifestGate {
                        request: InstallGateRequest::Unverified(intent),
                    },
            } => intent.code,
            _ => panic!("expected fail-closed package-manager request"),
        }
    }

    fn approval_for(intent: &InstallIntent) -> InstallApproval {
        InstallApproval {
            binding_sha256: intent.binding_sha256.clone(),
            manifests: intent
                .manifests
                .iter()
                .map(|path| ManifestSnapshotApproval {
                    path: path.clone(),
                    sha256: crate::security::dep_health::manifest_sha256(std::path::Path::new(
                        path,
                    ))
                    .unwrap(),
                })
                .collect(),
        }
    }

    fn write_npm_locked_project(dir: &std::path::Path) {
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"fixture","version":"1.0.0","dependencies":{"left-pad":"^1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
                "name":"fixture",
                "version":"1.0.0",
                "lockfileVersion":3,
                "packages":{
                    "":{"name":"fixture","version":"1.0.0","dependencies":{"left-pad":"^1.0.0"}},
                    "node_modules/left-pad":{
                        "version":"1.3.0",
                        "resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                        "integrity":"sha512-fixture"
                    }
                }
            }"#,
        )
        .unwrap();
    }

    fn write_cargo_locked_project(dir: &std::path::Path) {
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n[dependencies]\nserde='1'\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("Cargo.lock"),
            r#"version = 4

[[package]]
name = "fixture"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fixture"
"#,
        )
        .unwrap();
    }

    #[test]
    fn exact_coordinate_parsers_are_ecosystem_specific() {
        let npm = registry_request(PackageManager::Npm, "left-pad@1.3.0").unwrap();
        assert_eq!(npm.version.as_deref(), Some("1.3.0"));
        assert!(registry_request(PackageManager::Npm, "left-pad@1.x").is_err());
        assert!(registry_request(PackageManager::Npm, "left-pad@1.latest").is_err());

        for version in ["1.0", "2024.1", "1!2.0", "2.0rc1"] {
            let request =
                registry_request(PackageManager::Pip, &format!("package=={version}")).unwrap();
            assert_eq!(request.version.as_deref(), Some(version));
        }
        assert!(registry_request(PackageManager::Pip, "package==1.*").is_err());
    }

    #[test]
    fn direct_mutations_and_fetch_runners_fail_closed_without_transitive_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("app");
        std::fs::create_dir(&app).unwrap();
        std::fs::write(app.join("package.json"), "{\"dependencies\":{}}\n").unwrap();
        std::fs::write(
            app.join("Cargo.toml"),
            "[package]\nname='x'\nversion='0.1.0'\n",
        )
        .unwrap();
        let cases = [
            ("npm --prefix app install left-pad@1.3.0", dir.path()),
            ("pnpm -C app add left-pad@1.3.0", dir.path()),
            ("cargo +nightly add serde@1.0.228", app.as_path()),
            ("python -m pip install requests==2.32.0", app.as_path()),
            ("npm exec --package runner@1.2.3 -- runner", app.as_path()),
            ("npx runner@1.2.3", app.as_path()),
            ("pnpm dlx runner@1.2.3", app.as_path()),
            ("bunx runner@1.2.3", app.as_path()),
            ("uvx runner==1.0", app.as_path()),
            ("pipx run runner==1.0", app.as_path()),
            ("pipx install runner==1.0", app.as_path()),
            ("go install example.com/runner@v1.2.3", app.as_path()),
            ("go run example.com/runner@v1.2.3", app.as_path()),
        ];
        for (command, cwd) in cases {
            let mut insp = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": cwd}),
            );
            assert_eq!(
                unverified_code(&mut insp, &install),
                "transitive_resolution_unproven",
                "{command}"
            );
        }
    }

    #[test]
    fn ranged_sources_with_exact_locks_get_one_shot_permits() {
        let npm = tempfile::tempdir().unwrap();
        write_npm_locked_project(npm.path());
        let npm_ci = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": npm.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &npm_ci);
        assert_eq!(intent.manifests.len(), 2);
        assert_eq!(intent.resolution_locks.len(), 1);
        assert!(intent.resolution_locks[0].ends_with("package-lock.json"));
        insp.on_install_scan_proven(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&npm_ci, &policy()),
            InspectorVerdict::Allow
        ));
        assert!(insp.consume_install_permit(&npm_ci).is_ok());

        let cargo = tempfile::tempdir().unwrap();
        write_cargo_locked_project(cargo.path());
        let cargo_check = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "cargo check --locked", "cwd": cargo.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &cargo_check);
        assert_eq!(intent.manifests.len(), 2);
        assert_eq!(intent.resolution_locks.len(), 1);
        assert!(intent.resolution_locks[0].ends_with("Cargo.lock"));
        insp.on_install_scan_proven(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&cargo_check, &policy()),
            InspectorVerdict::Allow
        ));
        assert!(insp.consume_install_permit(&cargo_check).is_ok());
    }

    #[test]
    fn ranges_without_the_expected_lock_and_unpinned_fetchers_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"left-pad":"^1.0.0"}}"#,
        )
        .unwrap();
        let npm_ci = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        assert_eq!(
            unverified_code(&mut insp, &npm_ci),
            "required_lockfile_missing"
        );

        for command in [
            "npm exec --package runner@1 -- runner",
            "npx runner@1.x",
            "pnpm dlx runner@1.latest",
            "bunx runner@1",
            "uvx runner==1.*",
            "pipx run runner",
            "pipx install runner",
            "go install example.com/runner@v1",
            "go run example.com/runner@latest",
        ] {
            let mut insp = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            let code = unverified_code(&mut insp, &install);
            if command == "uvx runner==1.*" {
                assert_eq!(code, "shell_expansion_unsupported", "{command}");
            } else {
                assert!(
                    code.contains("exact_registry_version"),
                    "{command} must fail closed"
                );
            }
        }
    }

    #[test]
    fn windows_launcher_suffixes_and_paths_never_bypass_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(dir.path());
        for command in [
            "npm.cmd ci",
            "NPM.EXE ci",
            r#"C:\tools\nodejs\npm.cmd ci"#,
            r#"C:\tools\nodejs\NPM.BAT ci"#,
        ] {
            let mut insp = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            let intent = scan_intent(&mut insp, &install);
            assert_eq!(intent.manager, "npm", "{command}");
            assert_eq!(intent.operation, "ci", "{command}");
        }
    }

    #[test]
    fn shell_expansions_and_global_install_contexts_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        for command in [
            "npm ci --flag=$EVIL",
            "npm ci --flag=%EVIL%",
            "npm ci --flag=!EVIL!",
            "npm ci ^--ignore-scripts",
            "npm ci --workspace=*",
            "npm ci --workspace=?",
            "npm ci --workspace={a,b}",
            "npm ci --workspace=[ab]",
            "npm ci --prefix ~/app",
        ] {
            let mut insp = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            assert_eq!(
                unverified_code(&mut insp, &install),
                "shell_expansion_unsupported",
                "{command}"
            );
        }

        for command in [
            "npm -g ci",
            "npm ci --global",
            "npm ci --global=true",
            "npm ci --location=global",
            "npm ci --location GLOBAL",
            "pnpm install --global-dir global --frozen-lockfile",
            "bun install -g",
        ] {
            let mut insp = ManifestInstallInspector::new();
            let install = call(
                "local-shell",
                "exec",
                serde_json::json!({"command": command, "cwd": dir.path()}),
            );
            assert_eq!(
                unverified_code(&mut insp, &install),
                "unsupported_global_install_context",
                "{command}"
            );
        }
    }

    #[test]
    fn unrecognized_command_fields_with_package_manager_text_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut insp = ManifestInstallInspector::new();
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"shell_command": "npm ci", "cwd": dir.path()}),
        );
        assert_eq!(
            unverified_code(&mut insp, &install),
            "command_field_unrecognized"
        );
    }

    #[test]
    fn ambient_configs_and_parent_workspaces_fail_closed() {
        let npm_root = tempfile::tempdir().unwrap();
        let npm_child = npm_root.path().join("packages").join("child");
        std::fs::create_dir_all(&npm_child).unwrap();
        write_npm_locked_project(&npm_child);
        std::fs::write(
            npm_root.path().join("package.json"),
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        let npm_ci = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": &npm_child}),
        );
        let mut insp = ManifestInstallInspector::new();
        assert_eq!(
            unverified_code(&mut insp, &npm_ci),
            "ambient_workspace_context"
        );

        let cargo_root = tempfile::tempdir().unwrap();
        let cargo_child = cargo_root.path().join("member");
        std::fs::create_dir(&cargo_child).unwrap();
        write_cargo_locked_project(&cargo_child);
        std::fs::write(
            cargo_root.path().join("Cargo.toml"),
            "[workspace]\nmembers=['member']\n",
        )
        .unwrap();
        let cargo_check = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "cargo check --locked", "cwd": &cargo_child}),
        );
        let mut insp = ManifestInstallInspector::new();
        assert_eq!(
            unverified_code(&mut insp, &cargo_check),
            "ambient_workspace_context"
        );

        let config_dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(config_dir.path());
        std::fs::write(
            config_dir.path().join(".npmrc"),
            "registry=https://example.invalid/\n",
        )
        .unwrap();
        let npm_ci = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": config_dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        assert_eq!(
            unverified_code(&mut insp, &npm_ci),
            "ambient_package_manager_config"
        );
    }

    #[test]
    fn missing_cwd_combined_remote_and_non_registry_forms_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        for arguments in [
            serde_json::json!({"command": "npm install left-pad"}),
            serde_json::json!({"command": "npm install left-pad", "cwd": dir.path()}),
            serde_json::json!({"command": "npm install left-pad@latest", "cwd": dir.path()}),
            serde_json::json!({"command": "cargo add left-pad@latest", "cwd": dir.path()}),
            serde_json::json!({"command": "go get example.com/mod@latest", "cwd": dir.path()}),
            serde_json::json!({"command": "ssh host npm install left-pad", "cwd": dir.path()}),
            serde_json::json!({"command": "npm install ok && npm install evil", "cwd": dir.path()}),
            serde_json::json!({"command": "pip install git+https://example.invalid/x", "cwd": dir.path()}),
            serde_json::json!({"command": "NPM_CONFIG_REGISTRY=https://example.invalid npm install x@1.0.0", "cwd": dir.path()}),
            serde_json::json!({"command": "npm --userconfig customrc install x@1.0.0", "cwd": dir.path()}),
            serde_json::json!({"command": "cargo --config net.git-fetch-with-cli=true add x@1.0.0", "cwd": dir.path()}),
            serde_json::json!({"command": "pip install -c constraints.txt x==1.0.0", "cwd": dir.path()}),
            serde_json::json!({"command": "cargo build -p member", "cwd": dir.path()}),
            serde_json::json!({"command": "cargo check --locked", "cwd": dir.path(), "env": {"CARGO_REGISTRY_DEFAULT": "evil"}}),
            serde_json::json!({"command": "npm install x@1.0.0", "cmd": "npm install y@1.0.0", "cwd": dir.path()}),
            serde_json::json!({"command": "npm install x@1.0.0", "cwd": dir.path(), "workdir": dir.path()}),
        ] {
            let mut insp = ManifestInstallInspector::new();
            let install = call("shell", "exec", arguments);
            assert!(matches!(
                insp.inspect(&install, &policy()),
                InspectorVerdict::Block {
                    kind: BlockKind::ManifestGate {
                        request: InstallGateRequest::Unverified(_),
                    },
                    ..
                }
            ));
        }
    }

    #[test]
    fn approval_is_one_shot_and_bound_to_the_full_exact_intent() {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_locked_project(dir.path());
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "cargo check --locked", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &install);
        insp.on_install_scan_proven(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Allow
        ));
        assert!(insp.consume_install_permit(&install).is_ok());
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Block {
                kind: BlockKind::ManifestGate { .. },
                ..
            }
        ));

        let other_dir = tempfile::tempdir().unwrap();
        write_cargo_locked_project(other_dir.path());
        let mut changed_server = install.clone();
        changed_server.server = "other-shell".into();
        let mut changed_tool = install.clone();
        changed_tool.tool = "run".into();
        let changed_command = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "cargo build --locked", "cwd": dir.path()}),
        );
        let changed_target = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "cargo check --locked", "cwd": other_dir.path()}),
        );
        // Same parsed command and cwd, but different MCP argument keys. This
        // proves the binding covers the complete argument object, not only the
        // parser's normalized values.
        let changed_argument_shape = call(
            "local-shell",
            "exec",
            serde_json::json!({"cmd": "cargo check --locked", "directory": dir.path()}),
        );
        for changed in [
            changed_server,
            changed_tool,
            changed_command,
            changed_target,
            changed_argument_shape,
        ] {
            let mut binding_insp = ManifestInstallInspector::new();
            let intent = scan_intent(&mut binding_insp, &install);
            binding_insp.on_install_scan_proven(approval_for(&intent));
            assert!(matches!(
                binding_insp.inspect(&changed, &policy()),
                InspectorVerdict::Block {
                    kind: BlockKind::ManifestGate {
                        request: InstallGateRequest::Scan(_),
                    },
                    ..
                }
            ));
        }
    }

    #[test]
    fn final_dispatch_rehash_rejects_post_inspection_manifest_swap() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        write_npm_locked_project(dir.path());
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &install);
        insp.on_install_scan_proven(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Allow
        ));
        std::fs::write(
            &manifest,
            r#"{"name":"fixture","version":"1.0.0","dependencies":{"left-pad":"^2.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(
            insp.consume_install_permit(&install),
            Err("manifest_changed_after_approval")
        );
    }

    #[test]
    fn newly_created_lockfile_invalidates_the_approved_manifest_set() {
        let dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(dir.path());
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &install);
        assert_eq!(intent.manifests.len(), 2);
        insp.on_install_scan_proven(approval_for(&intent));
        std::fs::copy(
            dir.path().join("package-lock.json"),
            dir.path().join("npm-shrinkwrap.json"),
        )
        .unwrap();
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Block {
                kind: BlockKind::ManifestGate {
                    request: InstallGateRequest::Scan(_),
                },
                ..
            }
        ));
    }

    #[test]
    fn final_dispatch_rejects_a_lockfile_created_after_inspection() {
        let dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(dir.path());
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &install);
        insp.on_install_scan_proven(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Allow
        ));
        std::fs::copy(
            dir.path().join("package-lock.json"),
            dir.path().join("npm-shrinkwrap.json"),
        )
        .unwrap();
        assert_eq!(
            insp.consume_install_permit(&install),
            Err("install_permit_manifest_set_mismatch")
        );
    }

    #[test]
    fn final_dispatch_rehash_rejects_post_inspection_lock_swap() {
        let dir = tempfile::tempdir().unwrap();
        write_npm_locked_project(dir.path());
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "npm ci", "cwd": dir.path()}),
        );
        let mut insp = ManifestInstallInspector::new();
        let intent = scan_intent(&mut insp, &install);
        insp.on_install_scan_proven(approval_for(&intent));
        assert!(matches!(
            insp.inspect(&install, &policy()),
            InspectorVerdict::Allow
        ));
        let lock = dir.path().join("package-lock.json");
        let mut body = std::fs::read_to_string(&lock).unwrap();
        body.push('\n');
        std::fs::write(lock, body).unwrap();
        assert_eq!(
            insp.consume_install_permit(&install),
            Err("manifest_changed_after_approval")
        );
    }

    #[test]
    fn bare_yarn_frozen_lockfile_is_a_manifest_install() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{\"dependencies\":{}}\n").unwrap();
        std::fs::write(dir.path().join("yarn.lock"), "# empty lock\n").unwrap();
        let mut insp = ManifestInstallInspector::new();
        let install = call(
            "local-shell",
            "exec",
            serde_json::json!({"command": "yarn --frozen-lockfile", "cwd": dir.path()}),
        );
        let intent = scan_intent(&mut insp, &install);
        assert_eq!(intent.manager, "yarn");
        assert_eq!(intent.operation, "install");
        assert_eq!(intent.manifests.len(), 2);
        assert_eq!(intent.resolution_locks.len(), 1);
    }

    #[test]
    fn non_package_manager_call_still_allows() {
        let dir = tempfile::tempdir().unwrap();
        let mut insp = ManifestInstallInspector::new();
        let call = call(
            "shell",
            "exec",
            serde_json::json!({"command": "git status", "cwd": dir.path()}),
        );
        assert!(matches!(
            insp.inspect(&call, &policy()),
            InspectorVerdict::Allow
        ));
        assert!(insp.consume_install_permit(&call).is_ok());
    }
}
