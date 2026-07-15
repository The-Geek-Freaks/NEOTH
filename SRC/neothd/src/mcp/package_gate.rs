//! Strict, fail-closed package-install intent parsing for the MCP dispatch gate.
//!
//! This module is deliberately pure except for canonical filesystem reads used to
//! bind an install permit to exact manifests and lockfiles. The stateful inspector
//! remains in `tool_inspection`; this module owns only the typed intent and parser.

use crate::mcp::tool_call_parser::ParsedToolCall;
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
    Scan(Box<InstallIntent>),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PackageManager {
    Npm,
    Yarn,
    Pnpm,
    Bun,
    Cargo,
    Pip,
    Pipenv,
    Uv,
    Poetry,
    Go,
}

pub(super) enum ParsedInstall {
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
        "pipenv", "poetry", "go",
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

pub(super) fn registry_request(
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
        PackageManager::Pip
        | PackageManager::Pipenv
        | PackageManager::Uv
        | PackageManager::Poetry => {
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

pub(super) fn is_ambient_resolution_override(manager: PackageManager, key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    match manager {
        PackageManager::Npm | PackageManager::Yarn | PackageManager::Pnpm | PackageManager::Bun => {
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
        PackageManager::Pip
        | PackageManager::Pipenv
        | PackageManager::Uv
        | PackageManager::Poetry => {
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
                    | "PIPENV_PYPI_MIRROR"
                    | "PIPENV_PIPFILE"
                    | "POETRY_REPOSITORIES"
            )
        }
        PackageManager::Go => matches!(
            key.as_str(),
            "GOPROXY" | "GONOPROXY" | "GOPRIVATE" | "GONOSUMDB" | "GOSUMDB" | "GOENV" | "GOWORK"
        ),
    }
}

fn ambient_resolution_context_is_clean(
    manager: PackageManager,
    target_dir: &str,
) -> Result<(), &'static str> {
    let base = std::path::Path::new(target_dir);
    let env_override = std::env::vars_os()
        .any(|(key, _)| is_ambient_resolution_override(manager, &key.to_string_lossy()));
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
        PackageManager::Pip
        | PackageManager::Pipenv
        | PackageManager::Uv
        | PackageManager::Poetry => [
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
    let lifecycle_scripts_must_be_disabled = matches!(
        (manager, operation),
        (PackageManager::Npm, "ci")
            | (PackageManager::Yarn, "install")
            | (PackageManager::Pnpm, "install")
            | (PackageManager::Bun, "install")
    );
    if lifecycle_scripts_must_be_disabled && !has_flag(&["--ignore-scripts"]) {
        return Err("lifecycle_scripts_not_disabled");
    }
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
        (PackageManager::Bun, "install") if has_flag(&["--frozen-lockfile"]) => {
            if base.join("bun.lockb").exists() {
                return Err("binary_bun_lockfile_unsupported");
            }
            ("package.json", &["bun.lock"])
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

pub(super) fn parse_install(call: &ParsedToolCall) -> ParsedInstall {
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
        "pipenv" => PackageManager::Pipenv,
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
            PackageManager::Pipenv => &["install", "sync"],
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
            | (PackageManager::Pipenv, "install")
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
            PackageManager::Pipenv => "pipenv",
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

pub(super) fn validate_approval(
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
