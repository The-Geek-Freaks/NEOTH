//! U-01 + U-03 probe builders — bridges the existing
//! `self_update::check_for_update` (GitHub Releases) +
//! `check_all` (npm CLI versions) probes into the
//! `ComponentSpec` shape the U-04 cron loop consumes.
//!
//! The cron loop's builder runs on `tokio::task::spawn_blocking`. Each probe
//! here exposes both async + sync wrappers:
//!
//!   - `*_specs_async()` for callers in async contexts (tests,
//!     ad-hoc CLI subcommands).
//!   - `*_specs_blocking()` for the cron-builder closure — uses
//!     `tokio::runtime::Handle::current().block_on()` to drive
//!     the async probe from the blocking thread.
//!
//! A denied gate short-circuits before repository validation, npm, DNS, or Git
//! and yields auditable `SkippedByGate` rows. Failure modes are otherwise
//! encoded in the `ComponentSpec.latest_version
//! : Result<String, String>` field: a network error becomes
//! `Err("github probe: <msg>")` which `compute_outcome` turns
//! into `ComponentStatus::Failed`. The cron loop still emits the
//! audit frame so operators see "yes, the cron ran; yes, it
//! tried; here's why it didn't have a latest_version answer".

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::config::ReleaseChannel;
use crate::skills::store::{open_bound_directory, open_real_child_dir, read_regular_file_bounded};
use crate::updater::pipeline::{ComponentSpec, GateDecision, cli_version_specs, neoth_self_specs};
use crate::updater::self_update::{check_for_update_channel, current_version};

const MAX_UPDATE_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_COMPONENT_DIRECTORY_LABEL_BYTES: usize = 96;
const MAX_PROBE_COMPONENTS_PER_KIND: usize = 4096;
const MAX_PROBE_MANIFEST_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROBE_PLUGIN_WASM_TOTAL_BYTES: usize = 512 * 1024 * 1024;

/// Canonical owner/repo for the public `neoth` binary lookup.
pub const NEOTH_OWNER_REPO: &str = "The-Geek-Freaks/NEOTH";

// ── U-01 neoth_self ──────────────────────────────────────────────────────────

/// Probe `neoth` self-version. Returns a single-component spec
/// list ready for `run_updater_pass(UpdaterTaskKind::NeothSelf, …)`.
pub async fn neoth_self_specs_async(gate: GateDecision) -> Vec<ComponentSpec> {
    neoth_self_specs_async_for(NEOTH_OWNER_REPO, ReleaseChannel::Stable, gate).await
}

/// Config-aware self-update probe. The daemon passes the operator's repository
/// and release ring here instead of silently probing the public stable feed.
pub async fn neoth_self_specs_async_for(
    owner_repo: &str,
    channel: ReleaseChannel,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    let current = current_version().to_string();
    if matches!(&gate, GateDecision::Deny { .. }) {
        return neoth_self_specs(current, Err(UPDATE_PROBE_DENIED_MSG.to_string()), gate);
    }
    let latest = match check_for_update_channel(owner_repo, channel).await {
        Ok(c) => Ok(c.latest),
        Err(e) => Err(format!("github probe: {e}")),
    };
    neoth_self_specs(current, latest, gate)
}

/// Sync wrapper for the U-04 cron-builder closure. Calls
/// `block_on` on the current tokio runtime — safe because the
/// closure runs on `spawn_blocking` (no nested-runtime issue).
pub fn neoth_self_specs_blocking(gate: GateDecision) -> Vec<ComponentSpec> {
    neoth_self_specs_blocking_for(NEOTH_OWNER_REPO, ReleaseChannel::Stable, gate)
}

pub fn neoth_self_specs_blocking_for(
    owner_repo: &str,
    channel: ReleaseChannel,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(neoth_self_specs_async_for(owner_repo, channel, gate)),
        Err(_) => Vec::new(),
    }
}

// ── U-03 cli_version ─────────────────────────────────────────────────────────

/// Probe every CLI we manage (`claude-cli`, `antigravity-cli`,
/// `codex`) and project into a spec list for
/// `run_updater_pass(UpdaterTaskKind::CliVersion, …)`. CLIs that
/// aren't installed produce no spec entry after an allowed local scan (matches
/// `pipeline::cli_version_specs`'s `Option`-skip contract). A denied gate emits
/// one `unknown` row per managed component without executing any subprocess so
/// the audit result proves exactly which probes were suppressed.
pub async fn cli_version_specs_async(gate: GateDecision) -> Vec<ComponentSpec> {
    use crate::updater::Component;
    if matches!(&gate, GateDecision::Deny { .. }) {
        let denied: Result<String, String> = Err(UPDATE_PROBE_DENIED_MSG.to_string());
        return cli_version_specs(
            Some(("unknown".to_string(), denied.clone())),
            Some(("unknown".to_string(), denied.clone())),
            Some(("unknown".to_string(), denied)),
            &gate,
        );
    }
    let statuses = crate::updater::check_all().await;
    // Component doesn't derive Hash so a HashMap won't compile;
    // a 3-variant linear scan is cheap + keeps the lookup obvious.
    let find = |c: Component| -> Option<&crate::updater::UpdateStatus> {
        statuses.iter().find(|s| s.component == c)
    };
    let to_pair = |c: Component| -> Option<(String, Result<String, String>)> {
        let s = find(c)?;
        let installed = s.installed.clone()?;
        // The error string we surface depends on which channel the CLI
        // ships through. npm-strategy CLIs surface `npm view <pkg>`
        // failures; shell-script CLIs (Antigravity) have no upstream
        // registry yet, so we emit a stable sentinel the operator can
        // grep for in `neoth updater status`.
        let latest = s
            .latest
            .clone()
            .map(Ok)
            .unwrap_or_else(|| match c.npm_package() {
                Some(pkg) => Err(format!("npm view {pkg} version: failed")),
                None => Err(format!(
                    "{} ships via vendor shell-script (no registry probe yet)",
                    c.name()
                )),
            });
        Some((installed, latest))
    };
    cli_version_specs(
        to_pair(Component::ClaudeCli),
        to_pair(Component::Codex),
        to_pair(Component::AntigravityCli),
        &gate,
    )
}

/// Sync wrapper for the U-04 cron-builder closure.
pub fn cli_version_specs_blocking(gate: GateDecision) -> Vec<ComponentSpec> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(cli_version_specs_async(gate)),
        Err(_) => Vec::new(),
    }
}

// ── U-02 skill_plugin ────────────────────────────────────────────────────────

/// One scanned skill row carrying the operator-visible fields the
/// updater cares about. Split out from the legacy `(id, version)`
/// tuple shape so U-02b can carry the optional `source` URL alongside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledSkillRow {
    /// Audit-friendly name with `skill:` prefix.
    pub name: String,
    pub version: String,
    /// `git+https://…` URL the operator declared in `skill.yaml`,
    /// or `None` when the skill opted out of auto-update probes.
    pub source: Option<String>,
    /// Effective runtime state after manifest defaults plus every
    /// `freedom.yaml::skills` override. Disabled skills never cause egress.
    pub enabled: bool,
    /// Canonical digest of every path, entry type and file byte in the exact
    /// package generation observed during the preflight scan.
    generation_sha256: String,
    id: String,
}

#[derive(Debug)]
struct ManifestScanFailure {
    component: String,
    error: String,
}

#[derive(Debug, Default)]
struct InstalledSkillScan {
    rows: Vec<InstalledSkillRow>,
    failures: Vec<ManifestScanFailure>,
}

#[derive(Debug)]
struct BoundManifest {
    dir_name: String,
    body: Vec<u8>,
    generation_sha256: Option<String>,
}

#[derive(Debug, Default)]
struct BoundManifestScan {
    manifests: Vec<BoundManifest>,
    failures: Vec<ManifestScanFailure>,
}

fn component_name(kind: &str, dir_name: &str) -> String {
    if dir_name.len() <= MAX_COMPONENT_DIRECTORY_LABEL_BYTES
        && dir_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return format!("{kind}:{dir_name}");
    }
    let digest = crate::wasm_plugin::discovery::sha256_hex(dir_name.as_bytes());
    format!("{kind}:<unsafe-{}>", &digest[..32])
}

fn scan_bound_manifests(root_path: &Path, kind: &str, manifest_name: &str) -> BoundManifestScan {
    scan_bound_manifests_with_limits(
        root_path,
        kind,
        manifest_name,
        MAX_PROBE_COMPONENTS_PER_KIND,
        MAX_PROBE_MANIFEST_TOTAL_BYTES,
    )
}

fn scan_bound_manifests_with_limits(
    root_path: &Path,
    kind: &str,
    manifest_name: &str,
    max_components: usize,
    max_total_manifest_bytes: usize,
) -> BoundManifestScan {
    let mut scan = BoundManifestScan::default();
    let root = match open_bound_directory(root_path, false, &format!("{kind}s root")) {
        Ok(Some(root)) => root,
        Ok(None) => return scan,
        Err(error) => {
            scan.failures.push(ManifestScanFailure {
                component: format!("{kind}:<store>"),
                error: format!("unsafe or unreadable {kind} store: {error:#}"),
            });
            return scan;
        }
    };
    // This is an OBSERVATION probe. It takes the mutation lock so the snapshot
    // is not torn by a concurrent install, but it must not WRITE: the recovery
    // pass that used to run here rolled back or committed interrupted install
    // transactions from an audit cron. Recovery stays lazy at the next real
    // skill operation, which has eleven production callers.
    //
    // A lock failure degrades the snapshot; it does not erase it. Returning
    // early made every skill component vanish from the audit inventory for that
    // tick — one concurrent `skill install` and the WAL frames that exist to
    // record what is installed recorded nothing at all. The failure row says
    // the snapshot is unlocked; the readable manifests are still reported.
    let _skill_mutation_guard = if kind == "skill" {
        match crate::skills::installer::lock_skill_mutations(&root) {
            Ok(guard) => Some(guard),
            Err(error) => {
                scan.failures.push(ManifestScanFailure {
                    component: "skill:<store>".to_string(),
                    error: format!(
                        "skill store could not be locked for the updater snapshot; \
                         reporting an unsynchronised read: {error:#}"
                    ),
                });
                None
            }
        }
    } else {
        None
    };
    let entries = match root.dir.entries() {
        Ok(entries) => entries,
        Err(error) => {
            scan.failures.push(ManifestScanFailure {
                component: format!("{kind}:<store>"),
                error: format!("cannot enumerate {}: {error}", root.display_path.display()),
            });
            return scan;
        }
    };

    let mut observed_entries = 0usize;
    let mut total_manifest_bytes = 0usize;
    for entry in entries {
        observed_entries = observed_entries.saturating_add(1);
        if observed_entries > max_components {
            scan.failures.push(ManifestScanFailure {
                component: format!("{kind}:<store>"),
                error: format!(
                    "installed {kind} store exceeds the {max_components}-entry updater limit"
                ),
            });
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                scan.failures.push(ManifestScanFailure {
                    component: format!("{kind}:<unknown>"),
                    error: format!("cannot enumerate {}: {error}", root.display_path.display()),
                });
                continue;
            }
        };
        let name = entry.file_name();
        let Some(dir_name) = name.to_str() else {
            scan.failures.push(ManifestScanFailure {
                component: format!("{kind}:<non-utf8>"),
                error: "installed component directory name is not valid UTF-8".to_string(),
            });
            continue;
        };
        if dir_name.starts_with('.') {
            continue;
        }
        let component = component_name(kind, dir_name);
        let path = root.display_path.join(&name);
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                scan.failures.push(ManifestScanFailure {
                    component,
                    error: format!("cannot inspect {}: {error}", path.display()),
                });
                continue;
            }
        };
        if file_type.is_symlink() {
            scan.failures.push(ManifestScanFailure {
                component,
                error: format!(
                    "linked/reparse {kind} directories are not allowed: {}",
                    path.display()
                ),
            });
            continue;
        }
        if !file_type.is_dir() {
            scan.failures.push(ManifestScanFailure {
                component,
                error: format!(
                    "installed {kind} entry is not a real directory: {}",
                    path.display()
                ),
            });
            continue;
        }
        let component_dir = match open_real_child_dir(&root.dir, &name, &path) {
            Ok(component_dir) => component_dir,
            Err(error) => {
                scan.failures.push(ManifestScanFailure {
                    component,
                    error: format!("unsafe {kind} directory {}: {error:#}", path.display()),
                });
                continue;
            }
        };
        let manifest_path = path.join(manifest_name);
        let body = match read_regular_file_bounded(
            &component_dir,
            OsStr::new(manifest_name),
            &manifest_path,
            MAX_UPDATE_MANIFEST_BYTES,
        ) {
            Ok(body) => body,
            Err(error) if error_is_not_found(&error) => {
                scan.failures.push(ManifestScanFailure {
                    component,
                    error: format!("no {manifest_name} in installed {kind} directory"),
                });
                continue;
            }
            Err(error) => {
                scan.failures.push(ManifestScanFailure {
                    component,
                    error: format!("cannot read {}: {error:#}", manifest_path.display()),
                });
                continue;
            }
        };
        total_manifest_bytes = match total_manifest_bytes.checked_add(body.len()) {
            Some(total) if total <= max_total_manifest_bytes => total,
            _ => {
                scan.failures.push(ManifestScanFailure {
                    component: format!("{kind}:<store>"),
                    error: format!(
                        "installed {kind} manifests exceed the {max_total_manifest_bytes}-byte aggregate updater limit"
                    ),
                });
                break;
            }
        };
        let generation_sha256 = if kind == "skill" {
            match crate::skills::installer::skill_tree_generation_sha256(
                &component_dir,
                &path,
                Some(&body),
            ) {
                Ok(generation) => Some(generation),
                Err(error) => {
                    scan.failures.push(ManifestScanFailure {
                        component,
                        error: format!("cannot bind installed skill package generation: {error:#}"),
                    });
                    continue;
                }
            }
        } else {
            None
        };
        scan.manifests.push(BoundManifest {
            dir_name: dir_name.to_string(),
            body,
            generation_sha256,
        });
    }
    scan
}

fn scan_installed_skills_checked(
    home: &Path,
    policy: &crate::config::SkillsConfig,
) -> InstalledSkillScan {
    let policy = crate::skills::loader::SkillPolicy::from_config(policy);
    let bound = scan_bound_manifests(&home.join("skills"), "skill", "skill.yaml");
    let mut scan = InstalledSkillScan {
        rows: Vec::new(),
        failures: bound.failures,
    };
    for manifest in bound.manifests {
        let parsed = std::str::from_utf8(&manifest.body)
            .map_err(|error| format!("skill manifest is not UTF-8: {error}"))
            .and_then(|body| {
                serde_yaml::from_str::<crate::skills::schema::SkillManifest>(body)
                    .map_err(|error| format!("skill manifest YAML is invalid: {error}"))
            });
        match parsed {
            Ok(parsed) if crate::skills::creator::validate_skill_id(&parsed.id).is_err() => {
                scan.failures.push(ManifestScanFailure {
                    component: component_name("skill", &manifest.dir_name),
                    error: "manifest id is not canonical lowercase [a-z0-9_-]".to_string(),
                });
            }
            Ok(parsed) if parsed.id != manifest.dir_name => {
                scan.failures.push(ManifestScanFailure {
                    component: component_name("skill", &manifest.dir_name),
                    error: format!(
                        "manifest id `{}` does not match directory `{}`",
                        parsed.id, manifest.dir_name
                    ),
                });
            }
            Ok(parsed) if parsed.description.trim().is_empty() => {
                scan.failures.push(ManifestScanFailure {
                    component: component_name("skill", &manifest.dir_name),
                    error: "manifest description is empty".to_string(),
                });
            }
            Ok(mut parsed) => {
                let Some(generation_sha256) = manifest.generation_sha256 else {
                    scan.failures.push(ManifestScanFailure {
                        component: component_name("skill", &manifest.dir_name),
                        error: "skill package scan did not produce a generation binding"
                            .to_string(),
                    });
                    continue;
                };
                policy.apply_to_manifest(&mut parsed);
                scan.rows.push(InstalledSkillRow {
                    name: component_name("skill", &manifest.dir_name),
                    version: parsed.version,
                    source: parsed.source,
                    enabled: parsed.enabled,
                    generation_sha256,
                    id: parsed.id,
                });
            }
            Err(error) => scan.failures.push(ManifestScanFailure {
                component: component_name("skill", &manifest.dir_name),
                error,
            }),
        }
    }
    scan.rows.sort_by(|left, right| left.name.cmp(&right.name));
    scan.failures
        .sort_by(|left, right| left.component.cmp(&right.component));
    scan
}

fn log_manifest_scan_failures(failures: &[ManifestScanFailure]) {
    for failure in failures {
        tracing::warn!(
            component = %failure.component,
            error = %failure.error,
            "updater manifest probe rejected an unsafe or invalid installed component"
        );
    }
}

fn error_is_not_found(error: &anyhow::Error) -> bool {
    error
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
}

/// Scan `~/.neoth/skills/<id>/skill.yaml` files + return
/// [`InstalledSkillRow`] per skill. Unsafe links/reparse points and malformed
/// manifests are rejected without being read through and logged. The real
/// cron path additionally turns each rejection into a failed component row.
pub fn scan_installed_skills_rows(
    home: &Path,
    policy: &crate::config::SkillsConfig,
) -> Vec<InstalledSkillRow> {
    let scan = scan_installed_skills_checked(home, policy);
    log_manifest_scan_failures(&scan.failures);
    scan.rows
}

/// Backwards-compatible alias: callers that don't need the source
/// URL keep the `(name, version)` shape. New callers use
/// [`scan_installed_skills_rows`] directly.
pub fn scan_installed_skills(
    home: &Path,
    policy: &crate::config::SkillsConfig,
) -> Vec<(String, String)> {
    scan_installed_skills_rows(home, policy)
        .into_iter()
        .map(|r| (r.name, r.version))
        .collect()
}

/// One scanned plugin row carrying the operator-visible fields the
/// updater cares about. U-02b parity (Session 27) — mirrors
/// [`InstalledSkillRow`] so the resolver lane can carry the optional
/// `source` URL alongside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPluginRow {
    /// Audit-friendly name with `plugin:` prefix.
    pub name: String,
    pub version: String,
    /// `git+https://…` URL the operator declared in `plugin.toml`,
    /// or `None` when the plugin opted out of auto-update probes.
    pub source: Option<String>,
    /// True only when the host is enabled and the exact manifest is covered
    /// by a non-revoked, active, approval-bound operator activation.
    pub enabled: bool,
    /// Operator-readable reason for suppressing the network probe.
    pub disabled_reason: Option<String>,
    /// Exact runtime-discovered generation admitted during the scan. Kept
    /// private so only this module can authorize a later resolver call.
    generation: Option<PluginGeneration>,
    id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PluginGeneration {
    manifest_sha256: String,
    wasm_sha256: String,
}

impl From<&crate::wasm_plugin::discovery::DiscoveredPlugin> for PluginGeneration {
    fn from(plugin: &crate::wasm_plugin::discovery::DiscoveredPlugin) -> Self {
        Self {
            manifest_sha256: plugin.manifest_hash.clone(),
            wasm_sha256: plugin.content_hash.clone(),
        }
    }
}

#[derive(Debug, Default)]
struct InstalledPluginScan {
    rows: Vec<InstalledPluginRow>,
    failures: Vec<ManifestScanFailure>,
}

fn safe_discovery_reason(error: &crate::wasm_plugin::discovery::DiscoveryError) -> String {
    use crate::wasm_plugin::discovery::DiscoveryError;

    match error {
        DiscoveryError::StoreEntryLimit { .. } => {
            "plugin store exceeds the runtime discovery entry limit"
        }
        DiscoveryError::PluginDirIo { .. } => "plugin directory is missing or unreadable",
        DiscoveryError::PluginPathNotDirectory { .. } => "plugin path is not a real directory",
        DiscoveryError::MissingManifest { .. } => "plugin.toml is missing",
        DiscoveryError::MissingWasm { .. } => "plugin.wasm is missing",
        DiscoveryError::TomlIo { .. } => "plugin.toml is unreadable",
        DiscoveryError::WasmIo { .. } => "plugin.wasm is unreadable",
        DiscoveryError::ManifestTooLarge { .. } => "plugin.toml exceeds the runtime size limit",
        DiscoveryError::WasmTooLarge { .. } => "plugin.wasm exceeds the runtime size limit",
        DiscoveryError::AggregateWasmBudgetExceeded { .. } => {
            "aggregate plugin.wasm discovery budget exceeded"
        }
        DiscoveryError::PathNotRegular { file, .. } => {
            return format!("{file} is not a real regular file");
        }
        DiscoveryError::PathIsSymlink { file, .. } => {
            return format!("{file} is linked or a reparse point");
        }
        DiscoveryError::ManifestInvalid { .. } => "plugin.toml is invalid",
        DiscoveryError::IdDirectoryMismatch { .. } => {
            "plugin manifest id does not match its directory"
        }
        DiscoveryError::HashMismatch { .. } => "plugin.wasm does not match its configured pin",
        DiscoveryError::HashUnpinned { .. } => {
            "plugin has no pin while require_all_pinned is enabled"
        }
        DiscoveryError::Revoked { .. } => "plugin is revoked by current operator policy",
        DiscoveryError::SignatureMissing { .. } => "plugin signature is required but missing",
        DiscoveryError::SignatureInvalid { .. } => {
            "plugin signature or configured author key is invalid"
        }
        DiscoveryError::AuthorKeyNotConfigured { .. } => {
            "plugin signature is required but no author key is configured"
        }
        DiscoveryError::SymlinkRejected { .. } => "plugin directory is linked or a reparse point",
    }
    .to_string()
}

fn safe_admission_reason(
    error: &crate::wasm_plugin::discovery::RuntimePluginAdmissionError,
) -> String {
    use crate::wasm_plugin::discovery::{PluginApprovalError, RuntimePluginAdmissionError};

    match error {
        RuntimePluginAdmissionError::HostDisabled => {
            "plugin host is disabled by current operator policy".to_string()
        }
        RuntimePluginAdmissionError::Approval(PluginApprovalError::NotActive) => {
            "plugin activation is not active".to_string()
        }
        RuntimePluginAdmissionError::Approval(PluginApprovalError::MissingApproval) => {
            "plugin has no exact operator approval".to_string()
        }
        RuntimePluginAdmissionError::Approval(PluginApprovalError::PermissionChanged {
            ..
        }) => "plugin permission differs from its approval".to_string(),
        RuntimePluginAdmissionError::Approval(PluginApprovalError::ManifestChanged) => {
            "plugin manifest differs from its approval".to_string()
        }
        RuntimePluginAdmissionError::Approval(PluginApprovalError::WasmChanged) => {
            "plugin.wasm differs from its approval".to_string()
        }
        RuntimePluginAdmissionError::Integrity(error) => safe_discovery_reason(error),
    }
}

fn redact_plugin_manifest_scan_failure(mut failure: ManifestScanFailure) -> ManifestScanFailure {
    failure.error = if failure.error.contains("no plugin.toml") {
        "plugin.toml is missing".to_string()
    } else if failure.error.contains("exceeds the") {
        "plugin.toml exceeds the updater scan size limit".to_string()
    } else if failure.error.contains("linked/reparse")
        || failure.error.contains("unsafe plugin directory")
    {
        "plugin directory is linked, a reparse point, or otherwise unsafe".to_string()
    } else {
        "plugin directory or plugin.toml is unsafe or unreadable".to_string()
    };
    failure
}

fn scan_installed_plugins_checked(
    home: &Path,
    policy: &crate::config::WasmPluginsConfig,
) -> InstalledPluginScan {
    let bound = scan_bound_manifests(&home.join("plugins"), "plugin", "plugin.toml");
    let mut scan = InstalledPluginScan {
        rows: Vec::new(),
        failures: bound
            .failures
            .into_iter()
            .map(redact_plugin_manifest_scan_failure)
            .collect(),
    };
    let mut total_wasm_bytes = 0usize;
    for manifest in bound.manifests {
        let component = component_name("plugin", &manifest.dir_name);
        match crate::wasm_plugin::discovery::discover_one_bound(
            &home.join("plugins"),
            OsStr::new(&manifest.dir_name),
        ) {
            Ok(plugin) => {
                total_wasm_bytes = match total_wasm_bytes.checked_add(plugin.wasm_bytes.len()) {
                    Some(total) if total <= MAX_PROBE_PLUGIN_WASM_TOTAL_BYTES => total,
                    _ => {
                        scan.failures.push(ManifestScanFailure {
                            component: "plugin:<store>".to_string(),
                            error: format!(
                                "installed plugin artifacts exceed the {MAX_PROBE_PLUGIN_WASM_TOTAL_BYTES}-byte aggregate updater limit"
                            ),
                        });
                        break;
                    }
                };
                let admission =
                    crate::wasm_plugin::discovery::validate_runtime_admission(&plugin, policy);
                let disabled_reason = admission.as_ref().err().map(safe_admission_reason);
                scan.rows.push(InstalledPluginRow {
                    name: component,
                    version: plugin.manifest.version.clone(),
                    source: plugin.manifest.source.clone(),
                    enabled: disabled_reason.is_none(),
                    disabled_reason,
                    generation: Some(PluginGeneration::from(&plugin)),
                    id: plugin.manifest.id.clone(),
                });
            }
            Err(error) => scan.failures.push(ManifestScanFailure {
                component,
                error: safe_discovery_reason(&error),
            }),
        }
    }
    scan.rows.sort_by(|left, right| left.name.cmp(&right.name));
    scan.failures
        .sort_by(|left, right| left.component.cmp(&right.component));
    scan
}

/// Scan `~/.neoth/plugins/<id>/plugin.toml` files + return
/// [`InstalledPluginRow`] per plugin. Unsafe links/reparse points and malformed
/// manifests are rejected without being read through and logged. The real
/// cron path additionally turns each rejection into a failed component row.
pub fn scan_installed_plugins_rows(
    home: &Path,
    policy: &crate::config::WasmPluginsConfig,
) -> Vec<InstalledPluginRow> {
    let scan = scan_installed_plugins_checked(home, policy);
    log_manifest_scan_failures(&scan.failures);
    scan.rows
}

/// Backwards-compatible alias: callers that don't need the source
/// URL keep the `(name, version)` shape. New callers use
/// [`scan_installed_plugins_rows`] directly.
pub fn scan_installed_plugins(
    home: &Path,
    policy: &crate::config::WasmPluginsConfig,
) -> Vec<(String, String)> {
    scan_installed_plugins_rows(home, policy)
        .into_iter()
        .map(|r| (r.name, r.version))
        .collect()
}

/// Sentinel error string the U-02 probe writes into
/// `latest_version: Err(…)` until a real skill/plugin registry
/// ships. Operators see the WAL audit + the `neoth updater
/// status` "no upstream resolver" line so the cron's presence is
/// audited without false-promise of "we know what's latest".
pub const NO_REGISTRY_RESOLVER_MSG: &str =
    "no upstream registry yet — U-02b will resolve latest_version via the registry concept";
pub const DISABLED_SKILL_PROBE_MSG: &str = "upstream probe skipped without network: skill is disabled by effective manifest/operator policy";
pub const UPDATE_PROBE_DENIED_MSG: &str =
    "upstream probe skipped without network: updater gate denied this component";
pub const SKILL_AUTHORITY_REQUIRED_MSG: &str = "upstream probe skipped without network: installed Skill has no active exact-generation authority";

fn invalid_source_probe_status(source: &str) -> Option<String> {
    crate::updater::skill_resolver::parse_git_source(source)
        .err()
        .map(|error| format!("upstream probe skipped before network: {error}"))
}

#[cfg(test)]
fn revalidate_skill_at_resolver_sink(
    home: &Path,
    accepted_policy: &crate::config::SkillsConfig,
    row: &InstalledSkillRow,
) -> Result<String, String> {
    if !row.enabled {
        return Err(DISABLED_SKILL_PROBE_MSG.to_string());
    }
    let current = read_exact_skill_row_at_sink(home, accepted_policy, &row.id)?;
    if !current.enabled {
        return Err(DISABLED_SKILL_PROBE_MSG.to_string());
    }
    if current.generation_sha256 != row.generation_sha256 {
        return Err(
            "upstream probe skipped without network: skill package generation changed after scan"
                .to_string(),
        );
    }
    let source = current.source.ok_or_else(|| {
        "upstream probe skipped without network: skill source disappeared after scan".to_string()
    })?;
    if row.source.as_deref() != Some(source.as_str()) {
        return Err(
            "upstream probe skipped without network: skill source changed after scan".to_string(),
        );
    }
    Ok(source)
}

/// Re-open only the exact skill about to authorize egress. The old sink called
/// `scan_installed_skills_checked`, turning N source-bearing skills into N full
/// capability walks and allowing unrelated broken entries to influence a
/// single skill's decision. This keeps the exact config/policy and full package
/// generation checks while making sink work O(1) per resolver call.
#[cfg(test)]
fn read_exact_skill_row_at_sink(
    home: &Path,
    accepted_policy: &crate::config::SkillsConfig,
    id: &str,
) -> Result<InstalledSkillRow, String> {
    crate::skills::creator::validate_skill_id(id).map_err(|_| {
        "upstream probe skipped without network: skill id is no longer valid".to_string()
    })?;
    let skills_root = home.join("skills");
    let root = open_bound_directory(&skills_root, false, "skills root")
        .map_err(|_| {
            "upstream probe skipped without network: skill store is no longer valid".to_string()
        })?
        .ok_or_else(|| {
            "upstream probe skipped without network: skill generation is no longer valid"
                .to_string()
        })?;
    // The lock keeps this single-row read coherent against a concurrent
    // install. Recovery deliberately does NOT run here: it enumerates the whole
    // store and WRITES, so calling it once per source-carrying skill turned a
    // per-skill read into a full store pass per skill — and put mutations on a
    // read path. Recovery stays lazy at the next real skill operation.
    let _mutation_guard = crate::skills::installer::lock_skill_mutations(&root).map_err(|_| {
        "upstream probe skipped without network: skill store cannot be locked".to_string()
    })?;

    let name = OsStr::new(id);
    let path = root.display_path.join(name);
    let skill_dir = open_real_child_dir(&root.dir, name, &path).map_err(|_| {
        "upstream probe skipped without network: skill generation is no longer valid".to_string()
    })?;
    let manifest_path = path.join("skill.yaml");
    let body = read_regular_file_bounded(
        &skill_dir,
        OsStr::new("skill.yaml"),
        &manifest_path,
        MAX_UPDATE_MANIFEST_BYTES,
    )
    .map_err(|_| {
        "upstream probe skipped without network: skill manifest is no longer valid".to_string()
    })?;
    let generation_sha256 = crate::skills::installer::skill_tree_generation_sha256(
        &skill_dir,
        &path,
        Some(&body),
    )
    .map_err(|_| {
        "upstream probe skipped without network: skill package generation is no longer valid"
            .to_string()
    })?;
    let body = std::str::from_utf8(&body).map_err(|_| {
        "upstream probe skipped without network: skill manifest is not UTF-8".to_string()
    })?;
    let mut manifest =
        serde_yaml::from_str::<crate::skills::schema::SkillManifest>(body).map_err(|_| {
            "upstream probe skipped without network: skill manifest is invalid".to_string()
        })?;
    if manifest.id != id
        || crate::skills::creator::validate_skill_id(&manifest.id).is_err()
        || manifest.description.trim().is_empty()
    {
        return Err(
            "upstream probe skipped without network: skill manifest identity is no longer valid"
                .to_string(),
        );
    }

    // Re-apply the immutable policy generation accepted by ReloadController.
    // The raw config file may already contain a newer rejected candidate and
    // therefore must never become authority at this egress boundary.
    crate::skills::loader::SkillPolicy::from_config(accepted_policy)
        .apply_to_manifest(&mut manifest);
    Ok(InstalledSkillRow {
        name: component_name("skill", id),
        version: manifest.version,
        source: manifest.source,
        enabled: manifest.enabled,
        generation_sha256,
        id: manifest.id,
    })
}

#[cfg(test)]
async fn resolve_skill_latest_at_sink_with_resolver<R, Fut>(
    home: &Path,
    accepted_policy: &crate::config::SkillsConfig,
    row: &InstalledSkillRow,
    resolver: R,
) -> Result<String, String>
where
    R: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let home = home.to_path_buf();
    let accepted_policy = accepted_policy.clone();
    let row = row.clone();
    let source = tokio::task::spawn_blocking(move || {
        revalidate_skill_at_resolver_sink(&home, &accepted_policy, &row)
    })
    .await
    .map_err(|_| {
        "upstream probe skipped without network: skill revalidation worker failed".to_string()
    })??;
    if let Some(error) = invalid_source_probe_status(&source) {
        return Err(error);
    }
    resolver(source).await
}

fn revalidate_authorized_skill_at_resolver_sink(
    home: &Path,
    reload: &crate::config::reload::ReloadController,
    row: &InstalledSkillRow,
) -> Result<String, String> {
    if !row.enabled {
        return Err(DISABLED_SKILL_PROBE_MSG.to_string());
    }
    let authority =
        match crate::skills::authority::validate_installed_authority(home, &row.id, reload) {
            crate::skills::authority::InstalledSkillAuthorityValidation::Active(authority) => {
                authority
            }
            crate::skills::authority::InstalledSkillAuthorityValidation::Inactive(reason) => {
                return Err(format!(
                    "{SKILL_AUTHORITY_REQUIRED_MSG} ({})",
                    reason.as_str()
                ));
            }
        };
    if authority.package_generation_sha256() != row.generation_sha256 {
        return Err(
            "upstream probe skipped without network: skill package generation changed after scan"
                .to_string(),
        );
    }
    let manifest = authority.manifest();
    if !manifest.enabled {
        return Err(DISABLED_SKILL_PROBE_MSG.to_string());
    }
    let source = manifest.source.clone().ok_or_else(|| {
        "upstream probe skipped without network: skill source disappeared after scan".to_string()
    })?;
    if row.source.as_deref() != Some(source.as_str()) {
        return Err(
            "upstream probe skipped without network: skill source changed after scan".to_string(),
        );
    }
    Ok(source)
}

async fn resolve_authorized_skill_latest_at_sink(
    home: &Path,
    reload: &crate::config::reload::ReloadController,
    row: &InstalledSkillRow,
) -> Result<String, String> {
    resolve_authorized_skill_latest_at_sink_with_resolver(home, reload, row, |source| async move {
        crate::updater::skill_resolver::resolve_latest_version(&source).await
    })
    .await
}

async fn resolve_authorized_skill_latest_at_sink_with_resolver<R, Fut>(
    home: &Path,
    reload: &crate::config::reload::ReloadController,
    row: &InstalledSkillRow,
    resolver: R,
) -> Result<String, String>
where
    R: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let home = home.to_path_buf();
    let reload = reload.clone();
    let row = row.clone();
    let source = tokio::task::spawn_blocking(move || {
        revalidate_authorized_skill_at_resolver_sink(&home, &reload, &row)
    })
    .await
    .map_err(|_| {
        "upstream probe skipped without network: Skill authority worker failed".to_string()
    })??;
    if let Some(error) = invalid_source_probe_status(&source) {
        return Err(error);
    }
    resolver(source).await
}

fn revalidate_plugin_at_resolver_sink(
    home: &Path,
    accepted_policy: &crate::config::WasmPluginsConfig,
    row: &InstalledPluginRow,
) -> Result<String, String> {
    if !row.enabled {
        return Err(format!(
            "upstream probe skipped without network: {}",
            row.disabled_reason
                .as_deref()
                .unwrap_or("plugin is not runtime-admitted")
        ));
    }
    let expected = row.generation.as_ref().ok_or_else(|| {
        "upstream probe skipped without network: plugin scan has no bound generation".to_string()
    })?;
    let plugin = crate::wasm_plugin::discovery::discover_one_bound(
        &home.join("plugins"),
        OsStr::new(&row.id),
    )
    .map_err(|error| {
        format!(
            "upstream probe skipped without network: {}",
            safe_discovery_reason(&error)
        )
    })?;
    let current = PluginGeneration::from(&plugin);
    if &current != expected {
        return Err(
            "upstream probe skipped without network: plugin generation changed after scan"
                .to_string(),
        );
    }
    // Re-validate against the exact immutable policy generation accepted by
    // ReloadController. A newer on-disk candidate may have failed reload and
    // cannot override the running daemon's policy at the network boundary.
    crate::wasm_plugin::discovery::validate_runtime_admission(&plugin, accepted_policy).map_err(
        |error| {
            format!(
                "upstream probe skipped without network: {}",
                safe_admission_reason(&error)
            )
        },
    )?;
    let source = plugin.manifest.source.ok_or_else(|| {
        "upstream probe skipped without network: plugin source disappeared after scan".to_string()
    })?;
    if row.source.as_deref() != Some(source.as_str()) {
        return Err(
            "upstream probe skipped without network: plugin source changed after scan".to_string(),
        );
    }
    Ok(source)
}

async fn resolve_plugin_latest_at_sink<R, Fut>(
    home: &Path,
    accepted_policy: &crate::config::WasmPluginsConfig,
    row: &InstalledPluginRow,
    resolver: &R,
) -> Result<String, String>
where
    R: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let home = home.to_path_buf();
    let accepted_policy = accepted_policy.clone();
    let row = row.clone();
    let source = tokio::task::spawn_blocking(move || {
        revalidate_plugin_at_resolver_sink(&home, &accepted_policy, &row)
    })
    .await
    .map_err(|_| {
        "upstream probe skipped without network: plugin revalidation worker failed".to_string()
    })??;
    if let Some(error) = invalid_source_probe_status(&source) {
        return Err(error);
    }
    resolver(source).await
}

/// Compose installed skills + plugins into a single
/// `skill_plugin_specs` list.
///
/// This detached-policy inventory API performs no installed-Skill network
/// egress. A `SkillsConfig` value and manifest `enabled` bit are not runtime
/// authority; source-bearing Skills return [`SKILL_AUTHORITY_REQUIRED_MSG`].
/// The daemon uses [`skill_plugin_specs_for_home_authorized_async`], which
/// validates the exact live package/authority generation before its resolver.
/// Skills without a source declaration keep the no-registry sentinel.
///
/// Plugins (`~/.neoth/plugins/<id>/plugin.toml`) get the same
/// treatment as of Session 27 parity work: a `source` field on the
/// `PluginManifest` routes through the resolver; plugins without
/// the field keep the sentinel so the audit chain still
/// distinguishes "operator hasn't opted in" from "resolver failed". The
/// The caller must pass immutable skill and plugin policy snapshots. Raw config
/// files are deliberately not consulted: the file may already contain a newer
/// candidate rejected by `ReloadController`.
pub async fn skill_plugin_specs_for_home_async(
    home: PathBuf,
    skills_policy: crate::config::SkillsConfig,
    plugin_policy: crate::config::WasmPluginsConfig,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    skill_plugin_specs_for_home_async_with_plugin_resolver(
        home,
        skills_policy,
        plugin_policy,
        gate,
        None,
        |source| async move {
            crate::updater::skill_resolver::resolve_latest_version(&source).await
        },
    )
    .await
}

/// Runtime updater view. Installed Skill sources are resolved only after the
/// exact package generation consumes the same active authority record used by
/// the loader/router. The inventory-only API above deliberately performs no
/// Skill network egress because a detached `SkillsConfig` is not proof of an
/// accepted runtime generation.
pub(crate) async fn skill_plugin_specs_for_home_authorized_async(
    home: PathBuf,
    reload: std::sync::Arc<crate::config::reload::ReloadController>,
    plugin_policy: crate::config::WasmPluginsConfig,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    let skills_policy = reload.accepted_snapshot().config().skills.clone();
    skill_plugin_specs_for_home_async_with_plugin_resolver(
        home,
        skills_policy,
        plugin_policy,
        gate,
        Some(reload),
        |source| async move {
            crate::updater::skill_resolver::resolve_latest_version(&source).await
        },
    )
    .await
}

async fn skill_plugin_specs_for_home_async_with_plugin_resolver<R, Fut>(
    home: PathBuf,
    skills_policy: crate::config::SkillsConfig,
    plugin_policy: crate::config::WasmPluginsConfig,
    gate: GateDecision,
    skill_reload: Option<std::sync::Arc<crate::config::reload::ReloadController>>,
    plugin_resolver: R,
) -> Vec<ComponentSpec>
where
    R: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let mut installed: Vec<(String, String, Result<String, String>, GateDecision)> = Vec::new();
    // The capability API is synchronous. Keep a large operator store off the
    // Tokio worker before beginning the asynchronous network probes.
    let scan_home = home.clone();
    let scan_skills_policy = skills_policy.clone();
    let scan_plugin_policy = plugin_policy.clone();
    let (skill_scan, plugin_scan) = match tokio::task::spawn_blocking(move || {
        (
            scan_installed_skills_checked(&scan_home, &scan_skills_policy),
            scan_installed_plugins_checked(&scan_home, &scan_plugin_policy),
        )
    })
    .await
    {
        Ok(scans) => scans,
        Err(error) => {
            installed.push((
                "skill-plugin:<store>".to_string(),
                "unknown".to_string(),
                Err(format!("updater manifest scan worker failed: {error}")),
                gate,
            ));
            return crate::updater::pipeline::skill_plugin_specs(installed);
        }
    };
    log_manifest_scan_failures(&skill_scan.failures);
    for failure in skill_scan.failures {
        installed.push((
            failure.component,
            "unknown".to_string(),
            Err(failure.error),
            gate.clone(),
        ));
    }
    for row in skill_scan.rows {
        let latest = if matches!(&gate, GateDecision::Deny { .. }) {
            Err(UPDATE_PROBE_DENIED_MSG.to_string())
        } else if !row.enabled {
            Err(DISABLED_SKILL_PROBE_MSG.to_string())
        } else {
            match row.source.as_deref() {
                Some(_) => match skill_reload.as_deref() {
                    Some(reload) => {
                        resolve_authorized_skill_latest_at_sink(&home, reload, &row).await
                    }
                    None => Err(SKILL_AUTHORITY_REQUIRED_MSG.to_string()),
                },
                None => Err(NO_REGISTRY_RESOLVER_MSG.to_string()),
            }
        };
        installed.push((row.name, row.version, latest, gate.clone()));
    }
    log_manifest_scan_failures(&plugin_scan.failures);
    for failure in plugin_scan.failures {
        installed.push((
            failure.component,
            "unknown".to_string(),
            Err(failure.error),
            gate.clone(),
        ));
    }
    for row in plugin_scan.rows {
        let latest = if matches!(&gate, GateDecision::Deny { .. }) {
            Err(UPDATE_PROBE_DENIED_MSG.to_string())
        } else if !row.enabled {
            Err(format!(
                "upstream probe skipped without network: {}",
                row.disabled_reason
                    .as_deref()
                    .unwrap_or("plugin is not enabled by effective operator policy")
            ))
        } else {
            match row.source.as_deref() {
                Some(_) => {
                    resolve_plugin_latest_at_sink(&home, &plugin_policy, &row, &plugin_resolver)
                        .await
                }
                None => Err(NO_REGISTRY_RESOLVER_MSG.to_string()),
            }
        };
        installed.push((row.name, row.version, latest, gate.clone()));
    }
    crate::updater::pipeline::skill_plugin_specs(installed)
}

/// Sync wrapper kept for callers that don't have a tokio runtime
/// handy. Every source-declaring skill OR plugin yields the
/// sentinel error here because the resolver requires async.
/// Callers in async contexts MUST switch to
/// [`skill_plugin_specs_for_home_async`].
pub fn skill_plugin_specs_for_home(
    home: &Path,
    skills_policy: &crate::config::SkillsConfig,
    plugin_policy: &crate::config::WasmPluginsConfig,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    let mut installed: Vec<(String, String, Result<String, String>, GateDecision)> = Vec::new();
    let skill_scan = scan_installed_skills_checked(home, skills_policy);
    log_manifest_scan_failures(&skill_scan.failures);
    for failure in skill_scan.failures {
        installed.push((
            failure.component,
            "unknown".to_string(),
            Err(failure.error),
            gate.clone(),
        ));
    }
    for row in skill_scan.rows {
        let latest = if matches!(&gate, GateDecision::Deny { .. }) {
            UPDATE_PROBE_DENIED_MSG.to_string()
        } else if !row.enabled {
            DISABLED_SKILL_PROBE_MSG.to_string()
        } else if let Some(source) = row.source.as_deref() {
            invalid_source_probe_status(source)
                .unwrap_or_else(|| NO_REGISTRY_RESOLVER_MSG.to_string())
        } else {
            NO_REGISTRY_RESOLVER_MSG.to_string()
        };
        installed.push((row.name, row.version, Err(latest), gate.clone()));
    }
    let plugin_scan = scan_installed_plugins_checked(home, plugin_policy);
    log_manifest_scan_failures(&plugin_scan.failures);
    for failure in plugin_scan.failures {
        installed.push((
            failure.component,
            "unknown".to_string(),
            Err(failure.error),
            gate.clone(),
        ));
    }
    for row in plugin_scan.rows {
        let latest = if matches!(&gate, GateDecision::Deny { .. }) {
            UPDATE_PROBE_DENIED_MSG.to_string()
        } else if !row.enabled {
            format!(
                "upstream probe skipped without network: {}",
                row.disabled_reason
                    .as_deref()
                    .unwrap_or("plugin is not enabled by effective operator policy")
            )
        } else if let Some(source) = row.source.as_deref() {
            invalid_source_probe_status(source)
                .unwrap_or_else(|| NO_REGISTRY_RESOLVER_MSG.to_string())
        } else {
            NO_REGISTRY_RESOLVER_MSG.to_string()
        };
        installed.push((row.name, row.version, Err(latest), gate.clone()));
    }
    crate::updater::pipeline::skill_plugin_specs(installed)
}

/// Sync builder for the U-04 cron-builder closure. Installed artifacts are
/// rescanned each tick, while policy is taken only from the immutable config
/// generation accepted by `ReloadController` for that tick.
///
/// Detached callers cannot authorize installed-Skill egress. The daemon uses
/// [`skill_plugin_specs_authorized_blocking`] with its live
/// `ReloadController`; this compatibility wrapper reports an authority-required
/// status for every source-bearing Skill.
pub fn skill_plugin_specs_blocking(
    home: PathBuf,
    skills_policy: crate::config::SkillsConfig,
    plugin_policy: crate::config::WasmPluginsConfig,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(skill_plugin_specs_for_home_async(
            home,
            skills_policy,
            plugin_policy,
            gate,
        )),
        Err(_) => skill_plugin_specs_for_home(&home, &skills_policy, &plugin_policy, gate),
    }
}

/// Runtime counterpart of [`skill_plugin_specs_blocking`]. The live
/// `ReloadController` is mandatory so source probes cannot mistake a detached
/// config struct or manifest `enabled` bit for execution authority.
/// Blocking-thread-only adapter for the updater cron.
///
/// Async callers must use [`skill_plugin_specs_for_home_authorized_async`].
/// Calling this function from a Tokio worker can panic because it enters the
/// current runtime with `Handle::block_on`.
pub(crate) fn skill_plugin_specs_authorized_blocking(
    home: PathBuf,
    reload: std::sync::Arc<crate::config::reload::ReloadController>,
    plugin_policy: crate::config::WasmPluginsConfig,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(skill_plugin_specs_for_home_authorized_async(
            home,
            reload,
            plugin_policy,
            gate,
        )),
        Err(_) => {
            let skills_policy = reload.accepted_snapshot().config().skills.clone();
            skill_plugin_specs_for_home(&home, &skills_policy, &plugin_policy, gate)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updater::pipeline::GateDecision;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MINIMAL_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[cfg(unix)]
    fn try_symlink_dir(source: &Path, target: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(source, target)
    }

    #[cfg(windows)]
    fn try_symlink_dir(source: &Path, target: &Path) -> std::io::Result<()> {
        match std::os::windows::fs::symlink_dir(source, target) {
            Ok(()) => Ok(()),
            Err(_) => {
                let status = std::process::Command::new("cmd.exe")
                    .args(["/D", "/C", "mklink", "/J"])
                    .arg(target)
                    .arg(source)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()?;
                if status.success() {
                    Ok(())
                } else {
                    Err(std::io::Error::other(format!(
                        "mklink /J failed with {status}"
                    )))
                }
            }
        }
    }

    fn approve_plugin_with_policy(home: &Path, manifest_body: &str, extra_policy: &str) {
        let manifest = crate::wasm_plugin::manifest::parse_manifest(manifest_body.as_bytes())
            .expect("valid plugin fixture");
        let plugin =
            crate::wasm_plugin::discovery::discover_one(&home.join("plugins").join(&manifest.id))
                .expect("complete plugin fixture");
        std::fs::write(
            home.join("freedom.yaml"),
            format!(
                "plugins:\n  wasm:\n    enabled: true\n    activations:\n      {}:\n        state: active\n        approval:\n          approved_permission: {}\n          manifest_sha256: \"{}\"\n          wasm_sha256: \"{}\"\n{}",
                manifest.id,
                manifest.requested_permissions.as_str(),
                plugin.manifest_hash,
                plugin.content_hash,
                extra_policy,
            ),
        )
        .unwrap();
    }

    fn approve_plugin(home: &Path, manifest_body: &str) {
        approve_plugin_with_policy(home, manifest_body, "");
    }

    fn write_plugin(home: &Path, id: &str, manifest_body: &str) {
        let installed = home.join("plugins").join(id);
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(installed.join("plugin.toml"), manifest_body).unwrap();
        std::fs::write(installed.join("plugin.wasm"), MINIMAL_WASM).unwrap();
    }

    fn write_skill(home: &Path, id: &str, manifest_body: &str) {
        let installed = home.join("skills").join(id);
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(installed.join("skill.yaml"), manifest_body).unwrap();
    }

    fn install_test_wal_key(home: &Path) {
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&wal_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(windows)]
        crate::wal::win_native::set_private_current_user_directory_dacl(&wal_dir).unwrap();
        crate::wal::compaction::load_or_init_key(&wal_dir.join("hmac.key")).unwrap();
    }

    fn record_test_install_incarnation(home: &Path, id: &str) {
        let current = crate::skills::installer::inspect_current_install(&home.join("skills"), id)
            .expect("installed Skill fixture exists");
        crate::skills::mutation_lifecycle::record_committed_install_incarnation_for_test(
            home,
            id,
            &current.generation_sha256,
            crate::skills::installer::SkillMutationOrigin::CliInstall,
        )
        .unwrap();
    }

    fn test_reload_controller(
        home: &Path,
    ) -> std::sync::Arc<crate::config::reload::ReloadController> {
        let config = crate::config::FreedomConfig::default();
        let path = config_path(home);
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        std::sync::Arc::new(crate::config::reload::ReloadController::new(config, path))
    }

    fn activate_test_skill(
        home: &Path,
        id: &str,
        reload: &crate::config::reload::ReloadController,
    ) {
        let decision = crate::skills::authority::SkillAuthorityDecision::new(
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli,
            crate::skills::authority::SkillAuthorityState::Active,
            None,
        )
        .unwrap();
        crate::skills::authority::publish_installed_authority_decision(home, id, reload, decision)
            .unwrap();
    }

    fn config_path(home: &Path) -> PathBuf {
        home.join("freedom.yaml")
    }

    fn accepted_policies_at(
        path: &Path,
    ) -> (
        crate::config::SkillsConfig,
        crate::config::WasmPluginsConfig,
    ) {
        let config = crate::config::FreedomConfig::load_from_path_or_default(path)
            .expect("accepted policy fixture");
        (config.skills, config.plugins.wasm)
    }

    // Compatibility helpers keep the older fixture call sites concise. They
    // snapshot the fixture config once at entry; production cron wiring never
    // calls these and receives ReloadController's accepted generation.
    fn scan_installed_skills(home: &Path) -> Vec<(String, String)> {
        let (skills, _) = accepted_policies_at(&config_path(home));
        super::scan_installed_skills(home, &skills)
    }

    fn scan_installed_skills_rows(home: &Path) -> Vec<InstalledSkillRow> {
        let (skills, _) = accepted_policies_at(&config_path(home));
        super::scan_installed_skills_rows(home, &skills)
    }

    fn scan_installed_skills_checked(home: &Path, path: &Path) -> InstalledSkillScan {
        let (skills, _) = accepted_policies_at(path);
        super::scan_installed_skills_checked(home, &skills)
    }

    fn scan_installed_plugins(home: &Path, path: &Path) -> Vec<(String, String)> {
        let (_, plugins) = accepted_policies_at(path);
        super::scan_installed_plugins(home, &plugins)
    }

    fn scan_installed_plugins_rows(home: &Path, path: &Path) -> Vec<InstalledPluginRow> {
        let (_, plugins) = accepted_policies_at(path);
        super::scan_installed_plugins_rows(home, &plugins)
    }

    fn scan_installed_plugins_checked(home: &Path, path: &Path) -> InstalledPluginScan {
        let (_, plugins) = accepted_policies_at(path);
        super::scan_installed_plugins_checked(home, &plugins)
    }

    fn skill_plugin_specs_for_home(
        home: &Path,
        path: &Path,
        gate: GateDecision,
    ) -> Vec<ComponentSpec> {
        let (skills, plugins) = accepted_policies_at(path);
        super::skill_plugin_specs_for_home(home, &skills, &plugins, gate)
    }

    async fn skill_plugin_specs_for_home_async(
        home: PathBuf,
        path: PathBuf,
        gate: GateDecision,
    ) -> Vec<ComponentSpec> {
        let (skills, plugins) = accepted_policies_at(&path);
        super::skill_plugin_specs_for_home_async(home, skills, plugins, gate).await
    }

    async fn skill_plugin_specs_for_home_async_with_plugin_resolver<R, Fut>(
        home: PathBuf,
        path: PathBuf,
        gate: GateDecision,
        resolver: R,
    ) -> Vec<ComponentSpec>
    where
        R: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Result<String, String>>,
    {
        let (skills, plugins) = accepted_policies_at(&path);
        super::skill_plugin_specs_for_home_async_with_plugin_resolver(
            home, skills, plugins, gate, None, resolver,
        )
        .await
    }

    async fn resolve_skill_latest_at_sink_with_resolver<R, Fut>(
        home: &Path,
        path: &Path,
        row: &InstalledSkillRow,
        resolver: R,
    ) -> Result<String, String>
    where
        R: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<String, String>>,
    {
        let (skills, _) = accepted_policies_at(path);
        super::resolve_skill_latest_at_sink_with_resolver(home, &skills, row, resolver).await
    }

    async fn resolve_plugin_latest_at_sink<R, Fut>(
        home: &Path,
        path: &Path,
        row: &InstalledPluginRow,
        resolver: &R,
    ) -> Result<String, String>
    where
        R: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Result<String, String>>,
    {
        let (_, plugins) = accepted_policies_at(path);
        super::resolve_plugin_latest_at_sink(home, &plugins, row, resolver).await
    }

    fn denied_gate() -> GateDecision {
        GateDecision::Deny {
            reason: "recurring egress not authorised".to_string(),
        }
    }

    #[tokio::test]
    async fn denied_self_probe_short_circuits_before_repo_validation_or_network() {
        let specs = neoth_self_specs_async_for(
            "invalid repo that must never reach transport validation",
            ReleaseChannel::Stable,
            denied_gate(),
        )
        .await;
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].latest_version.as_ref().unwrap_err(),
            UPDATE_PROBE_DENIED_MSG
        );
        assert!(matches!(specs[0].gate_decision, GateDecision::Deny { .. }));
    }

    #[tokio::test]
    async fn denied_cli_probe_returns_auditable_rows_without_npm_egress() {
        let specs = cli_version_specs_async(denied_gate()).await;
        assert_eq!(specs.len(), crate::updater::Component::ALL.len());
        assert!(specs.iter().all(|spec| {
            spec.latest_version.as_ref().err().map(String::as_str) == Some(UPDATE_PROBE_DENIED_MSG)
                && matches!(spec.gate_decision, GateDecision::Deny { .. })
        }));
    }

    #[test]
    fn unsafe_directory_identifier_is_bounded_and_control_safe() {
        let raw = format!("line\nbreak{}", "x".repeat(512));
        let component = component_name("plugin", &raw);
        assert!(component.len() < 64);
        assert!(!component.chars().any(char::is_control));
        assert!(component.starts_with("plugin:<unsafe-"));
        assert!(!component.contains("line"));
    }

    fn counting_resolver(
        calls: Arc<AtomicUsize>,
    ) -> impl Fn(String) -> std::future::Ready<Result<String, String>> {
        move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok("v9.9.9".to_string()))
        }
    }

    #[tokio::test]
    async fn neoth_self_probe_returns_single_spec_with_current_version() {
        // Network call goes out; the assertion only pins the
        // spec shape, not the upstream response. A network
        // failure surfaces as `latest_version: Err(...)` —
        // still a valid single-spec list.
        let specs = neoth_self_specs_async(GateDecision::Allow).await;
        assert_eq!(specs.len(), 1, "neoth_self probe yields exactly one spec");
        assert_eq!(specs[0].name, "neoth");
        assert_eq!(specs[0].current_version, current_version());
    }

    #[test]
    fn neoth_self_blocking_outside_runtime_returns_empty() {
        // No tokio runtime in this test → Handle::try_current()
        // fails → empty vec (no panic).
        let specs = neoth_self_specs_blocking(GateDecision::Allow);
        assert!(specs.is_empty());
    }

    #[tokio::test]
    async fn cli_version_probe_yields_spec_only_for_installed_clis() {
        // CI runners don't have claude/codex/agy installed by default,
        // so the expected result is an empty vec. When operator has
        // them installed, each installed CLI produces exactly one
        // spec. `gemini-cli` alias is accepted for back-compat with
        // any pre-2026-05-19 frames that ride the wire.
        let specs = cli_version_specs_async(GateDecision::Allow).await;
        for s in &specs {
            assert!(
                matches!(
                    s.name.as_str(),
                    "claude-cli" | "codex" | "antigravity-cli" | "gemini-cli",
                ),
                "unexpected component name in cli_version probe: {}",
                s.name,
            );
        }
    }

    #[test]
    fn cli_version_blocking_outside_runtime_returns_empty() {
        let specs = cli_version_specs_blocking(GateDecision::Allow);
        assert!(specs.is_empty());
    }

    // ── U-02 skill_plugin scanners ───────────────────────────────

    #[test]
    fn scan_skills_returns_empty_when_dir_missing() {
        let home = tempfile::tempdir().unwrap();
        assert!(scan_installed_skills(home.path()).is_empty());
    }

    #[test]
    fn scan_skills_lists_one_per_id_dir() {
        let home = tempfile::tempdir().unwrap();
        let skills = home.path().join("skills");
        std::fs::create_dir_all(skills.join("alpha")).unwrap();
        std::fs::create_dir_all(skills.join("beta")).unwrap();
        std::fs::write(
            skills.join("alpha").join("skill.yaml"),
            "id: alpha\ndescription: A\nversion: 1.2.3\n",
        )
        .unwrap();
        std::fs::write(
            skills.join("beta").join("skill.yaml"),
            "id: beta\ndescription: B\nversion: 0.1.0\n",
        )
        .unwrap();
        let mut found = scan_installed_skills(home.path());
        found.sort();
        assert_eq!(
            found,
            vec![
                ("skill:alpha".to_string(), "1.2.3".to_string()),
                ("skill:beta".to_string(), "0.1.0".to_string()),
            ],
        );
    }

    #[test]
    fn scan_skills_reports_dirs_without_skill_yaml_as_failed_probe_rows() {
        let home = tempfile::tempdir().unwrap();
        let skills = home.path().join("skills");
        std::fs::create_dir_all(skills.join("orphan")).unwrap();
        // Compatibility inventory helpers return only valid rows.
        assert!(scan_installed_skills(home.path()).is_empty());
        // The actual updater/cron surface preserves the partial as an explicit
        // failed component instead of silently pretending the store is empty.
        let specs = skill_plugin_specs_for_home(
            home.path(),
            &config_path(home.path()),
            GateDecision::Allow,
        );
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "skill:orphan");
        assert!(
            specs[0]
                .latest_version
                .as_ref()
                .unwrap_err()
                .contains("no skill.yaml")
        );
    }

    #[test]
    fn scan_skills_reports_non_directory_entries_as_failed_probe_rows() {
        let home = tempfile::tempdir().unwrap();
        let skills = home.path().join("skills");
        std::fs::create_dir_all(&skills).unwrap();
        std::fs::write(skills.join("not-a-package"), b"not a skill directory").unwrap();

        let specs = skill_plugin_specs_for_home(
            home.path(),
            &config_path(home.path()),
            GateDecision::Allow,
        );
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "skill:not-a-package");
        assert!(
            specs[0]
                .latest_version
                .as_ref()
                .unwrap_err()
                .contains("not a real directory")
        );
    }

    #[test]
    fn manifest_scan_stops_at_aggregate_component_budget() {
        let home = tempfile::tempdir().unwrap();
        let plugins = home.path().join("plugins");
        for id in ["one", "two", "three"] {
            let directory = plugins.join(id);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("plugin.toml"), b"id = 'placeholder'").unwrap();
        }

        let scan =
            scan_bound_manifests_with_limits(&plugins, "plugin", "plugin.toml", 2, usize::MAX);
        assert_eq!(scan.manifests.len(), 2);
        assert_eq!(scan.failures.len(), 1);
        assert!(scan.failures[0].error.contains("2-entry updater limit"));
    }

    #[test]
    fn manifest_scan_stops_at_aggregate_manifest_byte_budget() {
        let home = tempfile::tempdir().unwrap();
        let plugin = home.path().join("plugins").join("oversized-total");
        std::fs::create_dir_all(&plugin).unwrap();
        std::fs::write(plugin.join("plugin.toml"), b"12345").unwrap();

        let scan = scan_bound_manifests_with_limits(
            &home.path().join("plugins"),
            "plugin",
            "plugin.toml",
            10,
            4,
        );
        assert!(scan.manifests.is_empty());
        assert_eq!(scan.failures.len(), 1);
        assert!(
            scan.failures[0]
                .error
                .contains("4-byte aggregate updater limit")
        );
    }

    #[test]
    fn scan_skills_rejects_id_mismatch_as_failed_probe_row() {
        let home = tempfile::tempdir().unwrap();
        let installed = home.path().join("skills").join("expected");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(
            installed.join("skill.yaml"),
            "id: different\ndescription: mismatch\nversion: 1.0.0\n",
        )
        .unwrap();

        let specs = skill_plugin_specs_for_home(
            home.path(),
            &config_path(home.path()),
            GateDecision::Allow,
        );
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "skill:expected");
        assert_eq!(specs[0].current_version, "unknown");
        assert!(
            specs[0]
                .latest_version
                .as_ref()
                .unwrap_err()
                .contains("does not match directory")
        );
    }

    #[test]
    fn scan_skills_rejects_linked_directory_without_reading_outside() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("skill.yaml"),
            "id: linked\ndescription: outside\nversion: 9.9.9\n",
        )
        .unwrap();
        let skills = home.path().join("skills");
        std::fs::create_dir_all(&skills).unwrap();
        try_symlink_dir(outside.path(), &skills.join("linked"))
            .expect("create linked skill fixture");

        let specs = skill_plugin_specs_for_home(
            home.path(),
            &config_path(home.path()),
            GateDecision::Allow,
        );
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "skill:linked");
        assert_eq!(specs[0].current_version, "unknown");
        let error = specs[0].latest_version.as_ref().unwrap_err();
        assert!(error.contains("linked/reparse") || error.contains("unsafe skill directory"));
        assert!(!error.contains("9.9.9"));
    }

    #[test]
    fn scan_skills_rejects_oversized_manifest_as_failed_probe_row() {
        let home = tempfile::tempdir().unwrap();
        let installed = home.path().join("skills").join("oversized");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(
            installed.join("skill.yaml"),
            vec![b'x'; MAX_UPDATE_MANIFEST_BYTES + 1],
        )
        .unwrap();

        let specs = skill_plugin_specs_for_home(
            home.path(),
            &config_path(home.path()),
            GateDecision::Allow,
        );
        assert_eq!(specs.len(), 1);
        assert!(
            specs[0]
                .latest_version
                .as_ref()
                .unwrap_err()
                .contains("exceeds the")
        );
    }

    #[test]
    fn scan_plugins_returns_empty_when_dir_missing() {
        let home = tempfile::tempdir().unwrap();
        assert!(scan_installed_plugins(home.path(), &config_path(home.path())).is_empty());
    }

    #[test]
    fn skill_plugin_specs_for_home_pairs_each_with_no_registry_err() {
        let home = tempfile::tempdir().unwrap();
        let skills = home.path().join("skills");
        std::fs::create_dir_all(skills.join("alpha")).unwrap();
        std::fs::write(
            skills.join("alpha").join("skill.yaml"),
            "id: alpha\ndescription: A\nversion: 0.7.0\n",
        )
        .unwrap();
        let specs = skill_plugin_specs_for_home(
            home.path(),
            &config_path(home.path()),
            GateDecision::Allow,
        );
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "skill:alpha");
        assert_eq!(specs[0].current_version, "0.7.0");
        match &specs[0].latest_version {
            Err(msg) => assert!(msg.contains("no upstream registry")),
            Ok(_) => panic!("U-02 must surface no-registry error until U-02b ships"),
        }
    }

    #[test]
    fn scan_installed_skills_rows_carries_source_when_present() {
        let home = tempfile::tempdir().unwrap();
        let skills = home.path().join("skills");
        std::fs::create_dir_all(skills.join("with-source")).unwrap();
        std::fs::write(
            skills.join("with-source").join("skill.yaml"),
            "id: with-source\n\
             description: U-02b drift-guard\n\
             version: 1.0.0\n\
             source: git+https://github.com/example/with-source\n",
        )
        .unwrap();
        std::fs::create_dir_all(skills.join("no-source")).unwrap();
        std::fs::write(
            skills.join("no-source").join("skill.yaml"),
            "id: no-source\ndescription: legacy\nversion: 0.1.0\n",
        )
        .unwrap();
        let rows = scan_installed_skills_rows(home.path());
        assert_eq!(rows.len(), 2);
        let with = rows
            .iter()
            .find(|r| r.name == "skill:with-source")
            .expect("with-source row present");
        assert_eq!(
            with.source.as_deref(),
            Some("git+https://github.com/example/with-source"),
        );
        let without = rows
            .iter()
            .find(|r| r.name == "skill:no-source")
            .expect("no-source row present");
        assert!(without.source.is_none());
    }

    #[tokio::test]
    async fn async_specs_returns_sentinel_for_skills_without_source() {
        let home = tempfile::tempdir().unwrap();
        let skills = home.path().join("skills");
        std::fs::create_dir_all(skills.join("legacy")).unwrap();
        std::fs::write(
            skills.join("legacy").join("skill.yaml"),
            "id: legacy\ndescription: no source field\nversion: 0.1.0\n",
        )
        .unwrap();
        let specs = skill_plugin_specs_for_home_async(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
        )
        .await;
        assert_eq!(specs.len(), 1);
        match &specs[0].latest_version {
            Err(msg) => assert!(
                msg.contains("no upstream registry"),
                "skills without source MUST surface the sentinel, got: {msg}"
            ),
            Ok(_) => panic!("source-less skill must NOT report a real version"),
        }
    }

    #[tokio::test]
    async fn detached_policy_source_skill_never_gains_network_authority() {
        let home = tempfile::tempdir().unwrap();
        write_skill(
            home.path(),
            "detached",
            "id: detached\n\
             description: detached policy cannot authorize egress\n\
             version: 1.0.0\n\
             source: git+https://127.0.0.1/authority-bypass\n",
        );

        let specs = skill_plugin_specs_for_home_async(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
        )
        .await;

        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].latest_version.as_ref().unwrap_err(),
            SKILL_AUTHORITY_REQUIRED_MSG
        );
    }

    #[tokio::test]
    async fn resolver_sink_rejects_installed_skill_without_exact_authority() {
        let home = tempfile::tempdir().unwrap();
        write_skill(
            home.path(),
            "unapproved-source",
            "id: unapproved-source\n\
             description: no authority means no source probe\n\
             version: 1.0.0\n\
             source: git+https://github.com/example/unapproved-source\n",
        );
        let reload = test_reload_controller(home.path());
        let row = super::scan_installed_skills_checked(
            home.path(),
            &reload.accepted_snapshot().config().skills,
        )
        .rows
        .pop()
        .expect("source-bearing installed candidate");
        let calls = Arc::new(AtomicUsize::new(0));

        let result = super::resolve_authorized_skill_latest_at_sink_with_resolver(
            home.path(),
            &reload,
            &row,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            result
                .unwrap_err()
                .starts_with(SKILL_AUTHORITY_REQUIRED_MSG)
        );
    }

    #[tokio::test]
    async fn resolver_sink_consumes_active_exact_generation_authority() {
        let home = tempfile::tempdir().unwrap();
        let id = "approved-source";
        write_skill(
            home.path(),
            id,
            "id: approved-source\n\
             description: exact authority permits this source probe\n\
             version: 1.0.0\n\
             source: git+https://github.com/example/approved-source\n",
        );
        install_test_wal_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path());
        activate_test_skill(home.path(), id, &reload);
        let row = super::scan_installed_skills_checked(
            home.path(),
            &reload.accepted_snapshot().config().skills,
        )
        .rows
        .pop()
        .expect("authorized installed Skill row");
        let calls = Arc::new(AtomicUsize::new(0));

        let result = super::resolve_authorized_skill_latest_at_sink_with_resolver(
            home.path(),
            &reload,
            &row,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(result.as_deref(), Ok("v9.9.9"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resolver_sink_rejects_post_authority_package_edit() {
        let home = tempfile::tempdir().unwrap();
        let id = "edited-source";
        write_skill(
            home.path(),
            id,
            "id: edited-source\n\
             description: later bytes invalidate authority\n\
             version: 1.0.0\n\
             source: git+https://github.com/example/edited-source\n",
        );
        install_test_wal_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path());
        activate_test_skill(home.path(), id, &reload);
        let row = super::scan_installed_skills_checked(
            home.path(),
            &reload.accepted_snapshot().config().skills,
        )
        .rows
        .pop()
        .expect("authorized installed Skill row");
        std::fs::write(
            home.path().join("skills").join(id).join("changed.txt"),
            b"changed after authority",
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));

        let result = super::resolve_authorized_skill_latest_at_sink_with_resolver(
            home.path(),
            &reload,
            &row,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            result
                .unwrap_err()
                .starts_with(SKILL_AUTHORITY_REQUIRED_MSG)
        );
    }

    #[tokio::test]
    async fn resolver_sink_rejects_revocation_after_scan_without_calling_resolver() {
        let home = tempfile::tempdir().unwrap();
        let id = "revoked-source";
        write_skill(
            home.path(),
            id,
            "id: revoked-source\n\
             description: revocation wins at the resolver sink\n\
             version: 1.0.0\n\
             source: git+https://github.com/example/revoked-source\n",
        );
        install_test_wal_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path());
        activate_test_skill(home.path(), id, &reload);
        let row = super::scan_installed_skills_checked(
            home.path(),
            &reload.accepted_snapshot().config().skills,
        )
        .rows
        .pop()
        .expect("authorized installed Skill row");
        let revoke = crate::skills::authority::SkillAuthorityDecision::new(
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli,
            crate::skills::authority::SkillAuthorityState::Revoked,
            Some("test revocation before resolver dispatch".to_string()),
        )
        .unwrap();
        crate::skills::authority::publish_installed_authority_decision(
            home.path(),
            id,
            &reload,
            revoke,
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));

        let result = super::resolve_authorized_skill_latest_at_sink_with_resolver(
            home.path(),
            &reload,
            &row,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            result
                .unwrap_err()
                .starts_with(SKILL_AUTHORITY_REQUIRED_MSG)
        );
    }

    #[tokio::test]
    async fn resolver_sink_rejects_identical_reinstall_incarnation_without_network() {
        let home = tempfile::tempdir().unwrap();
        let id = "reinstalled-source";
        write_skill(
            home.path(),
            id,
            "id: reinstalled-source\n\
             description: identical bytes still form a new install incarnation\n\
             version: 1.0.0\n\
             source: git+https://github.com/example/reinstalled-source\n",
        );
        install_test_wal_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path());
        activate_test_skill(home.path(), id, &reload);
        let row = super::scan_installed_skills_checked(
            home.path(),
            &reload.accepted_snapshot().config().skills,
        )
        .rows
        .pop()
        .expect("authorized installed Skill row");

        // A committed reinstall mints a fresh incarnation even when every
        // package byte is identical. The prior activation must not ride across
        // that ABA boundary.
        record_test_install_incarnation(home.path(), id);
        let calls = Arc::new(AtomicUsize::new(0));

        let result = super::resolve_authorized_skill_latest_at_sink_with_resolver(
            home.path(),
            &reload,
            &row,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            result
                .unwrap_err()
                .starts_with(SKILL_AUTHORITY_REQUIRED_MSG)
        );
    }

    #[tokio::test]
    async fn resolver_sink_calls_resolver_for_unchanged_enabled_skill() {
        let home = tempfile::tempdir().unwrap();
        write_skill(
            home.path(),
            "with-src",
            "id: with-src\n\
             description: U-02b live-resolver wiring\n\
             version: 1.0.0\n\
             source: git+https://github.com/example/with-src\n",
        );
        let row = scan_installed_skills_checked(home.path(), &config_path(home.path()))
            .rows
            .pop()
            .expect("enabled source-bound skill");
        let calls = Arc::new(AtomicUsize::new(0));
        let result = resolve_skill_latest_at_sink_with_resolver(
            home.path(),
            &config_path(home.path()),
            &row,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(result.as_deref(), Ok("v9.9.9"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exact_custom_skill_policy_denial_wins_without_network() {
        let home = tempfile::tempdir().unwrap();
        write_skill(
            home.path(),
            "custom-denied",
            "id: custom-denied\ndescription: custom policy\nversion: 1.0.0\nsource: git+https://github.com/example/custom-denied\n",
        );
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  enabled: [custom-denied]\n",
        )
        .unwrap();
        let custom_path = home.path().join("custom.yaml");
        std::fs::write(&custom_path, "skills:\n  disabled: [custom-denied]\n").unwrap();
        let row = scan_installed_skills_checked(home.path(), &custom_path)
            .rows
            .pop()
            .expect("disabled row remains operator-visible");
        assert!(!row.enabled);
        let calls = Arc::new(AtomicUsize::new(0));
        let result = resolve_skill_latest_at_sink_with_resolver(
            home.path(),
            &custom_path,
            &row,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(result.unwrap_err(), DISABLED_SKILL_PROBE_MSG);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rejected_on_disk_skill_policy_never_overrides_accepted_snapshot() {
        let home = tempfile::tempdir().unwrap();
        write_skill(
            home.path(),
            "revoked-at-sink",
            "id: revoked-at-sink\ndescription: policy drift\nversion: 1.0.0\nsource: git+https://github.com/example/revoked-at-sink\n",
        );
        let custom_path = home.path().join("custom.yaml");
        std::fs::write(&custom_path, "skills:\n  enabled: [revoked-at-sink]\n").unwrap();
        let (accepted_skills, accepted_plugins) = accepted_policies_at(&custom_path);
        let row = super::scan_installed_skills_checked(home.path(), &accepted_skills)
            .rows
            .pop()
            .expect("initially enabled skill generation");
        std::fs::write(&custom_path, "skills:\n  disabled: [revoked-at-sink]\n").unwrap();

        let specs = super::skill_plugin_specs_for_home(
            home.path(),
            &accepted_skills,
            &accepted_plugins,
            GateDecision::Allow,
        );
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].latest_version.as_ref().unwrap_err(),
            NO_REGISTRY_RESOLVER_MSG
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let result = super::resolve_skill_latest_at_sink_with_resolver(
            home.path(),
            &accepted_skills,
            &row,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(result.as_deref(), Ok("v9.9.9"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn skill_resolver_sink_rejects_changed_package_generation() {
        let home = tempfile::tempdir().unwrap();
        write_skill(
            home.path(),
            "mutated-at-sink",
            "id: mutated-at-sink\ndescription: generation drift\nversion: 1.0.0\nsource: git+https://github.com/example/mutated-at-sink\n",
        );
        let row = scan_installed_skills_checked(home.path(), &config_path(home.path()))
            .rows
            .pop()
            .expect("initial source-bound generation");
        std::fs::write(
            home.path()
                .join("skills")
                .join("mutated-at-sink")
                .join("asset.txt"),
            b"generation changed",
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let result = resolve_skill_latest_at_sink_with_resolver(
            home.path(),
            &config_path(home.path()),
            &row,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(result.unwrap_err().contains("generation changed"));
    }

    #[tokio::test]
    async fn disabled_skill_manifest_never_enters_source_resolver() {
        let home = tempfile::tempdir().unwrap();
        let installed = home.path().join("skills").join("disabled");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(
            installed.join("skill.yaml"),
            "id: disabled\ndescription: disabled\nversion: 1.0.0\nenabled: false\nsource: git+https://127.0.0.1/hostile/repo\n",
        )
        .unwrap();

        let specs = skill_plugin_specs_for_home_async(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
        )
        .await;
        let error = specs[0].latest_version.as_ref().unwrap_err();
        assert_eq!(error, DISABLED_SKILL_PROBE_MSG);
        assert!(!error.contains("approved public forge"));
    }

    #[tokio::test]
    async fn freedom_disabled_skill_never_enters_source_resolver() {
        let home = tempfile::tempdir().unwrap();
        let installed = home.path().join("skills").join("blocked");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(
            installed.join("skill.yaml"),
            "id: blocked\ndescription: blocked\nversion: 1.0.0\nsource: git+https://127.0.0.1/hostile/repo\n",
        )
        .unwrap();
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  disabled: [blocked]\n",
        )
        .unwrap();

        let specs = skill_plugin_specs_for_home_async(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
        )
        .await;
        assert_eq!(
            specs[0].latest_version.as_ref().unwrap_err(),
            DISABLED_SKILL_PROBE_MSG
        );
    }

    #[tokio::test]
    async fn visibility_off_skill_never_enters_source_resolver() {
        let home = tempfile::tempdir().unwrap();
        let installed = home.path().join("skills").join("hidden");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(
            installed.join("skill.yaml"),
            "id: hidden\ndescription: hidden\nversion: 1.0.0\nvisibility: off\nsource: git+https://127.0.0.1/hostile/repo\n",
        )
        .unwrap();

        let specs = skill_plugin_specs_for_home_async(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
        )
        .await;
        assert_eq!(
            specs[0].latest_version.as_ref().unwrap_err(),
            DISABLED_SKILL_PROBE_MSG
        );
    }

    #[tokio::test]
    async fn denied_update_gate_never_enters_source_resolver() {
        let home = tempfile::tempdir().unwrap();
        let installed = home.path().join("skills").join("denied");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(
            installed.join("skill.yaml"),
            "id: denied\ndescription: denied\nversion: 1.0.0\nsource: git+https://github.com/example/denied\n",
        )
        .unwrap();
        let gate = GateDecision::Deny {
            reason: "operator disabled updater".to_string(),
        };

        let specs = skill_plugin_specs_for_home_async(
            home.path().to_path_buf(),
            config_path(home.path()),
            gate,
        )
        .await;
        assert_eq!(
            specs[0].latest_version.as_ref().unwrap_err(),
            UPDATE_PROBE_DENIED_MSG
        );
        assert!(matches!(specs[0].gate_decision, GateDecision::Deny { .. }));
    }

    #[tokio::test]
    async fn unapproved_plugin_never_enters_source_resolver() {
        let home = tempfile::tempdir().unwrap();
        write_plugin(
            home.path(),
            "pending",
            "id = \"pending\"\nname = \"Pending\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/pending\"\n",
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let specs = skill_plugin_specs_for_home_async_with_plugin_resolver(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
            counting_resolver(calls.clone()),
        )
        .await;
        let error = specs[0].latest_version.as_ref().unwrap_err();
        assert!(error.contains("activation is not active"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn plugin_probe_requires_host_active_approval_and_non_revocation() {
        let home = tempfile::tempdir().unwrap();
        let manifest = "id = \"approved\"\nname = \"Approved\"\nversion = \"1.0.0\"\n";
        write_plugin(home.path(), "approved", manifest);
        let plugin = crate::wasm_plugin::discovery::discover_one(
            &home.path().join("plugins").join("approved"),
        )
        .unwrap();
        let mut policy = crate::config::WasmPluginsConfig::default();
        policy.activations.insert(
            plugin.manifest.id.clone(),
            crate::wasm_plugin::discovery::PluginActivationRecord::active_for(&plugin),
        );
        assert!(
            crate::wasm_plugin::discovery::validate_runtime_admission(&plugin, &policy).is_ok()
        );

        policy.enabled = false;
        assert!(matches!(
            crate::wasm_plugin::discovery::validate_runtime_admission(&plugin, &policy),
            Err(crate::wasm_plugin::discovery::RuntimePluginAdmissionError::HostDisabled)
        ));
        policy.enabled = true;
        policy.revoked_ids.push(plugin.manifest.id.clone());
        assert!(matches!(
            crate::wasm_plugin::discovery::validate_runtime_admission(&plugin, &policy),
            Err(
                crate::wasm_plugin::discovery::RuntimePluginAdmissionError::Integrity(
                    crate::wasm_plugin::discovery::DiscoveryError::Revoked { .. }
                )
            )
        ));
    }

    // ── Session 27 — U-02b plugin parity drift guards ─────────────────
    //
    // Same three cases as skills above, mirrored against the plugin
    // probe. The symmetry is load-bearing: a future PluginManifest
    // refactor that drops the `source` field would silently break the
    // resolver lane for plugins, and these tests are the canary.

    #[test]
    fn scan_installed_plugins_rows_carries_source_when_present() {
        let home = tempfile::tempdir().unwrap();
        write_plugin(
            home.path(),
            "with_source",
            "id = \"with_source\"\n\
             name = \"With Source\"\n\
             version = \"1.0.0\"\n\
             source = \"git+https://github.com/example/with-source\"\n",
        );
        write_plugin(
            home.path(),
            "no_source",
            "id = \"no_source\"\nname = \"Legacy\"\nversion = \"0.1.0\"\n",
        );
        let rows = scan_installed_plugins_rows(home.path(), &config_path(home.path()));
        assert_eq!(rows.len(), 2);
        let with = rows
            .iter()
            .find(|r| r.name == "plugin:with_source")
            .expect("with_source row present");
        assert_eq!(
            with.source.as_deref(),
            Some("git+https://github.com/example/with-source"),
        );
        let without = rows
            .iter()
            .find(|r| r.name == "plugin:no_source")
            .expect("no_source row present");
        assert!(without.source.is_none());
    }

    #[tokio::test]
    async fn async_specs_returns_sentinel_for_plugins_without_source() {
        let home = tempfile::tempdir().unwrap();
        let manifest = "id = \"legacy\"\nname = \"Legacy\"\nversion = \"0.1.0\"\n";
        write_plugin(home.path(), "legacy", manifest);
        approve_plugin(home.path(), manifest);
        let specs = skill_plugin_specs_for_home_async(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
        )
        .await;
        assert_eq!(specs.len(), 1);
        match &specs[0].latest_version {
            Err(msg) => assert!(
                msg.contains("no upstream registry"),
                "plugins without source MUST surface the sentinel, got: {msg}"
            ),
            Ok(_) => panic!("source-less plugin must NOT report a real version"),
        }
    }

    #[tokio::test]
    async fn async_specs_attempts_resolver_for_plugins_with_source() {
        let home = tempfile::tempdir().unwrap();
        let manifest = "id = \"with_src\"\n\
                        name = \"With Src\"\n\
                        version = \"1.0.0\"\n\
                        source = \"git+https://github.com/example/with-src\"\n";
        write_plugin(home.path(), "with_src", manifest);
        approve_plugin(home.path(), manifest);
        let calls = Arc::new(AtomicUsize::new(0));
        let specs = skill_plugin_specs_for_home_async_with_plugin_resolver(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
            counting_resolver(calls.clone()),
        )
        .await;
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].latest_version.as_deref(), Ok("v9.9.9"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn custom_config_path_denial_wins_over_home_freedom_allow() {
        let home = tempfile::tempdir().unwrap();
        let manifest = "id = \"custom_denied\"\nname = \"Custom Denied\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/custom-denied\"\n";
        write_plugin(home.path(), "custom_denied", manifest);
        approve_plugin(home.path(), manifest);
        let allowed = std::fs::read_to_string(config_path(home.path())).unwrap();
        let custom_path = home.path().join("custom.yaml");
        std::fs::write(
            &custom_path,
            allowed.replacen("enabled: true", "enabled: false", 1),
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let specs = skill_plugin_specs_for_home_async_with_plugin_resolver(
            home.path().to_path_buf(),
            custom_path,
            GateDecision::Allow,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            specs[0]
                .latest_version
                .as_ref()
                .unwrap_err()
                .contains("host is disabled")
        );
    }

    #[tokio::test]
    async fn rejected_on_disk_plugin_policy_never_overrides_accepted_snapshot() {
        let home = tempfile::tempdir().unwrap();
        let manifest = "id = \"sink_denied\"\nname = \"Sink Denied\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/sink-denied\"\n";
        write_plugin(home.path(), "sink_denied", manifest);
        approve_plugin(home.path(), manifest);
        let allowed = std::fs::read_to_string(config_path(home.path())).unwrap();
        let custom_path = home.path().join("custom.yaml");
        std::fs::write(&custom_path, &allowed).unwrap();
        let (accepted_skills, accepted_plugins) = accepted_policies_at(&custom_path);
        let row = super::scan_installed_plugins_checked(home.path(), &accepted_plugins)
            .rows
            .pop()
            .expect("custom config initially admits the exact generation");

        std::fs::write(
            &custom_path,
            allowed.replacen("enabled: true", "enabled: false", 1),
        )
        .unwrap();

        let specs = super::skill_plugin_specs_for_home(
            home.path(),
            &accepted_skills,
            &accepted_plugins,
            GateDecision::Allow,
        );
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].latest_version.as_ref().unwrap_err(),
            NO_REGISTRY_RESOLVER_MSG
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let result = super::resolve_plugin_latest_at_sink(
            home.path(),
            &accepted_plugins,
            &row,
            &counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(result.as_deref(), Ok("v9.9.9"));
    }

    #[tokio::test]
    async fn missing_wasm_never_reaches_plugin_resolver() {
        let home = tempfile::tempdir().unwrap();
        let installed = home.path().join("plugins").join("missing_wasm");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(
            installed.join("plugin.toml"),
            "id = \"missing_wasm\"\nname = \"Missing\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/missing\"\n",
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let specs = skill_plugin_specs_for_home_async_with_plugin_resolver(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(specs.len(), 1);
        assert!(
            specs[0]
                .latest_version
                .as_ref()
                .unwrap_err()
                .contains("plugin.wasm is missing")
        );
    }

    #[tokio::test]
    async fn linked_plugin_directory_never_reaches_plugin_resolver() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let manifest = "id = \"linked\"\nname = \"Linked\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/linked\"\n";
        write_plugin(outside.path(), "linked", manifest);
        let plugins = home.path().join("plugins");
        std::fs::create_dir_all(&plugins).unwrap();
        try_symlink_dir(
            &outside.path().join("plugins").join("linked"),
            &plugins.join("linked"),
        )
        .expect("create linked plugin fixture");
        let calls = Arc::new(AtomicUsize::new(0));
        let specs = skill_plugin_specs_for_home_async_with_plugin_resolver(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(specs.len(), 1);
        let error = specs[0].latest_version.as_ref().unwrap_err();
        assert!(error.contains("linked") || error.contains("reparse"));
        assert!(!error.contains(outside.path().to_string_lossy().as_ref()));
    }

    #[tokio::test]
    async fn nonregular_and_oversize_wasm_never_reach_plugin_resolver() {
        let home = tempfile::tempdir().unwrap();
        let nonregular = home.path().join("plugins").join("nonregular");
        std::fs::create_dir_all(nonregular.join("plugin.wasm")).unwrap();
        std::fs::write(
            nonregular.join("plugin.toml"),
            "id = \"nonregular\"\nname = \"Nonregular\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/nonregular\"\n",
        )
        .unwrap();
        let oversize = home.path().join("plugins").join("oversize");
        std::fs::create_dir_all(&oversize).unwrap();
        std::fs::write(
            oversize.join("plugin.toml"),
            "id = \"oversize\"\nname = \"Oversize\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/oversize\"\n",
        )
        .unwrap();
        std::fs::File::create(oversize.join("plugin.wasm"))
            .unwrap()
            .set_len(crate::wasm_plugin::discovery::MAX_WASM_BYTES + 1)
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let specs = skill_plugin_specs_for_home_async_with_plugin_resolver(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(specs.len(), 2);
        let errors = specs
            .iter()
            .map(|spec| spec.latest_version.as_ref().unwrap_err().as_str())
            .collect::<Vec<_>>();
        assert!(
            errors
                .iter()
                .any(|error| error.contains("not a real regular file")
                    || error.contains("unreadable"))
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("runtime size limit"))
        );
    }

    #[tokio::test]
    async fn pin_and_signature_failures_never_reach_plugin_resolver_and_are_redacted() {
        let pin_home = tempfile::tempdir().unwrap();
        let pin_manifest = "id = \"bad_pin\"\nname = \"Bad Pin\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/bad-pin\"\n";
        write_plugin(pin_home.path(), "bad_pin", pin_manifest);
        approve_plugin_with_policy(
            pin_home.path(),
            pin_manifest,
            "    pinned_hashes:\n      bad_pin: deadbeef\n",
        );
        let pin_calls = Arc::new(AtomicUsize::new(0));
        let pin_specs = skill_plugin_specs_for_home_async_with_plugin_resolver(
            pin_home.path().to_path_buf(),
            config_path(pin_home.path()),
            GateDecision::Allow,
            counting_resolver(pin_calls.clone()),
        )
        .await;
        let pin_error = pin_specs[0].latest_version.as_ref().unwrap_err();
        assert_eq!(pin_calls.load(Ordering::SeqCst), 0);
        assert!(pin_error.contains("configured pin"));
        assert!(!pin_error.contains("deadbeef"));
        assert!(!pin_error.contains(pin_home.path().to_string_lossy().as_ref()));

        let sig_home = tempfile::tempdir().unwrap();
        let sig_manifest = "id = \"bad_sig\"\nname = \"Bad Sig\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/bad-sig\"\n";
        write_plugin(sig_home.path(), "bad_sig", sig_manifest);
        std::fs::write(
            sig_home
                .path()
                .join("plugins")
                .join("bad_sig")
                .join("plugin.wasm.minisig"),
            "not a signature",
        )
        .unwrap();
        approve_plugin_with_policy(
            sig_home.path(),
            sig_manifest,
            "    author_pubkey: not-a-valid-minisign-key\n    require_signature: true\n",
        );
        let sig_calls = Arc::new(AtomicUsize::new(0));
        let sig_specs = skill_plugin_specs_for_home_async_with_plugin_resolver(
            sig_home.path().to_path_buf(),
            config_path(sig_home.path()),
            GateDecision::Allow,
            counting_resolver(sig_calls.clone()),
        )
        .await;
        let sig_error = sig_specs[0].latest_version.as_ref().unwrap_err();
        assert_eq!(sig_calls.load(Ordering::SeqCst), 0);
        assert!(sig_error.contains("signature") || sig_error.contains("author key"));
        assert!(!sig_error.contains("not-a-valid-minisign-key"));
    }

    #[tokio::test]
    async fn require_all_pinned_without_pin_never_reaches_plugin_resolver() {
        let home = tempfile::tempdir().unwrap();
        let manifest = "id = \"unpinned\"\nname = \"Unpinned\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/unpinned\"\n";
        write_plugin(home.path(), "unpinned", manifest);
        approve_plugin_with_policy(home.path(), manifest, "    require_all_pinned: true\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let specs = skill_plugin_specs_for_home_async_with_plugin_resolver(
            home.path().to_path_buf(),
            config_path(home.path()),
            GateDecision::Allow,
            counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            specs[0]
                .latest_version
                .as_ref()
                .unwrap_err()
                .contains("require_all_pinned")
        );
    }

    #[tokio::test]
    async fn resolver_sink_rejects_mutated_generation_without_calling_resolver() {
        let home = tempfile::tempdir().unwrap();
        let manifest = "id = \"mutated\"\nname = \"Mutated\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/mutated\"\n";
        write_plugin(home.path(), "mutated", manifest);
        approve_plugin(home.path(), manifest);
        let row = scan_installed_plugins_checked(home.path(), &config_path(home.path()))
            .rows
            .pop()
            .expect("initial runtime-admitted generation");
        std::fs::write(
            home.path()
                .join("plugins")
                .join("mutated")
                .join("plugin.wasm"),
            b"changed generation",
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let result = resolve_plugin_latest_at_sink(
            home.path(),
            &config_path(home.path()),
            &row,
            &counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(result.unwrap_err().contains("generation changed"));
    }

    #[tokio::test]
    async fn resolver_sink_enforces_newly_accepted_revocation_snapshot() {
        let home = tempfile::tempdir().unwrap();
        let manifest = "id = \"revoked_at_barrier\"\nname = \"Revoked\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/example/revoked\"\n";
        write_plugin(home.path(), "revoked_at_barrier", manifest);
        approve_plugin(home.path(), manifest);
        let row = scan_installed_plugins_checked(home.path(), &config_path(home.path()))
            .rows
            .pop()
            .expect("initial runtime-admitted generation");
        approve_plugin_with_policy(
            home.path(),
            manifest,
            "    revoked_ids: [revoked_at_barrier]\n",
        );
        let (_, accepted_plugins) = accepted_policies_at(&config_path(home.path()));
        let calls = Arc::new(AtomicUsize::new(0));
        let result = super::resolve_plugin_latest_at_sink(
            home.path(),
            &accepted_plugins,
            &row,
            &counting_resolver(calls.clone()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(result.unwrap_err().contains("revoked"));
    }
}
