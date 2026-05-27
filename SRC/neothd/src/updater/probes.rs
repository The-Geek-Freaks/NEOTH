//! U-01 + U-03 probe builders — bridges the existing
//! `self_update::check_for_update` (GitHub Releases) +
//! `check_all` (npm CLI versions) probes into the
//! `ComponentSpec` shape the U-04 cron loop consumes.
//!
//! The cron loop's builder signature is sync `Fn() -> Vec<ComponentSpec>`
//! because it runs on `tokio::task::spawn_blocking`. Each probe
//! here exposes both async + sync wrappers:
//!
//!   - `*_specs_async()` for callers in async contexts (tests,
//!     ad-hoc CLI subcommands).
//!   - `*_specs_blocking()` for the cron-builder closure — uses
//!     `tokio::runtime::Handle::current().block_on()` to drive
//!     the async probe from the blocking thread.
//!
//! Failure modes are encoded in the `ComponentSpec.latest_version
//! : Result<String, String>` field: a network error becomes
//! `Err("github probe: <msg>")` which `compute_outcome` turns
//! into `ComponentStatus::Failed`. The cron loop still emits the
//! audit frame so operators see "yes, the cron ran; yes, it
//! tried; here's why it didn't have a latest_version answer".

use crate::updater::pipeline::{ComponentSpec, GateDecision, cli_version_specs, neoth_self_specs};
use crate::updater::self_update::{check_for_update, current_version};

/// Canonical owner/repo for the `neothd` binary lookup.
pub const NEOTH_OWNER_REPO: &str = "The-Geek-Freaks/NEOTH";

// ── U-01 neoth_self ──────────────────────────────────────────────────────────

/// Probe `neothd` self-version. Returns a single-component spec
/// list ready for `run_updater_pass(UpdaterTaskKind::NeothSelf, …)`.
pub async fn neoth_self_specs_async(gate: GateDecision) -> Vec<ComponentSpec> {
    let current = current_version().to_string();
    let latest = match check_for_update(NEOTH_OWNER_REPO).await {
        Ok(c) => Ok(c.latest),
        Err(e) => Err(format!("github probe: {e}")),
    };
    neoth_self_specs(current, latest, gate)
}

/// Sync wrapper for the U-04 cron-builder closure. Calls
/// `block_on` on the current tokio runtime — safe because the
/// closure runs on `spawn_blocking` (no nested-runtime issue).
pub fn neoth_self_specs_blocking(gate: GateDecision) -> Vec<ComponentSpec> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(neoth_self_specs_async(gate)),
        Err(_) => Vec::new(),
    }
}

// ── U-03 cli_version ─────────────────────────────────────────────────────────

/// Probe every CLI we manage (`claude-cli`, `antigravity-cli`,
/// `codex`) and project into a spec list for
/// `run_updater_pass(UpdaterTaskKind::CliVersion, …)`. CLIs that
/// aren't installed produce no spec entry (matches
/// `pipeline::cli_version_specs`'s `Option`-skip contract).
pub async fn cli_version_specs_async(gate: GateDecision) -> Vec<ComponentSpec> {
    use crate::updater::Component;
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
}

/// Scan `~/.neoth/skills/<id>/skill.yaml` files + return
/// [`InstalledSkillRow`] per skill. Malformed YAMLs skip silently —
/// the skill registry's own load path surfaces the error elsewhere;
/// the updater probe stays observability-only.
pub fn scan_installed_skills_rows(home: &std::path::Path) -> Vec<InstalledSkillRow> {
    let dir = home.join("skills");
    let Ok(read) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("skill.yaml");
        let Ok(body) = std::fs::read_to_string(&manifest_path) else {
            continue;
        };
        if let Ok(m) = serde_yaml::from_str::<crate::skills::schema::SkillManifest>(&body) {
            out.push(InstalledSkillRow {
                name: format!("skill:{}", m.id),
                version: m.version,
                source: m.source,
            });
        }
    }
    out
}

/// Backwards-compatible alias: callers that don't need the source
/// URL keep the `(name, version)` shape. New callers use
/// [`scan_installed_skills_rows`] directly.
pub fn scan_installed_skills(home: &std::path::Path) -> Vec<(String, String)> {
    scan_installed_skills_rows(home)
        .into_iter()
        .map(|r| (r.name, r.version))
        .collect()
}

/// Scan `~/.neoth/plugins/<id>/plugin.toml` files + return
/// (id, version) per plugin. Same defensive shape as
/// `scan_installed_skills`.
pub fn scan_installed_plugins(home: &std::path::Path) -> Vec<(String, String)> {
    let dir = home.join("plugins");
    let Ok(read) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("plugin.toml");
        let Ok(body) = std::fs::read_to_string(&manifest_path) else {
            continue;
        };
        if let Ok(m) = toml::from_str::<crate::wasm_plugin::manifest::PluginManifest>(&body) {
            out.push((format!("plugin:{}", m.id), m.version));
        }
    }
    out
}

/// Sentinel error string the U-02 probe writes into
/// `latest_version: Err(…)` until a real skill/plugin registry
/// ships. Operators see the WAL audit + the `neoth updater
/// status` "no upstream resolver" line so the cron's presence is
/// audited without false-promise of "we know what's latest".
pub const NO_REGISTRY_RESOLVER_MSG: &str =
    "no upstream registry yet — U-02b will resolve latest_version via the registry concept";

/// Compose installed skills + plugins into a single
/// `skill_plugin_specs` list.
///
/// U-02b (Session 26) updated this from the original "always
/// `Err(NO_REGISTRY_RESOLVER_MSG)`" stub: skills that declare a
/// `source: git+https://…` field in their manifest now go through
/// [`crate::updater::skill_resolver::resolve_latest_version`] —
/// `git ls-remote --tags <url>` + highest-semver pick. Skills WITHOUT
/// a source declaration still surface the sentinel so the cron audit
/// chain captures "operator hasn't opted into auto-update probes yet"
/// distinctly from a real resolver failure.
///
/// Plugins (`~/.neoth/plugins/<id>/plugin.toml`) keep the sentinel
/// pending a matching `source` field addition to PluginManifest —
/// scoped as a follow-up so this commit stays focused on the skill
/// path Alex picked option 1 for.
pub async fn skill_plugin_specs_for_home_async(
    home: std::path::PathBuf,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    let mut installed: Vec<(String, String, Result<String, String>, GateDecision)> = Vec::new();
    let skill_rows = scan_installed_skills_rows(&home);
    for row in skill_rows {
        let latest = match row.source.as_deref() {
            Some(source) => crate::updater::skill_resolver::resolve_latest_version(source).await,
            None => Err(NO_REGISTRY_RESOLVER_MSG.to_string()),
        };
        installed.push((row.name, row.version, latest, gate.clone()));
    }
    for (name, version) in scan_installed_plugins(&home) {
        installed.push((
            name,
            version,
            Err(NO_REGISTRY_RESOLVER_MSG.to_string()),
            gate.clone(),
        ));
    }
    crate::updater::pipeline::skill_plugin_specs(installed)
}

/// Sync wrapper kept for callers that don't have a tokio runtime
/// handy. Every source-declaring skill yields the sentinel error
/// because the resolver requires async. Callers in async contexts
/// MUST switch to [`skill_plugin_specs_for_home_async`].
pub fn skill_plugin_specs_for_home(
    home: &std::path::Path,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    let mut installed: Vec<(String, String, Result<String, String>, GateDecision)> = Vec::new();
    for row in scan_installed_skills_rows(home) {
        installed.push((
            row.name,
            row.version,
            Err(NO_REGISTRY_RESOLVER_MSG.to_string()),
            gate.clone(),
        ));
    }
    for (name, version) in scan_installed_plugins(home) {
        installed.push((
            name,
            version,
            Err(NO_REGISTRY_RESOLVER_MSG.to_string()),
            gate.clone(),
        ));
    }
    crate::updater::pipeline::skill_plugin_specs(installed)
}

/// Sync builder for the U-04 cron-builder closure. The home path
/// is captured by value so each tick re-reads disk (operator-
/// added skills between ticks become visible without a daemon
/// restart).
///
/// U-02b: when invoked from the cron's `spawn_blocking` context the
/// builder hands control to `skill_plugin_specs_for_home_async` via
/// `Handle::try_current().block_on()` so source-declaring skills
/// reach the git ls-remote resolver. Outside a tokio runtime the
/// sync fallback emits the sentinel error for every skill — same
/// shape the cron-audit chain saw before U-02b.
pub fn skill_plugin_specs_blocking(
    home: std::path::PathBuf,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(skill_plugin_specs_for_home_async(home, gate)),
        Err(_) => skill_plugin_specs_for_home(&home, gate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updater::pipeline::GateDecision;

    #[tokio::test]
    async fn neoth_self_probe_returns_single_spec_with_current_version() {
        // Network call goes out; the assertion only pins the
        // spec shape, not the upstream response. A network
        // failure surfaces as `latest_version: Err(...)` —
        // still a valid single-spec list.
        let specs = neoth_self_specs_async(GateDecision::Allow).await;
        assert_eq!(specs.len(), 1, "neoth_self probe yields exactly one spec");
        assert_eq!(specs[0].name, "neothd");
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
    fn scan_skills_skips_dirs_without_skill_yaml() {
        let home = tempfile::tempdir().unwrap();
        let skills = home.path().join("skills");
        std::fs::create_dir_all(skills.join("orphan")).unwrap();
        // No skill.yaml file present.
        assert!(scan_installed_skills(home.path()).is_empty());
    }

    #[test]
    fn scan_plugins_returns_empty_when_dir_missing() {
        let home = tempfile::tempdir().unwrap();
        assert!(scan_installed_plugins(home.path()).is_empty());
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
        let specs = skill_plugin_specs_for_home(home.path(), GateDecision::Allow);
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
        let specs =
            skill_plugin_specs_for_home_async(home.path().to_path_buf(), GateDecision::Allow).await;
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
    async fn async_specs_attempts_resolver_for_skills_with_source() {
        // RFC2606 `.invalid` host guarantees `git ls-remote` fails →
        // resolver returns an Err containing "ls-remote" or "spawn".
        // The point is to prove the resolver path FIRED, not to assert
        // a specific upstream response.
        let home = tempfile::tempdir().unwrap();
        let skills = home.path().join("skills");
        std::fs::create_dir_all(skills.join("with-src")).unwrap();
        std::fs::write(
            skills.join("with-src").join("skill.yaml"),
            "id: with-src\n\
             description: U-02b live-resolver wiring\n\
             version: 1.0.0\n\
             source: git+https://nonexistent-host.invalid/owner/repo\n",
        )
        .unwrap();
        let specs =
            skill_plugin_specs_for_home_async(home.path().to_path_buf(), GateDecision::Allow).await;
        assert_eq!(specs.len(), 1);
        match &specs[0].latest_version {
            Err(msg) => {
                assert!(
                    !msg.contains("no upstream registry"),
                    "source-declaring skill must NOT surface the sentinel — \
                     resolver must have been called"
                );
            }
            Ok(_) => panic!("unreachable host must surface as Err"),
        }
    }
}
