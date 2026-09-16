//! Read-only readiness inspection for the optional codegraph outline sidecar.
//!
//! This is deliberately diagnostic data only. It never launches MCP, invokes a
//! provider tool, rebuilds a map, or mutates the configured NEOTH home.

use std::path::Path;

/// Result of inspecting whether a future, separately-authorized outline
/// enrichment attempt could use the current home-scoped configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrichmentReadiness {
    Disabled { detail: String },
    Ready { detail: String },
    Unavailable { detail: String },
}

/// Inspects the configured outline-enrichment prerequisites for `home`.
///
/// `home` is explicit so callers cannot accidentally substitute a selected
/// repository root for the NEOTH instance whose config and managed-root store
/// are being described.
pub fn inspect(home: &Path) -> EnrichmentReadiness {
    let expected = std::env::current_exe().ok();
    inspect_for_expected_executable(home, expected.as_deref())
}

/// Same read-only readiness inspection using an explicitly resolved local
/// executable for generated-registration identity. GUI diagnostics pass their
/// existing CLI resolver result here; runtime admission remains separate.
pub fn inspect_for_expected_executable(
    home: &Path,
    expected_executable: Option<&Path>,
) -> EnrichmentReadiness {
    let config_path = home.join("freedom.yaml");
    let config = match std::fs::read(&config_path) {
        Ok(bytes) => match serde_yaml::from_slice::<crate::config::FreedomConfig>(&bytes) {
            Ok(config) if config.code_map.validate().is_ok() => config,
            _ => return unavailable("outline enrichment configuration is unavailable or invalid; Doctor did not inspect MCP registration or SQLite"),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => crate::config::FreedomConfig::default(),
        Err(_) => return unavailable("outline enrichment configuration is unavailable or invalid; Doctor did not inspect MCP registration or SQLite"),
    };
    if !config.code_map.outline_enrichment {
        return disabled("disabled by freedom.yaml — no outline enrichment readiness is expected and no SQLite database was opened");
    }
    let registry_path = home.join("mcp_servers.yaml");
    let servers = match crate::mcp::McpServers::load_from(&registry_path) {
        Ok(servers) => servers,
        Err(_) => return unavailable("enabled, but mcp_servers.yaml is unavailable or invalid; no child, provider, or SQLite inspection was attempted"),
    };
    let registration = expected_executable.map_or(
        crate::mcp::codegraph_server::BuiltinOutlineRegistrationReadiness::NotExactGenerated,
        |expected| crate::mcp::codegraph_server::inspect_builtin_outline_registration_for_expected_executable(
            servers.get_enabled("neoth-codegraph"),
            expected,
        ),
    );
    let database_path = match registration {
        crate::mcp::codegraph_server::BuiltinOutlineRegistrationReadiness::Exact { database_path } => database_path,
        crate::mcp::codegraph_server::BuiltinOutlineRegistrationReadiness::DatabaseUnavailable => return unavailable("enabled, but the exact generated codegraph registration names an absent or inaccessible database; Doctor did not create, migrate, or repair it"),
        crate::mcp::codegraph_server::BuiltinOutlineRegistrationReadiness::NotExactGenerated => return unavailable("enabled, but no exact generated neoth-codegraph registration is eligible; custom or lookalike registrations are not used for outline enrichment"),
    };
    let lifecycle = &config.code_map.lifecycle;
    if !lifecycle.enabled || lifecycle.managed_roots.is_empty() {
        return unavailable("enabled with no managed code-map roots; Doctor cannot establish a fresh complete outline snapshot");
    }

    let mut ready_roots = Vec::new();
    let mut unavailable_roots = Vec::new();
    // Configuration limits this list to eight roots. `inspect` is read-only.
    for root in &lifecycle.managed_roots {
        let observed = crate::code_map::lifecycle::inspect(&database_path, root);
        match (&observed.root, &observed.state) {
            (
                Some(physical_root),
                crate::code_map::lifecycle::CodeMapLifecycleState::Fresh { snapshot },
            ) if snapshot.index_generation > 0
                && snapshot.index_generation == snapshot.graph_generation =>
            {
                ready_roots.push(format!(
                    "{} (index_generation={}, graph_generation={})",
                    physical_root, snapshot.index_generation, snapshot.graph_generation
                ));
            }
            (Some(physical_root), state) => unavailable_roots.push(format!(
                "{}: {}",
                physical_root,
                lifecycle_state_label(state)
            )),
            (None, state) => unavailable_roots.push(format!(
                "{}: {}",
                root.display(),
                lifecycle_state_label(state)
            )),
        }
    }
    if ready_roots.is_empty() {
        return unavailable(&format!(
            "enabled exact generated registration found, but no fresh complete managed map is ready ({}) ; Doctor did not rebuild, refresh, or enrich a request",
            unavailable_roots.join(", ")
        ));
    }
    let suffix = if !unavailable_roots.is_empty() {
        format!("; other managed roots unavailable: {}", unavailable_roots.join(", "))
    } else {
        String::new()
    };
    let selection = if config.code_map.enrichment_selectors.is_empty() {
        "the existing built-in neoth-codegraph/codegraph_outline route".to_owned()
    } else {
        format!(
            "the built-in route and {} exact configured ReadPath selector(s)",
            config.code_map.enrichment_selectors.len(),
        )
    };
    ready(&format!(
        "ready for a next eligible attempt through {} across {} fresh complete managed root(s): {}{}; Doctor did not enrich a request",
        selection,
        ready_roots.len(),
        ready_roots.join(", "),
        suffix
    ))
}

fn ready(detail: &str) -> EnrichmentReadiness {
    EnrichmentReadiness::Ready { detail: detail.to_owned() }
}

fn disabled(detail: &str) -> EnrichmentReadiness {
    EnrichmentReadiness::Disabled { detail: detail.to_owned() }
}

fn unavailable(detail: &str) -> EnrichmentReadiness {
    EnrichmentReadiness::Unavailable { detail: detail.to_owned() }
}

fn lifecycle_state_label(state: &crate::code_map::lifecycle::CodeMapLifecycleState) -> &'static str {
    match state {
        crate::code_map::lifecycle::CodeMapLifecycleState::Disabled => "disabled",
        crate::code_map::lifecycle::CodeMapLifecycleState::Absent => "absent",
        crate::code_map::lifecycle::CodeMapLifecycleState::Unmapped => "unmapped",
        crate::code_map::lifecycle::CodeMapLifecycleState::Incomplete { .. } => "incomplete",
        crate::code_map::lifecycle::CodeMapLifecycleState::Fresh { .. } => "fresh",
        crate::code_map::lifecycle::CodeMapLifecycleState::Stale { .. } => "stale",
        crate::code_map::lifecycle::CodeMapLifecycleState::Refreshing { .. } => "refreshing",
        crate::code_map::lifecycle::CodeMapLifecycleState::Recovering { .. } => "recovering",
        crate::code_map::lifecycle::CodeMapLifecycleState::Corrupt { .. } => "corrupt",
    }
}

#[cfg(test)]
mod tests {
    use super::{EnrichmentReadiness, inspect};

    #[test]
    fn w100_missing_config_keeps_the_doctor_disabled_wording_without_opening_sqlite() {
        let home = tempfile::TempDir::new().expect("temporary NEOTH home");
        let result = inspect(home.path());

        assert_eq!(
            result,
            EnrichmentReadiness::Disabled {
                detail: "disabled by freedom.yaml — no outline enrichment readiness is expected and no SQLite database was opened".into(),
            }
        );
        assert!(
            !home.path().join("code_map.db").exists(),
            "the readiness inspection must not create a code-map database"
        );
    }

    #[test]
    fn w100_invalid_config_stops_before_mcp_or_sqlite_inspection() {
        let home = tempfile::TempDir::new().expect("temporary NEOTH home");
        std::fs::write(home.path().join("freedom.yaml"), "code_map: [").expect("write invalid config");

        let result = inspect(home.path());

        assert_eq!(
            result,
            EnrichmentReadiness::Unavailable {
                detail: "outline enrichment configuration is unavailable or invalid; Doctor did not inspect MCP registration or SQLite".into(),
            }
        );
        assert!(
            !home.path().join("code_map.db").exists(),
            "invalid configuration must not cause a database open or repair"
        );
    }
}
