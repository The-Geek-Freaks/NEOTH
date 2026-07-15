//! GOLD-ADAPT-CCS-01 — consent-gated hex-graph MCP registration.
//!
//! The package is not installed globally. The registered launcher uses an
//! exact top-level npm pin and the central MCP spawn validator enforces that
//! pin on every consumer path. npx may fetch the package on first use; npm's
//! transitive dependency graph remains an upstream trust boundary.

use std::path::Path;

use anyhow::Result;

use crate::mcp::config::{HEX_GRAPH_MIN_NODE_VERSION, McpServers, hex_graph_recommended_config};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    Registered,
    MissingNode,
    NodeTooOld { found: String },
    MissingNpx,
}

/// Verify Node >= 20.19.0 and npx, then atomically upsert the canonical,
/// enabled hex-graph entry.
pub async fn auto_register(neoth_home: &Path) -> Result<RegisterOutcome> {
    let Some(node_version) = crate::installers::probe::cli_version("node").await else {
        return Ok(RegisterOutcome::MissingNode);
    };
    let Some(parsed) = parse_node_version(&node_version) else {
        return Ok(RegisterOutcome::NodeTooOld {
            found: node_version,
        });
    };
    if parsed < HEX_GRAPH_MIN_NODE_VERSION {
        return Ok(RegisterOutcome::NodeTooOld {
            found: node_version,
        });
    }
    if crate::installers::probe::cli_version("npx").await.is_none() {
        return Ok(RegisterOutcome::MissingNpx);
    }

    register_at(neoth_home)?;
    Ok(RegisterOutcome::Registered)
}

fn register_at(neoth_home: &Path) -> Result<()> {
    let mcp_path = neoth_home.join("mcp_servers.yaml");
    McpServers::update_at(&mcp_path, |servers| {
        let mut config = hex_graph_recommended_config();
        config.enabled = true;
        config.validate_launcher()?;
        if let Some(existing) = servers
            .servers
            .iter_mut()
            .find(|server| server.id == config.id)
        {
            *existing = config;
        } else {
            servers.servers.push(config);
        }
        Ok(true)
    })
}

fn parse_node_version(raw: &str) -> Option<(u64, u64, u64)> {
    let core = raw
        .trim()
        .strip_prefix('v')
        .unwrap_or(raw.trim())
        .split_once('-')
        .map_or(raw.trim().trim_start_matches('v'), |(core, _)| core);
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::config::{HEX_GRAPH_NPM_SPEC, McpLauncherPosture, McpServerConfig};

    #[test]
    fn parses_node_versions_and_enforces_minimum() {
        assert_eq!(parse_node_version("v20.19.0"), Some((20, 19, 0)));
        assert_eq!(parse_node_version("22.14.0"), Some((22, 14, 0)));
        assert_eq!(parse_node_version("v20.19.1-nightly"), Some((20, 19, 1)));
        assert_eq!(parse_node_version("not-a-version"), None);
        assert!((20, 18, 9) < HEX_GRAPH_MIN_NODE_VERSION);
    }

    #[test]
    fn register_writes_enabled_exact_pin_and_complete_safe_surface() {
        let dir = tempfile::tempdir().unwrap();
        register_at(dir.path()).unwrap();

        let servers = McpServers::load_from(&dir.path().join("mcp_servers.yaml")).unwrap();
        let server = servers.get_enabled("hex-graph").unwrap();
        assert_eq!(
            server.args,
            vec!["-y".to_string(), HEX_GRAPH_NPM_SPEC.to_string()]
        );
        assert_eq!(
            server.validate_launcher().unwrap(),
            McpLauncherPosture::PinnedNpx
        );
        let tools = server.allow_tools.as_ref().unwrap();
        assert_eq!(tools.len(), 13);
        for required in [
            "index_project",
            "find_symbols",
            "find_references",
            "analyze_changes",
            "api_impact",
            "analyze_architecture",
        ] {
            assert!(tools.iter().any(|tool| tool == required));
        }
    }

    #[test]
    fn register_is_idempotent_and_refreshes_an_old_unpinned_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_servers.yaml");
        let existing = McpServers {
            smart_loading: true,
            servers: vec![McpServerConfig {
                id: "hex-graph".into(),
                description: None,
                command: "npx".into(),
                args: vec!["-y".into(), "@levnikolaevich/hex-graph-mcp".into()],
                env: Default::default(),
                enabled: false,
                allow_tools: None,
                trust_all_tools: true,
                smart_approve: true,
                autonomy_gate: None,
            }],
        };
        std::fs::write(&path, serde_yaml::to_string(&existing).unwrap()).unwrap();

        register_at(dir.path()).unwrap();
        register_at(dir.path()).unwrap();
        let servers = McpServers::load_from(&path).unwrap();
        assert_eq!(servers.servers.len(), 1);
        let server = &servers.servers[0];
        assert!(server.enabled);
        assert_eq!(
            server.args,
            vec!["-y".to_string(), HEX_GRAPH_NPM_SPEC.to_string()]
        );
        assert!(!server.trust_all_tools);
        assert!(!server.smart_approve);
    }

    #[test]
    fn register_preserves_other_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_servers.yaml");
        let existing = McpServers {
            smart_loading: false,
            servers: vec![McpServerConfig {
                id: "local".into(),
                description: None,
                command: "local-mcp".into(),
                args: vec![],
                env: Default::default(),
                enabled: true,
                allow_tools: Some(vec!["read".into()]),
                trust_all_tools: false,
                smart_approve: false,
                autonomy_gate: None,
            }],
        };
        std::fs::write(&path, serde_yaml::to_string(&existing).unwrap()).unwrap();

        register_at(dir.path()).unwrap();
        let servers = McpServers::load_from(&path).unwrap();
        assert!(!servers.smart_loading);
        assert_eq!(servers.servers.len(), 2);
        assert!(servers.servers.iter().any(|server| server.id == "local"));
    }

    #[test]
    fn corrupt_registry_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_servers.yaml");
        let corrupt = b"servers: [unterminated\n";
        std::fs::write(&path, corrupt).unwrap();

        assert!(register_at(dir.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    }
}
