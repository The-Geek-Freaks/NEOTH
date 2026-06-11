//! `~/.neoth/mcp_servers.yaml` — operator's MCP server configuration.
//!
//! ```yaml
//! servers:
//!   - id: filesystem
//!     command: npx
//!     args: ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/notes"]
//!     env:
//!       LOG_LEVEL: info
//!
//!   - id: github
//!     command: npx
//!     args: ["-y", "@modelcontextprotocol/server-github"]
//!     env:
//!       GITHUB_PERSONAL_ACCESS_TOKEN: from_env  # operator-controlled
//! ```
//!
//! `env: from_env` is a sentinel meaning "read this value from the
//! NEOTH-process environment at spawn time". Plain values pass through.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
}

fn default_enabled() -> bool {
    true
}

/// Top-level container — supports the operator-friendly `servers:` key.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct McpServers {
    #[serde(default)]
    pub servers: Vec<McpServerConfig>,
}

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
        };
        let err = cfg.resolve_env().unwrap_err();
        assert!(
            err.to_string()
                .contains("NEOTH_TEST_DEFINITELY_MISSING_VAR")
        );
    }

    // --- A8 autoroute_decision tests ---

    fn one_enabled_server() -> McpServers {
        McpServers {
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
}
