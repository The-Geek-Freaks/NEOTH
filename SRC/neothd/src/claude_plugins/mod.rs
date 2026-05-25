//! Q-01 (Session 24) — Anthropic claude-plugins-official `plugin.json`
//! schema parser.
//!
//! NEOTH's `wasm_plugin` module handles the WASM sandbox manifest
//! shipped in `plugin.toml`. THIS module handles the WIDER
//! Claude-Code-ecosystem `plugin.json` format that bundles slash
//! commands, sub-agent definitions, skills, MCP server configs, and
//! TOML hooks in a single discoverable plugin directory.
//!
//! The two coexist: a NEOTH-native WASM plugin is `plugin.toml` →
//! `wasm_plugin::manifest::PluginManifest`. A Claude Code plugin
//! imported from the public ecosystem (e.g. anthropics/claude-code
//! plugins repo) is `plugin.json` → [`ClaudePluginManifest`]. The
//! ingest pipeline picks the right parser based on the filename.
//!
//! ## On-disk shape (Anthropic convention)
//!
//! ```text
//! my-plugin/
//! ├── plugin.json
//! ├── commands/
//! │   └── greet.md           # slash command body
//! ├── agents/
//! │   └── reviewer.md         # sub-agent system prompt
//! ├── skills/
//! │   └── morning-news/
//! │       └── SKILL.md
//! ├── .mcp.json               # MCP server config
//! └── hooks.json              # PostToolUse / PreToolUse hooks
//! ```
//!
//! `plugin.json` itself only carries the metadata + relative paths to
//! the typed asset bundles. The actual content (slash command markdown,
//! agent system prompts, skill markdown) lives in the sibling files;
//! the manifest is just the routing table.
//!
//! ## Scope of this commit (Q-01)
//!
//! - Parse + validate the `plugin.json` shape.
//! - Surface a typed `ClaudePluginManifest` other modules can consume.
//! - Tests covering happy path + every reject-on-validation case.
//!
//! Discovery + registration (walk `~/.neoth/plugins-claude/*/plugin.json`
//! at boot, register commands/agents/skills with the live runtime) is
//! a follow-up. The parser primitive is what's blocking — without it
//! every downstream consumer would have to re-implement the JSON
//! shape and they'd drift.

use serde::{Deserialize, Serialize};

/// Parsed `plugin.json` from the Claude-Code plugins ecosystem.
/// Field defaults match the Anthropic-published schema so an absent
/// optional section round-trips cleanly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudePluginManifest {
    /// Plugin id. Must be snake-case-or-hyphen-case + non-empty.
    /// NOT a display name — that's `display_name` for plugins that
    /// want a separate human-readable label.
    pub name: String,
    /// Semver-shaped version string (`1.2.3` / `0.1.0-alpha.1` /
    /// `1.0.0+build.7`).
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub author: Option<Author>,
    /// Slash command markdown files. Relative paths from the plugin
    /// root. Each file is a slash command per the operator-facing
    /// `/<command>` convention.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Sub-agent system-prompt markdown files. Each registers as a
    /// `@<agent-name>` invocation target.
    #[serde(default)]
    pub agents: Vec<String>,
    /// Skill markdown files (typically `<skill-name>/SKILL.md`).
    /// Each becomes a Skill-tool entry the runtime can invoke.
    #[serde(default)]
    pub skills: Vec<String>,
    /// Path to the `.mcp.json` file that lists this plugin's MCP
    /// server configs. `None` when the plugin doesn't ship MCP
    /// servers.
    #[serde(default)]
    pub mcp_servers: Option<String>,
    /// Path to a hooks config (PostToolUse / PreToolUse etc.).
    #[serde(default)]
    pub hooks: Option<String>,
    /// Optional homepage URL for the operator's reference. Not
    /// validated — operators occasionally point at a private repo.
    #[serde(default)]
    pub homepage: Option<String>,
    /// Optional license SPDX identifier (`MIT`, `Apache-2.0`, …).
    /// Surfaced by `neoth plugins list` so operators see what they
    /// just installed.
    #[serde(default)]
    pub license: Option<String>,
}

/// Plugin author. Anthropic's schema allows either a bare string or
/// an object with name + email — we accept both via the untagged
/// enum but always materialise to the object form so downstream
/// callers don't branch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Author {
    /// Bare string form: `"author": "Alex"`.
    Name(String),
    /// Object form: `"author": {"name": "Alex", "email": "alex@x"}`.
    Object {
        name: String,
        #[serde(default)]
        email: Option<String>,
        #[serde(default)]
        url: Option<String>,
    },
}

impl Author {
    pub fn name(&self) -> &str {
        match self {
            Author::Name(s) => s,
            Author::Object { name, .. } => name,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("plugin name must be non-empty kebab-or-snake-case (got: {got:?})")]
    InvalidName { got: String },
    #[error("plugin version must be semver-shaped (got: {got:?})")]
    InvalidVersion { got: String },
    #[error("relative path `{got}` escapes plugin root (no `..` allowed)")]
    PathEscapesRoot { got: String },
    #[error("relative path `{got}` is absolute — must be relative to plugin root")]
    PathIsAbsolute { got: String },
    #[error("JSON parse error: {0}")]
    Parse(String),
}

/// Parse + validate `plugin.json` bytes.
pub fn parse_manifest(json_bytes: &[u8]) -> Result<ClaudePluginManifest, ManifestError> {
    let parsed: ClaudePluginManifest = serde_json::from_slice(json_bytes)
        .map_err(|e| ManifestError::Parse(e.to_string()))?;
    validate_manifest(&parsed)?;
    Ok(parsed)
}

/// Post-parse validation. Split out so callers that construct a
/// manifest programmatically (tests, future GUI editor) can validate
/// without round-tripping through JSON.
pub fn validate_manifest(m: &ClaudePluginManifest) -> Result<(), ManifestError> {
    if !is_valid_name(&m.name) {
        return Err(ManifestError::InvalidName {
            got: m.name.clone(),
        });
    }
    if !is_semver_shape(&m.version) {
        return Err(ManifestError::InvalidVersion {
            got: m.version.clone(),
        });
    }
    for path in m
        .commands
        .iter()
        .chain(m.agents.iter())
        .chain(m.skills.iter())
        .chain(m.mcp_servers.iter())
        .chain(m.hooks.iter())
    {
        validate_relative_path(path)?;
    }
    Ok(())
}

fn is_valid_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    // First char alphabetic; rest alphanumeric / `-` / `_`.
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn is_semver_shape(s: &str) -> bool {
    // Loose check — matches `MAJOR.MINOR.PATCH` with optional
    // `-pre` / `+build`. Pre-release + build segments accept the
    // standard `[0-9A-Za-z-.]+` band. No strict spec compliance
    // because operators occasionally ship `0.1.0-rc.1+sha.abc` and
    // a strict parser would reject perfectly cromulent versions.
    let core_and_rest = match s.split_once('+') {
        Some((core_pre, build)) => {
            if build.is_empty() || !build.chars().all(is_semver_extra_char) {
                return false;
            }
            core_pre
        }
        None => s,
    };
    let (core, pre) = match core_and_rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (core_and_rest, None),
    };
    if let Some(p) = pre {
        if p.is_empty() || !p.chars().all(is_semver_extra_char) {
            return false;
        }
    }
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn is_semver_extra_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-'
}

fn validate_relative_path(p: &str) -> Result<(), ManifestError> {
    if p.starts_with('/') || p.starts_with('\\') {
        return Err(ManifestError::PathIsAbsolute {
            got: p.to_string(),
        });
    }
    // Windows-style absolute (`C:\...` / `C:/...`).
    if p.len() >= 2 {
        let bytes = p.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(ManifestError::PathIsAbsolute {
                got: p.to_string(),
            });
        }
    }
    // No `..` segment — protect the plugin sandbox from path-traversal.
    for seg in p.split(|c| c == '/' || c == '\\') {
        if seg == ".." {
            return Err(ManifestError::PathEscapesRoot {
                got: p.to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str, version: &str) -> ClaudePluginManifest {
        ClaudePluginManifest {
            name: name.to_string(),
            version: version.to_string(),
            description: None,
            display_name: None,
            author: None,
            commands: Vec::new(),
            agents: Vec::new(),
            skills: Vec::new(),
            mcp_servers: None,
            hooks: None,
            homepage: None,
            license: None,
        }
    }

    #[test]
    fn parses_minimal_manifest_with_only_name_and_version() {
        let json = br#"{"name":"my-plugin","version":"1.0.0"}"#;
        let m = parse_manifest(json).unwrap();
        assert_eq!(m.name, "my-plugin");
        assert_eq!(m.version, "1.0.0");
        assert!(m.commands.is_empty());
        assert!(m.agents.is_empty());
        assert!(m.skills.is_empty());
    }

    #[test]
    fn parses_full_manifest_with_every_optional_field() {
        let json = br#"{
            "name": "neoth-plugin",
            "version": "0.2.1-rc.1+build.7",
            "description": "A plugin",
            "display_name": "NEOTH Plugin",
            "author": {"name": "Alex", "email": "a@x", "url": "https://x"},
            "commands": ["commands/greet.md"],
            "agents": ["agents/reviewer.md"],
            "skills": ["skills/morning-news/SKILL.md"],
            "mcp_servers": ".mcp.json",
            "hooks": "hooks.json",
            "homepage": "https://example.com",
            "license": "MIT"
        }"#;
        let m = parse_manifest(json).unwrap();
        assert_eq!(m.name, "neoth-plugin");
        assert_eq!(m.version, "0.2.1-rc.1+build.7");
        assert_eq!(m.description.as_deref(), Some("A plugin"));
        assert_eq!(m.display_name.as_deref(), Some("NEOTH Plugin"));
        assert_eq!(m.author.unwrap().name(), "Alex");
        assert_eq!(m.commands, vec!["commands/greet.md"]);
        assert_eq!(m.agents, vec!["agents/reviewer.md"]);
        assert_eq!(m.skills, vec!["skills/morning-news/SKILL.md"]);
        assert_eq!(m.mcp_servers.as_deref(), Some(".mcp.json"));
        assert_eq!(m.hooks.as_deref(), Some("hooks.json"));
        assert_eq!(m.license.as_deref(), Some("MIT"));
    }

    #[test]
    fn author_accepts_bare_string_form() {
        let json = br#"{"name":"x","version":"1.0.0","author":"Alex"}"#;
        let m = parse_manifest(json).unwrap();
        assert_eq!(m.author.as_ref().unwrap().name(), "Alex");
    }

    #[test]
    fn invalid_name_rejected() {
        for bad in &["", "1starts-with-digit", "has space", "ends-with-!", "..", "/"] {
            let json = format!(r#"{{"name":"{bad}","version":"1.0.0"}}"#);
            let r = parse_manifest(json.as_bytes());
            assert!(r.is_err(), "expected reject for name `{bad}`");
        }
    }

    #[test]
    fn valid_names_accepted() {
        for ok in &["a", "my-plugin", "snake_case", "Mixed-Case_123", "my-plugin-v2"] {
            let json = format!(r#"{{"name":"{ok}","version":"1.0.0"}}"#);
            let r = parse_manifest(json.as_bytes());
            assert!(r.is_ok(), "expected accept for name `{ok}`: {:?}", r.err());
        }
    }

    #[test]
    fn invalid_version_rejected() {
        for bad in &["", "1", "1.0", "1.0.x", "v1.0.0", "1.0.0-", "1.0.0+"] {
            let json = format!(r#"{{"name":"x","version":"{bad}"}}"#);
            let r = parse_manifest(json.as_bytes());
            assert!(r.is_err(), "expected reject for version `{bad}`");
        }
    }

    #[test]
    fn valid_versions_accepted() {
        for ok in &[
            "0.0.0",
            "1.0.0",
            "12.34.56",
            "1.0.0-alpha",
            "1.0.0-rc.1",
            "1.0.0+build.7",
            "1.0.0-rc.1+sha.abc",
        ] {
            let m = manifest("x", ok);
            assert!(
                validate_manifest(&m).is_ok(),
                "expected accept for version `{ok}`",
            );
        }
    }

    #[test]
    fn absolute_path_rejected_in_commands() {
        let json = br#"{"name":"x","version":"1.0.0","commands":["/etc/passwd"]}"#;
        let r = parse_manifest(json);
        assert!(matches!(r, Err(ManifestError::PathIsAbsolute { .. })));
    }

    #[test]
    fn windows_absolute_path_rejected() {
        let m = ClaudePluginManifest {
            commands: vec!["C:\\Windows\\System32\\config\\SAM".into()],
            ..manifest("x", "1.0.0")
        };
        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::PathIsAbsolute { .. }),
        ));
    }

    #[test]
    fn parent_traversal_in_path_rejected() {
        let m = ClaudePluginManifest {
            skills: vec!["../../../etc/passwd".into()],
            ..manifest("x", "1.0.0")
        };
        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::PathEscapesRoot { .. }),
        ));
    }

    #[test]
    fn parent_traversal_anywhere_in_path_rejected() {
        // Even mid-path `..` segments are dangerous (`skills/x/../../y`).
        let m = ClaudePluginManifest {
            agents: vec!["agents/x/../../escape.md".into()],
            ..manifest("x", "1.0.0")
        };
        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::PathEscapesRoot { .. }),
        ));
    }

    #[test]
    fn parse_error_surfaces_with_context() {
        let r = parse_manifest(b"not json");
        assert!(matches!(r, Err(ManifestError::Parse(_))));
    }

    #[test]
    fn name_over_64_chars_rejected() {
        let long = "a".repeat(65);
        let m = manifest(&long, "1.0.0");
        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidName { .. }),
        ));
    }
}
