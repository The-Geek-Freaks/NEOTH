//! Skill manifest types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// On-disk YAML manifest. Parsed once at load time + validated.
///
/// Loaded from `~/.neoth/skills/<id>/skill.yaml`. The directory name is the
/// canonical skill id; the `id` field in YAML must match (loader enforces).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    pub id: String,
    pub description: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub trigger_keywords: Vec<String>,
    #[serde(default)]
    pub system_prompt: String,
    /// NEOTH-specific addition: restrict the tool surface this skill may
    /// call. Empty = no restriction. Names refer to the daemon's tool
    /// registry (claude-code-style — `recall`, `channel-send`, `fetch`, …).
    #[serde(default)]
    pub tool_allowlist: Vec<String>,
    /// Skill author for attribution in `neoth skills list`. Optional.
    /// Q-5 (QUELLEN adoption) — surfacing upstream tags/homepage so
    /// operator-shared skill libraries can carry provenance.
    #[serde(default)]
    pub author: Option<String>,
    /// Free-form tags for grouping in skill listings (`memory`, `email`, …).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Project homepage URL — appears in `neoth skills list` table output.
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_version() -> String {
    "1.0.0".to_string()
}
fn default_true() -> bool {
    true
}

/// Runtime view of a loaded skill — manifest + resolved on-disk path.
/// Distinct from `SkillManifest` because the router cares about provenance
/// (used in `neoth skills list` output and audit logs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub manifest: SkillManifest,
    pub path: PathBuf,
}

impl Skill {
    pub fn id(&self) -> &str {
        &self.manifest.id
    }

    pub fn description(&self) -> &str {
        &self.manifest.description
    }

    pub fn system_prompt(&self) -> &str {
        &self.manifest.system_prompt
    }

    pub fn trigger_keywords(&self) -> &[String] {
        &self.manifest.trigger_keywords
    }

    pub fn is_enabled(&self) -> bool {
        self.manifest.enabled
    }

    pub fn author(&self) -> Option<&str> {
        self.manifest.author.as_deref()
    }

    pub fn tags(&self) -> &[String] {
        &self.manifest.tags
    }

    pub fn homepage(&self) -> Option<&str> {
        self.manifest.homepage.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Old manifests (pre-Q-5) round-trip cleanly — the new fields default
    /// to None/empty.
    #[test]
    fn manifest_without_q5_fields_deserialises() {
        let yaml = r#"
id: old-skill
description: legacy manifest
version: "1.0.0"
trigger_keywords: ["x"]
system_prompt: "hi"
"#;
        let m: SkillManifest = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(m.id, "old-skill");
        assert!(m.author.is_none());
        assert!(m.tags.is_empty());
        assert!(m.homepage.is_none());
        assert!(m.enabled, "enabled defaults to true");
    }

    /// New manifests carry author + tags + homepage.
    #[test]
    fn manifest_with_q5_fields_round_trips() {
        let yaml = r#"
id: morning-news
description: daily-news skill
version: "0.1.0"
trigger_keywords: ["news", "headlines"]
system_prompt: "ok"
author: "alex"
tags: ["news", "daily"]
homepage: "https://example.com/morning-news"
"#;
        let m: SkillManifest = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(m.author.as_deref(), Some("alex"));
        assert_eq!(m.tags, vec!["news".to_string(), "daily".to_string()]);
        assert_eq!(
            m.homepage.as_deref(),
            Some("https://example.com/morning-news"),
        );
    }

    #[test]
    fn skill_helpers_proxy_to_manifest() {
        let manifest = SkillManifest {
            id: "x".into(),
            description: "d".into(),
            version: "1.0.0".into(),
            trigger_keywords: vec!["k".into()],
            system_prompt: "p".into(),
            tool_allowlist: vec![],
            author: Some("alex".into()),
            tags: vec!["one".into(), "two".into()],
            homepage: Some("https://x".into()),
            enabled: true,
        };
        let s = Skill {
            manifest,
            path: PathBuf::from("/tmp/x"),
        };
        assert_eq!(s.author(), Some("alex"));
        assert_eq!(s.tags(), &["one".to_string(), "two".to_string()]);
        assert_eq!(s.homepage(), Some("https://x"));
        assert!(s.is_enabled());
    }
}
