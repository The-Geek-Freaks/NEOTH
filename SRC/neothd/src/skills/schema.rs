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
    /// QM-3 (2026-05-22) MODE_REGISTRY pattern. Optional list of named
    /// modes a skill ships — each carries its own system-prompt delta,
    /// spectrum, oversight level, and trigger phrases. Backward-compat:
    /// skills without `modes:` behave exactly as before (single
    /// keyword-based activation). When present, the registry-lookup
    /// path activates: operator says "fact-check these claims" →
    /// `mode:fact-check` hits before the broader skill match.
    #[serde(default)]
    pub modes: Vec<ModeEntry>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// QM-3 mode-spectrum enum. Controls how template-heavy the output
/// is — fidelity = strict template adherence, balanced = mix,
/// originality = synthesis priority. ARS source: `mode_spectrum.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Spectrum {
    Fidelity,
    Balanced,
    Originality,
}

impl Spectrum {
    pub fn as_str(self) -> &'static str {
        match self {
            Spectrum::Fidelity => "fidelity",
            Spectrum::Balanced => "balanced",
            Spectrum::Originality => "originality",
        }
    }
}

/// QM-3 oversight enum. Drives how much operator confirmation a
/// mode demands — Low = autonomous, VeryHigh = step-by-step confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Oversight {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl Oversight {
    pub fn as_str(self) -> &'static str {
        match self {
            Oversight::Low => "low",
            Oversight::Medium => "medium",
            Oversight::High => "high",
            Oversight::VeryHigh => "very_high",
        }
    }
}

/// QM-3 output contract. Operator-readable format + length hint so
/// the mode's renderer knows what shape to produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputContract {
    /// `markdown` / `json` / `prose` / `table` / `bullets` / ...
    pub format: String,
    /// Free-form length hint: `short`, `medium`, `long`,
    /// `~500-words`, `<= 3 paragraphs`. The renderer interprets.
    #[serde(default)]
    pub length_hint: Option<String>,
}

/// QM-3 mode entry — one named mode inside a skill.
///
/// Skills can ship 1..N modes. The registry-flatten step collects
/// them into a process-wide [`crate::skills::mode_registry::ModeRegistry`]
/// at boot so operator commands like `/mode fact-check` route in
/// O(1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeEntry {
    /// Stable mode id (kebab-case). Unique within a skill; the
    /// registry-flatten asserts uniqueness across the whole set so
    /// two skills can't claim the same mode name.
    pub id: String,
    /// Operator-readable one-liner shown in `neoth mode list`.
    pub description: String,
    /// Spectrum classification.
    pub spectrum: Spectrum,
    /// Oversight level the mode demands.
    pub oversight: Oversight,
    /// Output shape contract.
    pub output: OutputContract,
    /// Trigger phrases that activate the mode. Mirrors the skill's
    /// trigger_keywords but at mode granularity — "do a lit-review"
    /// activates `mode:lit-review` even though the parent skill's
    /// keywords might be broader.
    #[serde(default)]
    pub trigger_phrases: Vec<String>,
    /// Optional system-prompt delta the mode prepends ABOVE the
    /// skill's base system_prompt. Mode-specific instructions.
    #[serde(default)]
    pub system_prompt_delta: String,
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
        assert!(m.modes.is_empty(), "QM-3 modes defaults to empty");
        assert!(m.enabled, "enabled defaults to true");
    }

    // ── QM-3 mode registry shape tests ───────────────────────────────────

    #[test]
    fn qm_3_manifest_with_modes_round_trips() {
        let yaml = r#"
id: deep-research
description: research skill with named modes
version: "0.1.0"
trigger_keywords: ["research"]
system_prompt: "base prompt"
modes:
  - id: lit-review
    description: Annotated bibliography output
    spectrum: balanced
    oversight: high
    output:
      format: markdown
      length_hint: "~500-1000 words"
    trigger_phrases: ["lit review", "literature review"]
    system_prompt_delta: "Focus on citation density."
  - id: fact-check
    description: Per-claim verification pass
    spectrum: fidelity
    oversight: very_high
    output:
      format: json
    trigger_phrases: ["fact-check", "verify these claims"]
"#;
        let m: SkillManifest = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(m.modes.len(), 2);
        let lit = &m.modes[0];
        assert_eq!(lit.id, "lit-review");
        assert_eq!(lit.spectrum, Spectrum::Balanced);
        assert_eq!(lit.oversight, Oversight::High);
        assert_eq!(lit.output.format, "markdown");
        assert_eq!(lit.output.length_hint.as_deref(), Some("~500-1000 words"));
        assert_eq!(lit.trigger_phrases.len(), 2);
        let fc = &m.modes[1];
        assert_eq!(fc.spectrum, Spectrum::Fidelity);
        assert_eq!(fc.oversight, Oversight::VeryHigh);
        // Length hint omitted in YAML → None.
        assert!(fc.output.length_hint.is_none());
    }

    #[test]
    fn qm_3_spectrum_round_trips_serde() {
        for s in [
            Spectrum::Fidelity,
            Spectrum::Balanced,
            Spectrum::Originality,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: Spectrum = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
            assert_eq!(s.as_str(), json.trim_matches('"'));
        }
    }

    #[test]
    fn qm_3_oversight_round_trips_serde() {
        for o in [
            Oversight::Low,
            Oversight::Medium,
            Oversight::High,
            Oversight::VeryHigh,
        ] {
            let json = serde_json::to_string(&o).unwrap();
            let back: Oversight = serde_json::from_str(&json).unwrap();
            assert_eq!(o, back);
            assert_eq!(o.as_str(), json.trim_matches('"'));
        }
    }

    #[test]
    fn qm_3_oversight_very_high_serializes_with_snake_case_underscore() {
        // Pin the wire shape — VeryHigh becomes "very_high", not
        // "veryhigh" or "very-high".
        let s = serde_json::to_string(&Oversight::VeryHigh).unwrap();
        assert_eq!(s, "\"very_high\"");
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
            modes: vec![],
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
