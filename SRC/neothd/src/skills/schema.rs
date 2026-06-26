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
    /// U-02b (Session 26): upstream source URI the updater probes for
    /// the latest published version. `git+https://github.com/<owner>/
    /// <repo>` is the only scheme supported today — the resolver
    /// shells out to `git ls-remote --tags <url>` and picks the
    /// highest-sorting semver tag. `None` opts the skill out of
    /// auto-update probes (operator manually pulls + replaces).
    /// Future schemes (`registry+https://skills.neoth.dev/v1/<id>`)
    /// land in a follow-up commit when a community registry exists.
    #[serde(default)]
    pub source: Option<String>,
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
    /// GOLD-ADAPT-OH-13 — optional sub-agent delegation. When set, the skill
    /// router automatically synthesises a `Dispatch` for the named agent
    /// (looked up by `name` in the loaded agent list) and routes the turn
    /// through the standard omit-flag enrichment path instead of injecting
    /// the skill's own `system_prompt` as a layer. The skill's payload
    /// reaches the agent as `d.prompt`; the `skill_layer` is cleared before
    /// the enrichment rebuild to prevent double-injection.
    #[serde(default)]
    pub delegate_to: Option<String>,
    /// GOLD-CCPARITY-MODEL-02 — per-skill model override. When set, any turn
    /// that activates this skill routes through the named model instead of
    /// the operator's default `args.model`. Priority chain (highest first):
    ///   Dispatch.model (agent) > skill.manifest.model > args.model
    /// Accepts any model id string the active provider understands
    /// (e.g. `"claude-haiku-4-5"`, `"gpt-4o-mini"`). `None` = use default.
    #[serde(default)]
    pub model: Option<String>,
    /// GOLD-CCPARITY-PATHS-01 — file-path gating. When non-empty, the skill
    /// auto-activates ONLY when at least one of the operator's active files
    /// matches one of these gitignore-style glob patterns (e.g. `"**/*.rs"`,
    /// `"src/**"`). Empty list = always activate (backward-compat default).
    /// The router reads the operator's active files from the
    /// `NEOTH_ACTIVE_FILES` environment variable (`:` on Unix, `;` on
    /// Windows). When unset, all path-gated skills activate normally.
    #[serde(default)]
    pub paths: Vec<String>,
    /// GOLD-CCPARITY-EFFORT-03 — per-skill reasoning-budget override.
    /// When set, any turn that activates this skill overrides
    /// `MAX_THINKING_TOKENS` to the corresponding token count before the
    /// provider spawn, making the model spend more (or less) thinking budget
    /// on this skill's domain. `None` = use the provider default (10 000).
    ///
    /// Valid YAML values: `low` (1 024), `medium` (4 096),
    /// `high` (16 384), `max` (32 000).
    ///
    /// Example `skill.yaml`:
    /// ```yaml
    /// effort: high
    /// ```
    #[serde(default)]
    pub effort: Option<crate::providers::effort_override::EffortBudget>,
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
    /// Round-3 v0.4 ARCH-07 — `SHA-256(yaml || system_prompt)` 64-char
    /// hex computed at load time by `skills::loader::load_all`. A
    /// reviewer can recompute this against the on-disk file to verify
    /// "the skill that injected at turn T was definitely the file
    /// the audit log claims". Default empty for back-compat with
    /// callers constructing Skill manually (e.g. tests); loader-built
    /// instances always populate it.
    #[serde(default)]
    pub content_hash: String,
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

    /// U-02b — operator-declared upstream source for the updater
    /// resolver. `None` opts the skill out of auto-update probes.
    pub fn source(&self) -> Option<&str> {
        self.manifest.source.as_deref()
    }

    /// GOLD-CCPARITY-MODEL-02 — per-skill model override, or `None` when
    /// the skill defers to the operator's default provider model.
    pub fn model(&self) -> Option<&str> {
        self.manifest.model.as_deref()
    }

    /// GOLD-CCPARITY-PATHS-01 — path-glob gate patterns for this skill.
    /// Empty slice means the skill is always eligible (no path gate).
    pub fn paths(&self) -> &[String] {
        &self.manifest.paths
    }

    /// GOLD-CCPARITY-EFFORT-03 — per-skill reasoning-budget from the
    /// skill manifest. `None` means the provider default applies.
    pub fn effort(&self) -> Option<crate::providers::effort_override::EffortBudget> {
        self.manifest.effort
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
author: "sam"
tags: ["news", "daily"]
homepage: "https://example.com/morning-news"
"#;
        let m: SkillManifest = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(m.author.as_deref(), Some("sam"));
        assert_eq!(m.tags, vec!["news".to_string(), "daily".to_string()]);
        assert_eq!(
            m.homepage.as_deref(),
            Some("https://example.com/morning-news"),
        );
    }

    /// GOLD-ADAPT-OH-13 — `delegate_to` parses from YAML and defaults to None.
    #[test]
    fn delegate_to_field_parses_and_defaults() {
        let with_delegate = r#"
id: plan-and-run
description: delegate skill
trigger_keywords: ["plan this"]
system_prompt: "unused when delegating"
delegate_to: planner
"#;
        let m: SkillManifest = serde_yaml::from_str(with_delegate).expect("parse");
        assert_eq!(m.delegate_to.as_deref(), Some("planner"));

        let without_delegate = r#"
id: plain-skill
description: no delegation
trigger_keywords: ["hello"]
system_prompt: "do stuff"
"#;
        let m2: SkillManifest = serde_yaml::from_str(without_delegate).expect("parse");
        assert!(m2.delegate_to.is_none(), "delegate_to defaults to None");
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
            author: Some("sam".into()),
            tags: vec!["one".into(), "two".into()],
            homepage: Some("https://x".into()),
            source: None,
            modes: vec![],
            enabled: true,
            delegate_to: None,
            model: None,
            paths: vec![],
            effort: None,
        };
        let s = Skill {
            manifest,
            path: PathBuf::from("/tmp/x"),
            content_hash: String::new(),
        };
        assert_eq!(s.author(), Some("sam"));
        assert_eq!(s.tags(), &["one".to_string(), "two".to_string()]);
        assert_eq!(s.homepage(), Some("https://x"));
        assert!(s.is_enabled());
        assert!(s.model().is_none());
    }

    // ── GOLD-CCPARITY-MODEL-02 model field tests ──────────────────────────

    #[test]
    fn model_field_parses_from_yaml() {
        let yaml = r#"
id: fast-skill
description: uses haiku
trigger_keywords: ["quick"]
system_prompt: "be fast"
model: claude-haiku-4-5
"#;
        let m: SkillManifest = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(m.model.as_deref(), Some("claude-haiku-4-5"));
    }

    #[test]
    fn model_field_defaults_to_none_when_absent() {
        let yaml = r#"
id: default-skill
description: no model override
trigger_keywords: ["default"]
system_prompt: "use default model"
"#;
        let m: SkillManifest = serde_yaml::from_str(yaml).expect("parse");
        assert!(m.model.is_none(), "model field should default to None");
    }

    // ── GOLD-CCPARITY-PATHS-01 schema tests ──────────────────────────────────

    #[test]
    fn paths_field_parses_from_yaml() {
        let yaml = r#"
id: rust-skill
description: Rust coding assistant
trigger_keywords: ["refactor"]
system_prompt: "be rusty"
paths:
  - "**/*.rs"
  - "src/**"
"#;
        let m: SkillManifest = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(m.paths, vec!["**/*.rs".to_string(), "src/**".to_string()]);
    }

    #[test]
    fn paths_field_defaults_to_empty_when_absent() {
        let yaml = r#"
id: no-gate-skill
description: no path gate
trigger_keywords: ["hello"]
system_prompt: "do stuff"
"#;
        let m: SkillManifest = serde_yaml::from_str(yaml).expect("parse");
        assert!(m.paths.is_empty(), "paths must default to empty Vec");
    }

    #[test]
    fn skill_paths_accessor_proxies_manifest() {
        let manifest = SkillManifest {
            id: "p".into(),
            description: "d".into(),
            version: "1.0.0".into(),
            trigger_keywords: vec![],
            system_prompt: "p".into(),
            tool_allowlist: vec![],
            author: None,
            tags: vec![],
            homepage: None,
            source: None,
            modes: vec![],
            enabled: true,
            delegate_to: None,
            model: None,
            paths: vec!["**/*.rs".into()],
            effort: None,
        };
        let s = Skill {
            manifest,
            path: std::path::PathBuf::from("/tmp/p"),
            content_hash: String::new(),
        };
        assert_eq!(s.paths(), &["**/*.rs".to_string()]);
    }

    #[test]
    fn skill_model_accessor_proxies_manifest() {
        let manifest = SkillManifest {
            id: "m".into(),
            description: "d".into(),
            version: "1.0.0".into(),
            trigger_keywords: vec![],
            system_prompt: "p".into(),
            tool_allowlist: vec![],
            author: None,
            tags: vec![],
            homepage: None,
            source: None,
            modes: vec![],
            enabled: true,
            delegate_to: None,
            model: Some("claude-opus-4-7".into()),
            paths: vec![],
            effort: None,
        };
        let s = Skill {
            manifest,
            path: std::path::PathBuf::from("/tmp/m"),
            content_hash: String::new(),
        };
        assert_eq!(s.model(), Some("claude-opus-4-7"));
    }

    // ── GOLD-CCPARITY-EFFORT-03 schema tests ─────────────────────────────────

    #[test]
    fn effort_field_parses_high_from_yaml() {
        let yaml = r#"
id: deep-think
description: high reasoning skill
trigger_keywords: ["analyze"]
system_prompt: "think deeply"
effort: high
"#;
        let m: SkillManifest = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(
            m.effort,
            Some(crate::providers::effort_override::EffortBudget::High)
        );
    }

    #[test]
    fn effort_field_defaults_to_none_when_absent() {
        let yaml = r#"
id: quick-skill
description: no effort override
trigger_keywords: ["quick"]
system_prompt: "be quick"
"#;
        let m: SkillManifest = serde_yaml::from_str(yaml).expect("parse");
        assert!(m.effort.is_none(), "effort must default to None");
    }

    #[test]
    fn effort_accessor_proxies_manifest() {
        use crate::providers::effort_override::EffortBudget;
        let manifest = SkillManifest {
            id: "e".into(),
            description: "d".into(),
            version: "1.0.0".into(),
            trigger_keywords: vec![],
            system_prompt: "p".into(),
            tool_allowlist: vec![],
            author: None,
            tags: vec![],
            homepage: None,
            source: None,
            modes: vec![],
            enabled: true,
            delegate_to: None,
            model: None,
            paths: vec![],
            effort: Some(EffortBudget::Max),
        };
        let s = Skill {
            manifest,
            path: std::path::PathBuf::from("/tmp/e"),
            content_hash: String::new(),
        };
        assert_eq!(s.effort(), Some(EffortBudget::Max));
    }
}
