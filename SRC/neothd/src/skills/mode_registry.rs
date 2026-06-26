//! QM-3 — MODE_REGISTRY. Flat process-wide lookup of every named
//! mode every loaded skill ships.
//!
//! Per `PLAN/QUELLEN_ADOPT_academic_2026-05-21.md` §2 "MODE_REGISTRY
//! Pattern — CORE NEOTH PRIMITIVE". The ARS academic-research-skills
//! repo's `MODE_REGISTRY.md` is a table-driven registry with one row
//! per mode carrying id / spectrum / oversight / output / triggers.
//! When an operator says "do a systematic review on X" the orchestrator
//! flips to that mode's agent composition + output contract + oversight
//! level in a single declarative lookup. NEOTH adopts the pattern as
//! a process-wide primitive shared by every skill.
//!
//! ## What ships in QM-3
//!
//! - `ModeRegistry::from_skills(&[Skill])` — flatten every skill's
//!   `modes:` list into one searchable table. Asserts no duplicate
//!   mode-id across the whole set (two skills can't claim the same
//!   mode name).
//! - `ModeRegistry::get(id)` — O(1) lookup by id.
//! - `ModeRegistry::match_trigger(prompt)` — finds the first mode
//!   whose `trigger_phrases` matches the operator's message. Mirrors
//!   the skill router's keyword-scan, one level deeper.
//! - `ModeRegistry::all()` / `iter()` — enumerate for `neoth mode
//!   list` rendering.
//! - `ResolvedMode` — bundles the matched mode + its parent skill id
//!   so callers can both inject the mode's prompt delta AND
//!   subsequently apply the skill's tool_allowlist.
//!
//! ## What's wiring (follow-up commits)
//!
//! - `/mode <id>` slash command — operator types `/mode fact-check`
//!   in chat, daemon writes `freedom.yaml::active_mode` and reloads.
//! - `neoth mode <id>` CLI — same path, CLI surface.
//! - Stage-1 keyword scan integration — `cli::chat::run_chat_with`
//!   calls `match_trigger` BEFORE `skills::route` so mode triggers
//!   beat broader skill matches.
//! - WAL `0xB0..=0xBF` band for mode-activation audit frames.
//!
//! The primitive is in place + tested today; the wiring lands when
//! the chat dispatcher integration commit drops.

use std::collections::HashMap;

use anyhow::Result;

use super::schema::{ModeEntry, Skill};

/// QM-3 process-wide mode lookup. Built once at daemon boot from
/// the loaded skill set; cheap to share across handlers via Arc.
#[derive(Clone, Debug, Default)]
pub struct ModeRegistry {
    /// Flat `mode_id → (skill_id, mode)` map. Mode ids are unique
    /// across the whole set per the build-time check.
    entries: HashMap<String, ResolvedMode>,
}

/// QM-3 resolved mode — the matched `ModeEntry` plus its parent
/// skill id. Returned by `get` / `match_trigger` so callers don't
/// have to re-walk the skill list to find the owning manifest.
#[derive(Clone, Debug)]
pub struct ResolvedMode {
    /// Parent skill id (matches `Skill::id`).
    pub skill_id: String,
    /// The mode entry itself. Cloned out of the skill manifest so
    /// callers can use it without re-borrowing the manifest list.
    pub mode: ModeEntry,
}

impl ModeRegistry {
    /// Build from a slice of loaded skills. Walks every skill's
    /// `modes:` list, asserts no two modes claim the same id, and
    /// returns the flat lookup.
    ///
    /// Returns an error when a duplicate mode id is detected — that's
    /// a config-time error operators should fix before the daemon
    /// boots (two skills both claiming `lit-review` would have
    /// undefined routing).
    pub fn from_skills(skills: &[Skill]) -> Result<Self> {
        let mut entries = HashMap::new();
        for s in skills {
            for m in &s.manifest.modes {
                if let Some(prior) = entries.get(&m.id) {
                    let prior: &ResolvedMode = prior;
                    anyhow::bail!(
                        "duplicate mode id `{}` — claimed by both `{}` and `{}`. \
                         Rename one in the skill manifest.",
                        m.id,
                        prior.skill_id,
                        s.id()
                    );
                }
                entries.insert(
                    m.id.clone(),
                    ResolvedMode {
                        skill_id: s.id().to_string(),
                        mode: m.clone(),
                    },
                );
            }
        }
        Ok(Self { entries })
    }

    /// O(1) lookup by mode id.
    pub fn get(&self, id: &str) -> Option<&ResolvedMode> {
        self.entries.get(id)
    }

    /// Number of modes registered.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no skill shipped any modes. Common for slim
    /// installs that only carry the verification + TDD skills.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Enumerate every registered mode for `neoth mode list` output.
    /// Order is non-deterministic (HashMap iteration); the CLI
    /// renderer sorts by mode id before printing.
    pub fn iter(&self) -> impl Iterator<Item = &ResolvedMode> {
        self.entries.values()
    }

    /// Stage-1 trigger matcher. Returns the FIRST mode whose
    /// trigger_phrases substring-match the operator's prompt
    /// (case-insensitive). When two modes both match, the iteration
    /// order is non-deterministic — for the academic skill set
    /// triggers are designed to be mutually exclusive ("fact-check"
    /// vs "lit-review" vs "systematic-review") so collisions are
    /// rare in practice. Future SP-3 work adds priority ordering.
    pub fn match_trigger(&self, prompt: &str) -> Option<&ResolvedMode> {
        let lower = prompt.to_lowercase();
        for resolved in self.entries.values() {
            for phrase in &resolved.mode.trigger_phrases {
                if !phrase.is_empty() && lower.contains(&phrase.to_lowercase()) {
                    return Some(resolved);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::schema::{ModeEntry, OutputContract, Oversight, SkillManifest, Spectrum};
    use std::path::PathBuf;

    fn make_skill(id: &str, modes: Vec<ModeEntry>) -> Skill {
        Skill {
            manifest: SkillManifest {
                id: id.to_string(),
                description: "test".into(),
                version: "0.1.0".into(),
                trigger_keywords: vec![],
                system_prompt: "base".into(),
                tool_allowlist: vec![],
                author: None,
                tags: vec![],
                homepage: None,
                source: None,
                modes,
                enabled: true,
                delegate_to: None,
                model: None,
            },
            path: PathBuf::from(format!("<test>/{id}/skill.yaml")),
            content_hash: String::new(),
        }
    }

    fn make_mode(id: &str, triggers: &[&str], oversight: Oversight) -> ModeEntry {
        ModeEntry {
            id: id.to_string(),
            description: format!("mode {id}"),
            spectrum: Spectrum::Balanced,
            oversight,
            output: OutputContract {
                format: "markdown".into(),
                length_hint: None,
            },
            trigger_phrases: triggers.iter().map(|s| s.to_string()).collect(),
            system_prompt_delta: String::new(),
        }
    }

    #[test]
    fn registry_built_from_empty_skill_list_is_empty() {
        let r = ModeRegistry::from_skills(&[]).unwrap();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn registry_built_from_skills_without_modes_is_empty() {
        let s1 = make_skill("skill-a", vec![]);
        let s2 = make_skill("skill-b", vec![]);
        let r = ModeRegistry::from_skills(&[s1, s2]).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn registry_flattens_modes_across_skills() {
        let s1 = make_skill(
            "deep-research",
            vec![
                make_mode("lit-review", &["literature review"], Oversight::High),
                make_mode("fact-check", &["fact-check"], Oversight::VeryHigh),
            ],
        );
        let s2 = make_skill(
            "academic-paper",
            vec![make_mode("plan", &["plan a paper"], Oversight::Medium)],
        );
        let r = ModeRegistry::from_skills(&[s1, s2]).unwrap();
        assert_eq!(r.len(), 3);
        assert!(r.get("lit-review").is_some());
        assert!(r.get("fact-check").is_some());
        assert!(r.get("plan").is_some());
        assert!(r.get("nonexistent").is_none());
    }

    #[test]
    fn registry_reports_parent_skill_id() {
        let s1 = make_skill(
            "deep-research",
            vec![make_mode("lit-review", &["lit review"], Oversight::High)],
        );
        let r = ModeRegistry::from_skills(&[s1]).unwrap();
        let resolved = r.get("lit-review").unwrap();
        assert_eq!(resolved.skill_id, "deep-research");
        assert_eq!(resolved.mode.id, "lit-review");
    }

    #[test]
    fn registry_rejects_duplicate_mode_id_across_skills() {
        // Two different skills both claim the same mode id —
        // config-time error, daemon must refuse to boot the
        // ambiguous registry.
        let s1 = make_skill("skill-a", vec![make_mode("dup", &["a"], Oversight::Low)]);
        let s2 = make_skill("skill-b", vec![make_mode("dup", &["b"], Oversight::Low)]);
        let r = ModeRegistry::from_skills(&[s1, s2]);
        assert!(r.is_err(), "duplicate mode id must error");
        let err = r.unwrap_err().to_string();
        assert!(err.contains("dup"));
        assert!(err.contains("skill-a"));
        assert!(err.contains("skill-b"));
    }

    #[test]
    fn registry_rejects_duplicate_mode_id_within_same_skill() {
        // Same skill claims the same mode id twice. Still an error;
        // the manifest YAML is invalid.
        let s1 = make_skill(
            "dup-skill",
            vec![
                make_mode("twice", &["a"], Oversight::Low),
                make_mode("twice", &["b"], Oversight::Low),
            ],
        );
        let r = ModeRegistry::from_skills(&[s1]);
        assert!(r.is_err());
    }

    #[test]
    fn match_trigger_finds_substring_case_insensitive() {
        let s1 = make_skill(
            "deep-research",
            vec![make_mode(
                "lit-review",
                &["literature review", "Lit Review"],
                Oversight::High,
            )],
        );
        let r = ModeRegistry::from_skills(&[s1]).unwrap();
        // Lower-case substring match.
        let hit = r.match_trigger("Can you do a Literature Review on transformers?");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().mode.id, "lit-review");
    }

    #[test]
    fn match_trigger_returns_none_for_no_match() {
        let s1 = make_skill(
            "deep-research",
            vec![make_mode(
                "lit-review",
                &["literature review"],
                Oversight::High,
            )],
        );
        let r = ModeRegistry::from_skills(&[s1]).unwrap();
        let hit = r.match_trigger("Tell me a joke");
        assert!(hit.is_none());
    }

    #[test]
    fn match_trigger_skips_empty_phrases() {
        // Empty strings in trigger_phrases must not match every
        // prompt (`"".contains("")` is always true).
        let s1 = make_skill(
            "x",
            vec![ModeEntry {
                id: "ghost".into(),
                description: "x".into(),
                spectrum: Spectrum::Fidelity,
                oversight: Oversight::Low,
                output: OutputContract {
                    format: "markdown".into(),
                    length_hint: None,
                },
                trigger_phrases: vec!["".to_string()],
                system_prompt_delta: String::new(),
            }],
        );
        let r = ModeRegistry::from_skills(&[s1]).unwrap();
        // Even though "" technically substring-matches everything,
        // the registry must skip empty phrases.
        let hit = r.match_trigger("anything");
        assert!(hit.is_none());
    }

    // ── QM-23 acceptance: bundled academic_research skill ships 15 modes ──

    #[tokio::test]
    async fn qm_23_bundled_academic_skill_registers_fifteen_modes() {
        // R3-P0 + QM-3 + QM-23 integration: the bundled academic_research
        // skill YAML loads via `loader::load_all`, parses through serde
        // into 15 ModeEntry rows, and ModeRegistry::from_skills surfaces
        // all of them by id without duplicate-id errors. Pinning the
        // count at exactly 15 means a future PR that drops one of the
        // academic modes (or adds a 16th) surfaces here.
        use crate::skills::loader::load_all;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let skills = load_all(dir.path()).await.unwrap();
        let academic = skills
            .iter()
            .find(|s| s.id() == "academic_research")
            .expect("academic_research bundled skill must load");
        assert_eq!(
            academic.manifest.modes.len(),
            15,
            "QM-23: academic_research skill must ship 15 modes"
        );
        // Build a registry just from this one skill — must succeed
        // (no duplicate ids within the skill).
        let registry = ModeRegistry::from_skills(std::slice::from_ref(academic)).unwrap();
        assert_eq!(registry.len(), 15);

        // Sample a known mode and verify its shape.
        let lit = registry
            .get("research_lit_review")
            .expect("research_lit_review must register");
        assert_eq!(lit.skill_id, "academic_research");
        assert_eq!(lit.mode.spectrum, Spectrum::Balanced);
        assert_eq!(lit.mode.oversight, Oversight::High);
        assert_eq!(lit.mode.output.format, "markdown");
        assert!(!lit.mode.trigger_phrases.is_empty());
    }

    #[tokio::test]
    async fn qm_23_academic_mode_trigger_phrases_match_typical_prompts() {
        // Pin a handful of operator-language → mode routings so
        // future trigger-phrase edits don't break the discovered UX.
        use crate::skills::loader::load_all;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let skills = load_all(dir.path()).await.unwrap();
        let academic = skills
            .iter()
            .find(|s| s.id() == "academic_research")
            .unwrap()
            .clone();
        let registry = ModeRegistry::from_skills(&[academic]).unwrap();

        // Operator says "fact-check these claims" → research_fact_check
        let hit = registry
            .match_trigger("Please fact-check these claims for me")
            .expect("trigger must hit");
        assert_eq!(hit.mode.id, "research_fact_check");

        // Operator says "I need a lit review" → research_lit_review
        let hit = registry
            .match_trigger("I need a lit review on transformer architectures")
            .expect("trigger must hit");
        assert_eq!(hit.mode.id, "research_lit_review");

        // Operator says "do a PRISMA review" → research_systematic
        let hit = registry
            .match_trigger("Can you do a PRISMA review of these 12 papers?")
            .expect("trigger must hit");
        assert_eq!(hit.mode.id, "research_systematic");

        // Operator says "review methodology of this paper" → reviewer_methodology
        let hit = registry
            .match_trigger("Please review methodology of attached manuscript")
            .expect("trigger must hit");
        assert_eq!(hit.mode.id, "reviewer_methodology");
    }

    #[test]
    fn iter_yields_every_resolved_mode() {
        let s1 = make_skill(
            "x",
            vec![
                make_mode("a", &["aa"], Oversight::Low),
                make_mode("b", &["bb"], Oversight::Low),
            ],
        );
        let r = ModeRegistry::from_skills(&[s1]).unwrap();
        let ids: std::collections::HashSet<_> = r.iter().map(|rm| rm.mode.id.clone()).collect();
        assert!(ids.contains("a"));
        assert!(ids.contains("b"));
        assert_eq!(ids.len(), 2);
    }
}
