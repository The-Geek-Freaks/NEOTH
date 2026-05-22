//! R3 P0 — Bundled skills embedded into the binary at compile time.
//!
//! Per `PLAN/REEVALUATION_GESAMT_2026-05-22_R3.md` §5 P0: NEOTH ships
//! 21 skill YAMLs under `SRC/neothd/assets/skills/<id>/skill.yaml`, but
//! pre-this-module those YAMLs only existed as source-tree assets +
//! loader-test fixtures. Runtime [`super::loader::load_all`] walked
//! `~/.neoth/skills/` exclusively, so a fresh operator install booted
//! with ZERO skills active.
//!
//! This module fixes that by `include_str!`-ing every shipped skill at
//! compile time. The shipped binary's `.rodata` carries every YAML;
//! the loader merges bundled + user-installed skills with user winning
//! on id collisions. Operators on a fresh `~/` get the full skill
//! library out of the box; operators who install custom skills under
//! `~/.neoth/skills/<id>/` override the bundled defaults transparently.
//!
//! ## AIO hard rule compliance
//!
//! Per `[[neoth-aio-cross-platform]]`: every runtime dep must ship
//! in-binary OR auto-install. Bundled-skill YAMLs go the in-binary
//! route — zero filesystem touches at boot, no installer step needed,
//! no `cargo build` artifacts left behind. The YAMLs become part of
//! the binary the same way `Cargo.toml` becomes part of `cargo --version`.
//!
//! ## Update protocol
//!
//! Adding a new shipped skill: drop the directory under
//! `SRC/neothd/assets/skills/<new_id>/skill.yaml`, then add the
//! `(id, include_str!(...))` entry below. The
//! `loader::tests::qm_21_ported_superpowers_skills_all_parse_clean`
//! test also pins the expected id list — update it in the same commit
//! so the build-time guarantee stays honest.

/// Every skill NEOTH ships in its binary. Sorted by id so the runtime
/// merge order is deterministic.
///
/// Each entry is `(id_string, yaml_body)`. The `id_string` MUST match
/// the manifest's `id:` field exactly — the loader rejects mismatches.
/// The `include_str!` path is relative to THIS file
/// (`SRC/neothd/src/skills/bundled.rs`), hence the `../../assets/...`
/// prefix.
pub const BUNDLED_SKILLS: &[(&str, &str)] = &[
    (
        "brainstorming",
        include_str!("../../assets/skills/brainstorming/skill.yaml"),
    ),
    (
        "diagnose",
        include_str!("../../assets/skills/diagnose/skill.yaml"),
    ),
    (
        "dispatching_parallel_agents",
        include_str!("../../assets/skills/dispatching_parallel_agents/skill.yaml"),
    ),
    (
        "executing_plans",
        include_str!("../../assets/skills/executing_plans/skill.yaml"),
    ),
    (
        "finishing_a_development_branch",
        include_str!("../../assets/skills/finishing_a_development_branch/skill.yaml"),
    ),
    (
        "grill_me",
        include_str!("../../assets/skills/grill_me/skill.yaml"),
    ),
    (
        "grill_with_docs",
        include_str!("../../assets/skills/grill_with_docs/skill.yaml"),
    ),
    (
        "improve_codebase_architecture",
        include_str!("../../assets/skills/improve_codebase_architecture/skill.yaml"),
    ),
    (
        "prototype",
        include_str!("../../assets/skills/prototype/skill.yaml"),
    ),
    (
        "receiving_code_review",
        include_str!("../../assets/skills/receiving_code_review/skill.yaml"),
    ),
    (
        "requesting_code_review",
        include_str!("../../assets/skills/requesting_code_review/skill.yaml"),
    ),
    (
        "systematic_debugging",
        include_str!("../../assets/skills/systematic_debugging/skill.yaml"),
    ),
    (
        "test_driven_development",
        include_str!("../../assets/skills/test_driven_development/skill.yaml"),
    ),
    (
        "to_issues",
        include_str!("../../assets/skills/to_issues/skill.yaml"),
    ),
    (
        "to_prd",
        include_str!("../../assets/skills/to_prd/skill.yaml"),
    ),
    (
        "triage",
        include_str!("../../assets/skills/triage/skill.yaml"),
    ),
    (
        "using_git_worktrees",
        include_str!("../../assets/skills/using_git_worktrees/skill.yaml"),
    ),
    (
        "verification_before_completion",
        include_str!("../../assets/skills/verification_before_completion/skill.yaml"),
    ),
    (
        "writing_plans",
        include_str!("../../assets/skills/writing_plans/skill.yaml"),
    ),
    (
        "writing_skills",
        include_str!("../../assets/skills/writing_skills/skill.yaml"),
    ),
    (
        "zoom_out",
        include_str!("../../assets/skills/zoom_out/skill.yaml"),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::schema::SkillManifest;

    #[test]
    fn every_bundled_skill_has_nonempty_body() {
        assert!(!BUNDLED_SKILLS.is_empty());
        for (id, body) in BUNDLED_SKILLS {
            assert!(
                !body.trim().is_empty(),
                "bundled skill {id} has empty body — include_str! failed at compile time?"
            );
        }
    }

    #[test]
    fn every_bundled_skill_parses_as_valid_manifest() {
        for (id, body) in BUNDLED_SKILLS {
            let manifest: SkillManifest = serde_yaml::from_str(body)
                .unwrap_or_else(|e| panic!("bundled skill `{id}` failed to parse: {e}"));
            assert_eq!(
                manifest.id, *id,
                "bundled entry id `{}` doesn't match manifest id `{}`",
                id, manifest.id
            );
            assert!(
                !manifest.description.trim().is_empty(),
                "bundled skill `{id}` has empty description"
            );
            assert!(
                !manifest.system_prompt.trim().is_empty(),
                "bundled skill `{id}` has empty system_prompt"
            );
            assert!(
                !manifest.trigger_keywords.is_empty(),
                "bundled skill `{id}` has no trigger_keywords — router would miss it"
            );
        }
    }

    #[test]
    fn bundled_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for (id, _) in BUNDLED_SKILLS {
            assert!(
                seen.insert(*id),
                "duplicate bundled skill id: {id} (an entry was copy-pasted)"
            );
        }
    }

    #[test]
    fn bundled_ids_are_sorted_alphabetically() {
        // Pin the sort so a future contributor adding a skill in the
        // middle of the array gets a test failure pointing them at
        // alphabetical order — keeps the merge contract stable.
        let ids: Vec<&str> = BUNDLED_SKILLS.iter().map(|(id, _)| *id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(
            ids, sorted,
            "BUNDLED_SKILLS must be alphabetical by id; re-sort entries"
        );
    }

    #[test]
    fn bundled_count_matches_assets_directory() {
        // Build-time invariant: the count in BUNDLED_SKILLS matches
        // what's on disk under SRC/neothd/assets/skills/. A skill
        // dropped without an `include_str!` entry would otherwise
        // silently miss runtime activation — exactly the R3 P0 gap
        // this module exists to close.
        let assets_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("assets")
            .join("skills");
        if !assets_dir.exists() {
            // Source-only / packaging-stripped builds: skip.
            return;
        }
        let on_disk = std::fs::read_dir(&assets_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| !n.starts_with('.'))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            BUNDLED_SKILLS.len(),
            on_disk,
            "BUNDLED_SKILLS has {} entries but assets/skills/ has {} dirs — \
             add the missing include_str!(...) entry or remove the asset",
            BUNDLED_SKILLS.len(),
            on_disk
        );
    }
}
