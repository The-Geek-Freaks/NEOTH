//! R3 P0 — Bundled skills embedded into the binary at compile time.
//!
//! Per `PLAN/REEVALUATION_GESAMT_2026-05-22_R3.md` §5 P0: NEOTH ships
//! 30 skill YAMLs under `SRC/neothd/assets/skills/<id>/skill.yaml` (the
//! exact count is pinned by the `bundled_count_matches_assets_directory`
//! test), but
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
        "academic_research",
        include_str!("../../assets/skills/academic_research/skill.yaml"),
    ),
    (
        "archon",
        include_str!("../../assets/skills/archon/skill.yaml"),
    ),
    (
        "brainstorming",
        include_str!("../../assets/skills/brainstorming/skill.yaml"),
    ),
    (
        "conductor",
        include_str!("../../assets/skills/conductor/skill.yaml"),
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
        "lowkey_base",
        include_str!("../../assets/skills/lowkey_base/skill.yaml"),
    ),
    (
        "magi_ultra",
        include_str!("../../assets/skills/magi_ultra/skill.yaml"),
    ),
    (
        "max_plus_plus",
        include_str!("../../assets/skills/max_plus_plus/skill.yaml"),
    ),
    (
        "omega_prime",
        include_str!("../../assets/skills/omega_prime/skill.yaml"),
    ),
    (
        "pm-ab-test-analysis",
        include_str!("../../assets/skills/pm-ab-test-analysis/skill.yaml"),
    ),
    (
        "pm-analyze-feature-requests",
        include_str!("../../assets/skills/pm-analyze-feature-requests/skill.yaml"),
    ),
    (
        "pm-ansoff-matrix",
        include_str!("../../assets/skills/pm-ansoff-matrix/skill.yaml"),
    ),
    (
        "pm-beachhead-segment",
        include_str!("../../assets/skills/pm-beachhead-segment/skill.yaml"),
    ),
    (
        "pm-brainstorm-experiments-existing",
        include_str!("../../assets/skills/pm-brainstorm-experiments-existing/skill.yaml"),
    ),
    (
        "pm-brainstorm-experiments-new",
        include_str!("../../assets/skills/pm-brainstorm-experiments-new/skill.yaml"),
    ),
    (
        "pm-brainstorm-ideas-existing",
        include_str!("../../assets/skills/pm-brainstorm-ideas-existing/skill.yaml"),
    ),
    (
        "pm-brainstorm-ideas-new",
        include_str!("../../assets/skills/pm-brainstorm-ideas-new/skill.yaml"),
    ),
    (
        "pm-brainstorm-okrs",
        include_str!("../../assets/skills/pm-brainstorm-okrs/skill.yaml"),
    ),
    (
        "pm-business-model",
        include_str!("../../assets/skills/pm-business-model/skill.yaml"),
    ),
    (
        "pm-cohort-analysis",
        include_str!("../../assets/skills/pm-cohort-analysis/skill.yaml"),
    ),
    (
        "pm-competitive-battlecard",
        include_str!("../../assets/skills/pm-competitive-battlecard/skill.yaml"),
    ),
    (
        "pm-competitor-analysis",
        include_str!("../../assets/skills/pm-competitor-analysis/skill.yaml"),
    ),
    (
        "pm-create-prd",
        include_str!("../../assets/skills/pm-create-prd/skill.yaml"),
    ),
    (
        "pm-customer-journey-map",
        include_str!("../../assets/skills/pm-customer-journey-map/skill.yaml"),
    ),
    (
        "pm-draft-nda",
        include_str!("../../assets/skills/pm-draft-nda/skill.yaml"),
    ),
    (
        "pm-dummy-dataset",
        include_str!("../../assets/skills/pm-dummy-dataset/skill.yaml"),
    ),
    (
        "pm-grammar-check",
        include_str!("../../assets/skills/pm-grammar-check/skill.yaml"),
    ),
    (
        "pm-growth-loops",
        include_str!("../../assets/skills/pm-growth-loops/skill.yaml"),
    ),
    (
        "pm-gtm-motions",
        include_str!("../../assets/skills/pm-gtm-motions/skill.yaml"),
    ),
    (
        "pm-gtm-strategy",
        include_str!("../../assets/skills/pm-gtm-strategy/skill.yaml"),
    ),
    (
        "pm-ideal-customer-profile",
        include_str!("../../assets/skills/pm-ideal-customer-profile/skill.yaml"),
    ),
    (
        "pm-identify-assumptions-existing",
        include_str!("../../assets/skills/pm-identify-assumptions-existing/skill.yaml"),
    ),
    (
        "pm-identify-assumptions-new",
        include_str!("../../assets/skills/pm-identify-assumptions-new/skill.yaml"),
    ),
    (
        "pm-intended-vs-implemented",
        include_str!("../../assets/skills/pm-intended-vs-implemented/skill.yaml"),
    ),
    (
        "pm-interview-script",
        include_str!("../../assets/skills/pm-interview-script/skill.yaml"),
    ),
    (
        "pm-job-stories",
        include_str!("../../assets/skills/pm-job-stories/skill.yaml"),
    ),
    (
        "pm-lean-canvas",
        include_str!("../../assets/skills/pm-lean-canvas/skill.yaml"),
    ),
    (
        "pm-market-segments",
        include_str!("../../assets/skills/pm-market-segments/skill.yaml"),
    ),
    (
        "pm-market-sizing",
        include_str!("../../assets/skills/pm-market-sizing/skill.yaml"),
    ),
    (
        "pm-marketing-ideas",
        include_str!("../../assets/skills/pm-marketing-ideas/skill.yaml"),
    ),
    (
        "pm-metrics-dashboard",
        include_str!("../../assets/skills/pm-metrics-dashboard/skill.yaml"),
    ),
    (
        "pm-monetization-strategy",
        include_str!("../../assets/skills/pm-monetization-strategy/skill.yaml"),
    ),
    (
        "pm-north-star-metric",
        include_str!("../../assets/skills/pm-north-star-metric/skill.yaml"),
    ),
    (
        "pm-opportunity-solution-tree",
        include_str!("../../assets/skills/pm-opportunity-solution-tree/skill.yaml"),
    ),
    (
        "pm-outcome-roadmap",
        include_str!("../../assets/skills/pm-outcome-roadmap/skill.yaml"),
    ),
    (
        "pm-pestle-analysis",
        include_str!("../../assets/skills/pm-pestle-analysis/skill.yaml"),
    ),
    (
        "pm-porters-five-forces",
        include_str!("../../assets/skills/pm-porters-five-forces/skill.yaml"),
    ),
    (
        "pm-positioning-ideas",
        include_str!("../../assets/skills/pm-positioning-ideas/skill.yaml"),
    ),
    (
        "pm-pre-mortem",
        include_str!("../../assets/skills/pm-pre-mortem/skill.yaml"),
    ),
    (
        "pm-pricing-strategy",
        include_str!("../../assets/skills/pm-pricing-strategy/skill.yaml"),
    ),
    (
        "pm-prioritization-frameworks",
        include_str!("../../assets/skills/pm-prioritization-frameworks/skill.yaml"),
    ),
    (
        "pm-prioritize-assumptions",
        include_str!("../../assets/skills/pm-prioritize-assumptions/skill.yaml"),
    ),
    (
        "pm-prioritize-features",
        include_str!("../../assets/skills/pm-prioritize-features/skill.yaml"),
    ),
    (
        "pm-privacy-policy",
        include_str!("../../assets/skills/pm-privacy-policy/skill.yaml"),
    ),
    (
        "pm-product-name",
        include_str!("../../assets/skills/pm-product-name/skill.yaml"),
    ),
    (
        "pm-product-strategy",
        include_str!("../../assets/skills/pm-product-strategy/skill.yaml"),
    ),
    (
        "pm-product-vision",
        include_str!("../../assets/skills/pm-product-vision/skill.yaml"),
    ),
    (
        "pm-release-notes",
        include_str!("../../assets/skills/pm-release-notes/skill.yaml"),
    ),
    (
        "pm-retro",
        include_str!("../../assets/skills/pm-retro/skill.yaml"),
    ),
    (
        "pm-review-resume",
        include_str!("../../assets/skills/pm-review-resume/skill.yaml"),
    ),
    (
        "pm-sentiment-analysis",
        include_str!("../../assets/skills/pm-sentiment-analysis/skill.yaml"),
    ),
    (
        "pm-shipping-artifacts",
        include_str!("../../assets/skills/pm-shipping-artifacts/skill.yaml"),
    ),
    (
        "pm-sprint-plan",
        include_str!("../../assets/skills/pm-sprint-plan/skill.yaml"),
    ),
    (
        "pm-sql-queries",
        include_str!("../../assets/skills/pm-sql-queries/skill.yaml"),
    ),
    (
        "pm-stakeholder-map",
        include_str!("../../assets/skills/pm-stakeholder-map/skill.yaml"),
    ),
    (
        "pm-startup-canvas",
        include_str!("../../assets/skills/pm-startup-canvas/skill.yaml"),
    ),
    (
        "pm-strategy-red-team",
        include_str!("../../assets/skills/pm-strategy-red-team/skill.yaml"),
    ),
    (
        "pm-summarize-interview",
        include_str!("../../assets/skills/pm-summarize-interview/skill.yaml"),
    ),
    (
        "pm-summarize-meeting",
        include_str!("../../assets/skills/pm-summarize-meeting/skill.yaml"),
    ),
    (
        "pm-swot-analysis",
        include_str!("../../assets/skills/pm-swot-analysis/skill.yaml"),
    ),
    (
        "pm-test-scenarios",
        include_str!("../../assets/skills/pm-test-scenarios/skill.yaml"),
    ),
    (
        "pm-user-personas",
        include_str!("../../assets/skills/pm-user-personas/skill.yaml"),
    ),
    (
        "pm-user-segmentation",
        include_str!("../../assets/skills/pm-user-segmentation/skill.yaml"),
    ),
    (
        "pm-user-stories",
        include_str!("../../assets/skills/pm-user-stories/skill.yaml"),
    ),
    (
        "pm-value-prop-statements",
        include_str!("../../assets/skills/pm-value-prop-statements/skill.yaml"),
    ),
    (
        "pm-value-proposition",
        include_str!("../../assets/skills/pm-value-proposition/skill.yaml"),
    ),
    (
        "pm-wwas",
        include_str!("../../assets/skills/pm-wwas/skill.yaml"),
    ),
    (
        "pme",
        include_str!("../../assets/skills/pme/skill.yaml"),
    ),
    (
        "prototype",
        include_str!("../../assets/skills/prototype/skill.yaml"),
    ),
    (
        "raskal",
        include_str!("../../assets/skills/raskal/skill.yaml"),
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
    fn pm_skills_ship_disabled_by_default() {
        // GOLD-ADOPT-14 gremium decision (unanimous 3-lens): the imported
        // `pm-*` product-management skills ship DISABLED so a non-PM operator's
        // router stays clean (route() has no confidence floor — generic-keyword
        // domain skills would false-activate). Operators turn them on with
        // `neoth skill --enable pm-<id>`. Pin it so a re-import can't flip the
        // default. Conversely every NON-pm bundled skill ships enabled.
        let mut pm = 0;
        for (id, body) in BUNDLED_SKILLS {
            let m: SkillManifest = serde_yaml::from_str(body).unwrap();
            if id.starts_with("pm-") {
                pm += 1;
                assert!(!m.enabled, "pm-* skill `{id}` must ship disabled");
            } else {
                assert!(m.enabled, "non-pm bundled skill `{id}` must ship enabled");
            }
        }
        assert!(pm >= 60, "expected the ~68 pm-* imports; got {pm}");
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

    #[test]
    fn lowkey_persona_family_is_bundled_and_triggerable() {
        // QU-07 — the 7 LOWKEY-family registers must ship as first-class,
        // router-triggerable skills (not just the hardcoded LOWKEY_PROMPT
        // constant). Drift guard: a future removal of any persona fails here.
        let ids: std::collections::HashSet<&str> =
            BUNDLED_SKILLS.iter().map(|(id, _)| *id).collect();
        for persona in [
            "lowkey_base",
            "magi_ultra",
            "omega_prime",
            "archon",
            "raskal",
            "pme",
            "max_plus_plus",
        ] {
            assert!(
                ids.contains(persona),
                "LOWKEY persona `{persona}` not bundled"
            );
            let (_, body) = BUNDLED_SKILLS
                .iter()
                .find(|(id, _)| *id == persona)
                .unwrap();
            let manifest: SkillManifest = serde_yaml::from_str(body).unwrap();
            assert!(
                !manifest.trigger_keywords.is_empty(),
                "LOWKEY persona `{persona}` has no trigger_keywords — router can't reach it"
            );
        }
    }
}
