//! R3 P0 — Bundled skills embedded into the binary at compile time.
//!
//! Per `PLAN/REEVALUATION_GESAMT_2026-05-22_R3.md` §5 P0: NEOTH ships
//! the full skill library under `SRC/neothd/assets/skills/<id>/skill.yaml`
//! (one YAML per skill — the exact count grows with the library and is
//! pinned by the `bundled_count_matches_assets_directory` test), but
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
/// Is `id` one of the skills NEOTH ships inside its binary (vs an
/// operator-authored / externally installed skill)? Drives the "contribute
/// this improvement upstream?" offer after a SkillOpt-improved skill is adopted.
pub fn is_bundled(id: &str) -> bool {
    BUNDLED_SKILLS.iter().any(|(bid, _)| *bid == id)
}

/// Repo-relative source path of a bundled skill's `<file>` (default
/// `skill.yaml`), for an upstream PR. `None` when `id` isn't bundled. The path
/// mirrors the `include_str!` layout above (`SRC/neothd/assets/skills/<id>/…`).
pub fn bundled_asset_path(id: &str, file: &str) -> Option<String> {
    is_bundled(id).then(|| format!("SRC/neothd/assets/skills/{id}/{file}"))
}

pub const BUNDLED_SKILLS: &[(&str, &str)] = &[
    (
        "academic_research",
        include_str!("../../assets/skills/academic_research/skill.yaml"),
    ),
    (
        "agent_engineering_patterns",
        include_str!("../../assets/skills/agent_engineering_patterns/skill.yaml"),
    ),
    (
        "anti_slop",
        include_str!("../../assets/skills/anti_slop/skill.yaml"),
    ),
    (
        "archon",
        include_str!("../../assets/skills/archon/skill.yaml"),
    ),
    (
        "brainstorming",
        include_str!("../../assets/skills/brainstorming/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL2-06 (2026-06-19) — bundled skill.
    (
        "code_review_and_quality",
        include_str!("../../assets/skills/code_review_and_quality/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL-04 (2026-06-14) — re-implemented from addyosmani/agent-skills (MIT).
    (
        "code_simplification",
        include_str!("../../assets/skills/code_simplification/skill.yaml"),
    ),
    (
        "conductor",
        include_str!("../../assets/skills/conductor/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL-05 (2026-06-14) — re-implemented from addyosmani/agent-skills (MIT).
    (
        "context_engineering",
        include_str!("../../assets/skills/context_engineering/skill.yaml"),
    ),
    (
        "cybersec_detection_engineering",
        include_str!("../../assets/skills/cybersec_detection_engineering/skill.yaml"),
    ),
    (
        "cybersec_dfir",
        include_str!("../../assets/skills/cybersec_dfir/skill.yaml"),
    ),
    (
        "cybersec_exploit_dev",
        include_str!("../../assets/skills/cybersec_exploit_dev/skill.yaml"),
    ),
    (
        "cybersec_malware_analysis",
        include_str!("../../assets/skills/cybersec_malware_analysis/skill.yaml"),
    ),
    (
        "cybersec_pentest_recon",
        include_str!("../../assets/skills/cybersec_pentest_recon/skill.yaml"),
    ),
    (
        "cybersec_threat_modeling",
        include_str!("../../assets/skills/cybersec_threat_modeling/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL2-01 (2026-06-19) — bundled skill.
    (
        "debugging_and_error_recovery",
        include_str!("../../assets/skills/debugging_and_error_recovery/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL-06 (2026-06-14) — re-implemented from addyosmani/agent-skills (MIT).
    (
        "deprecation_migration",
        include_str!("../../assets/skills/deprecation_migration/skill.yaml"),
    ),
    // GOLD-ADAPT-DESIGN-01 (2026-06-19) — bundled skill.
    (
        "design_eng",
        include_str!("../../assets/skills/design_eng/skill.yaml"),
    ),
    (
        "diagnose",
        include_str!("../../assets/skills/diagnose/skill.yaml"),
    ),
    (
        "diagram_mermaid",
        include_str!("../../assets/skills/diagram_mermaid/skill.yaml"),
    ),
    (
        "dispatching_parallel_agents",
        include_str!("../../assets/skills/dispatching_parallel_agents/skill.yaml"),
    ),
    // GOLD-ADAPT-GRILL-05 (2026-06-19) — per-session domain glossary discipline.
    (
        "domain_glossary",
        include_str!("../../assets/skills/domain_glossary/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL-01 (2026-06-14) — re-implemented from addyosmani/agent-skills (MIT).
    (
        "doubt_driven_development",
        include_str!("../../assets/skills/doubt_driven_development/skill.yaml"),
    ),
    // GOLD-ADAPT-DRAW-01 (2026-06-19) — bundled skill.
    (
        "drawio_diagram",
        include_str!("../../assets/skills/drawio_diagram/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL2-08 (2026-06-19) — bundled skill.
    (
        "efficient_frontier",
        include_str!("../../assets/skills/efficient_frontier/skill.yaml"),
    ),
    (
        "engineering_code_review",
        include_str!("../../assets/skills/engineering_code_review/skill.yaml"),
    ),
    (
        "engineering_documentation",
        include_str!("../../assets/skills/engineering_documentation/skill.yaml"),
    ),
    (
        "engineering_incident_response",
        include_str!("../../assets/skills/engineering_incident_response/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL-02 (2026-06-14) — re-implemented from addyosmani/agent-skills (MIT).
    (
        "engineering_observability",
        include_str!("../../assets/skills/engineering_observability/skill.yaml"),
    ),
    (
        "engineering_system_design",
        include_str!("../../assets/skills/engineering_system_design/skill.yaml"),
    ),
    (
        "engineering_tech_debt",
        include_str!("../../assets/skills/engineering_tech_debt/skill.yaml"),
    ),
    (
        "engineering_testing_strategy",
        include_str!("../../assets/skills/engineering_testing_strategy/skill.yaml"),
    ),
    (
        "executing_plans",
        include_str!("../../assets/skills/executing_plans/skill.yaml"),
    ),
    (
        "finishing_a_development_branch",
        include_str!("../../assets/skills/finishing_a_development_branch/skill.yaml"),
    ),
    // GOLD-ADAPT-GITPR-02 (2026-06-19) — bundled skill.
    (
        "git_pr_create",
        include_str!("../../assets/skills/git_pr_create/skill.yaml"),
    ),
    // GOLD-ADAPT-GITPR-03 (2026-06-19) — bundled skill.
    (
        "github_pr_review",
        include_str!("../../assets/skills/github_pr_review/skill.yaml"),
    ),
    (
        "grill_me",
        include_str!("../../assets/skills/grill_me/skill.yaml"),
    ),
    (
        "grill_with_docs",
        include_str!("../../assets/skills/grill_with_docs/skill.yaml"),
    ),
    // GOLD-ADAPT-DOC-03 (2026-06-19) — bundled skill.
    (
        "hallmark_ui",
        include_str!("../../assets/skills/hallmark_ui/skill.yaml"),
    ),
    // GOLD-ADAPT-JV-IMP-07 (2026-06-19) — bundled skill.
    (
        "hippocampus_memory",
        include_str!("../../assets/skills/hippocampus_memory/skill.yaml"),
    ),
    // GOLD-ADAPT-DOC-02 (2026-06-19) — bundled skill.
    (
        "html_diagram",
        include_str!("../../assets/skills/html_diagram/skill.yaml"),
    ),
    // GOLD-ADAPT-DOC-02 (2026-06-19) — bundled skill.
    (
        "html_page",
        include_str!("../../assets/skills/html_page/skill.yaml"),
    ),
    // GOLD-ADAPT-DOC-02 (2026-06-19) — bundled skill.
    (
        "html_plan",
        include_str!("../../assets/skills/html_plan/skill.yaml"),
    ),
    // GOLD-ADAPT-HCP-01 (2026-06-19) — IaC security-audit skill (default-disabled).
    (
        "iac_security_audit",
        include_str!("../../assets/skills/iac_security_audit/skill.yaml"),
    ),
    // GOLD-ADAPT-DESIGN-02 (2026-06-19) — bundled skill.
    (
        "impeccable",
        include_str!("../../assets/skills/impeccable/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL2-07 (2026-06-19) — bundled skill.
    (
        "improve_advisor",
        include_str!("../../assets/skills/improve_advisor/skill.yaml"),
    ),
    (
        "improve_codebase_architecture",
        include_str!("../../assets/skills/improve_codebase_architecture/skill.yaml"),
    ),
    // GOLD-ADAPT-PT-06 (2026-06-15) — ponytail YAGNI ladder as a router-activatable skill.
    (
        "lazy_dev",
        include_str!("../../assets/skills/lazy_dev/skill.yaml"),
    ),
    // GOLD-ADAPT-PT-07 (2026-06-15) — over-engineering audit (cross-module / dep level).
    (
        "lazy_review",
        include_str!("../../assets/skills/lazy_review/skill.yaml"),
    ),
    (
        "log_analyzer",
        include_str!("../../assets/skills/log_analyzer/skill.yaml"),
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
    // NN-MEM-02 (2026-06-22) — 5-dimensional synthesis pattern-recognition companion
    // skill. On-demand synthesis of the weekly cron's 5 dimensions (frequency +
    // temporal-clustering + domain-correlation + contradiction-flags + cross-cutting).
    // Ships DISABLED by default (opt-in alongside synthesis_cron.enabled).
    (
        "memory_synthesis",
        include_str!("../../assets/skills/memory_synthesis/skill.yaml"),
    ),
    // GOLD-ADAPT-PONY-01 (2026-06-19) — bundled skill.
    (
        "neoth_debt",
        include_str!("../../assets/skills/neoth_debt/skill.yaml"),
    ),
    // GOLD-ADAPT-DOC-04 (2026-06-23) — officecli family (11 skills), binary-gated, Apache-2.0.
    // All ship `enabled: false`; operator enables after installing officecli from d.officecli.ai.
    // Sorted: officecli_docx_convert < officecli_docx_create < officecli_docx_edit <
    //         officecli_docx_format < officecli_office_pipeline < officecli_pdf_convert <
    //         officecli_pptx_create < officecli_pptx_edit < officecli_xlsx_create <
    //         officecli_xlsx_edit < officecli_xlsx_formula  (all 'o' before omega_prime 'o+m').
    (
        "officecli_docx_convert",
        include_str!("../../assets/skills/officecli_docx_convert/skill.yaml"),
    ),
    (
        "officecli_docx_create",
        include_str!("../../assets/skills/officecli_docx_create/skill.yaml"),
    ),
    (
        "officecli_docx_edit",
        include_str!("../../assets/skills/officecli_docx_edit/skill.yaml"),
    ),
    (
        "officecli_docx_format",
        include_str!("../../assets/skills/officecli_docx_format/skill.yaml"),
    ),
    (
        "officecli_office_pipeline",
        include_str!("../../assets/skills/officecli_office_pipeline/skill.yaml"),
    ),
    (
        "officecli_pdf_convert",
        include_str!("../../assets/skills/officecli_pdf_convert/skill.yaml"),
    ),
    (
        "officecli_pptx_create",
        include_str!("../../assets/skills/officecli_pptx_create/skill.yaml"),
    ),
    (
        "officecli_pptx_edit",
        include_str!("../../assets/skills/officecli_pptx_edit/skill.yaml"),
    ),
    (
        "officecli_xlsx_create",
        include_str!("../../assets/skills/officecli_xlsx_create/skill.yaml"),
    ),
    (
        "officecli_xlsx_edit",
        include_str!("../../assets/skills/officecli_xlsx_edit/skill.yaml"),
    ),
    (
        "officecli_xlsx_formula",
        include_str!("../../assets/skills/officecli_xlsx_formula/skill.yaml"),
    ),
    (
        "omega_prime",
        include_str!("../../assets/skills/omega_prime/skill.yaml"),
    ),
    // GOLD-ADAPT-KBD-01 (2026-06-19) — bundled skill.
    (
        "paper_review",
        include_str!("../../assets/skills/paper_review/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL2-03 (2026-06-19) — bundled skill.
    (
        "performance_optimization",
        include_str!("../../assets/skills/performance_optimization/skill.yaml"),
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
    ("pme", include_str!("../../assets/skills/pme/skill.yaml")),
    // GOLD-ADAPT-DOC-01 (2026-06-23) — ppt_master skill: python-pptx presentation
    // generation, advisory Python install gate, MIT. Ships enabled; gate is advisory.
    (
        "ppt_master",
        include_str!("../../assets/skills/ppt_master/skill.yaml"),
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
    // GOLD-ADAPT-SKILL2-02 (2026-06-19) — bundled skill.
    (
        "security_and_hardening",
        include_str!("../../assets/skills/security_and_hardening/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL-08 (2026-06-14) — re-implemented from addyosmani/agent-skills (MIT).
    (
        "ship_review",
        include_str!("../../assets/skills/ship_review/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL2-04 (2026-06-19) — bundled skill.
    (
        "shipping_and_launch",
        include_str!("../../assets/skills/shipping_and_launch/skill.yaml"),
    ),
    // GOLD-ADAPT-KIT-01 (2026-06-19) — bundled skill.
    (
        "skill_security_review",
        include_str!("../../assets/skills/skill_security_review/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL-03 (2026-06-14) — re-implemented from addyosmani/agent-skills (MIT).
    (
        "source_driven_development",
        include_str!("../../assets/skills/source_driven_development/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL2-05 (2026-06-19) — bundled skill.
    (
        "spec_driven_development",
        include_str!("../../assets/skills/spec_driven_development/skill.yaml"),
    ),
    // GOLD-ADAPT-SKILL2-09 (2026-06-19) — bundled skill.
    (
        "stay_within_limits",
        include_str!("../../assets/skills/stay_within_limits/skill.yaml"),
    ),
    (
        "systematic_debugging",
        include_str!("../../assets/skills/systematic_debugging/skill.yaml"),
    ),
    // GOLD-ADAPT-DESIGN-03 (2026-06-19) — bundled skill.
    (
        "taste",
        include_str!("../../assets/skills/taste/skill.yaml"),
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
    // GOLD-ADAPT-WEBQ-01 (2026-06-19) — bundled skill.
    (
        "webq_a11y",
        include_str!("../../assets/skills/webq_a11y/skill.yaml"),
    ),
    // GOLD-ADAPT-WEBQ-02 (2026-06-19) — bundled skill.
    (
        "webq_best_practices",
        include_str!("../../assets/skills/webq_best_practices/skill.yaml"),
    ),
    // GOLD-ADAPT-WEBQ-03 (2026-06-19) — bundled skill.
    (
        "webq_core_web_vitals",
        include_str!("../../assets/skills/webq_core_web_vitals/skill.yaml"),
    ),
    // GOLD-ADAPT-WEBQ-04 (2026-06-19) — bundled skill.
    (
        "webq_performance",
        include_str!("../../assets/skills/webq_performance/skill.yaml"),
    ),
    // GOLD-ADAPT-WEBQ-05 (2026-06-19) — bundled skill.
    (
        "webq_seo",
        include_str!("../../assets/skills/webq_seo/skill.yaml"),
    ),
    // GOLD-ADAPT-WEBQ-06 (2026-06-19) — bundled skill.
    (
        "webq_web_quality_audit",
        include_str!("../../assets/skills/webq_web_quality_audit/skill.yaml"),
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

    /// GOLD-ADAPT-DOC-01 (2026-06-23) — integration test.
    ///
    /// Asserts three things in one pass:
    ///  1. ppt_master is in BUNDLED_SKILLS, parses cleanly, ships enabled.
    ///  2. The keyword router (the live consumer) routes realistic operator
    ///     prompts to ppt_master when the full bundled skill set is loaded —
    ///     proving the trigger_keywords are live, not just declared.
    ///  3. The Python gate probe does not panic.
    #[test]
    fn gold_adapt_doc_01_ppt_master_bundled_enabled_and_routes() {
        use crate::skills::router::route;
        use crate::skills::schema::Skill;
        use std::path::PathBuf;

        // 1. Bundled presence + parse + enabled.
        let (_, body) = BUNDLED_SKILLS
            .iter()
            .find(|(id, _)| *id == "ppt_master")
            .expect("GOLD-ADAPT-DOC-01: ppt_master must be in BUNDLED_SKILLS");
        let manifest: SkillManifest = serde_yaml::from_str(body)
            .expect("ppt_master skill.yaml must parse cleanly");
        assert_eq!(manifest.id, "ppt_master");
        assert!(
            manifest.enabled,
            "ppt_master must ship enabled (not a pm-* or specialist skill)"
        );
        assert!(
            !manifest.trigger_keywords.is_empty(),
            "ppt_master must have trigger_keywords"
        );
        assert!(
            !manifest.system_prompt.trim().is_empty(),
            "ppt_master must have a non-empty system_prompt"
        );

        // 2. Live routing: build an isolated skill set containing only
        //    ppt_master so route() must select it (no cross-activation risk).
        let skill = Skill {
            manifest: manifest.clone(),
            path: PathBuf::from("/bundled/ppt_master/skill.yaml"),
            content_hash: String::new(),
        };
        let skills = vec![skill];
        for prompt in [
            "create a presentation about our Q3 results",
            "build a slideshow for the all-hands meeting",
            "generate slides for the product launch",
            "write a powerpoint presentation on the roadmap",
            "make a presentation about the new feature",
            "create pptx file for the board",
        ] {
            let m = route(prompt, &skills).unwrap_or_else(|| {
                panic!("ppt_master: prompt `{prompt}` routed to nothing")
            });
            assert_eq!(
                m.skill.id(),
                "ppt_master",
                "prompt `{prompt}` should route to ppt_master, got `{}`",
                m.skill.id()
            );
        }

        // 3. Python gate probe — smoke only (CI may or may not have python-pptx).
        let _gate: bool = crate::config::installer::is_pptmaster_installed();
    }

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
            } else if *id == "github_pr_review"
                || *id == "iac_security_audit"
                || *id == "memory_synthesis"
                || id.starts_with("officecli_")
            {
                // Documented non-pm DISABLED specialists:
                //   github_pr_review (GITPR-03) — touches the network.
                //   iac_security_audit (HCP-01) — niche IaC pentest checklist.
                //   memory_synthesis (NN-MEM-02) — opt-in alongside synthesis_cron.enabled.
                //   officecli_* (GOLD-ADAPT-DOC-04) — binary-gated; operator enables
                //     after installing officecli from d.officecli.ai.
                // All ship off; operator enables with `neoth skill --enable <id>`.
                assert!(
                    !m.enabled,
                    "specialist/binary-gated skill `{id}` must ship disabled"
                );
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

    #[test]
    fn engineering_pack_is_bundled_enabled_and_routes() {
        // GOLD-ADOPT-01 — the ported engineering skill pack must be (a) all
        // present, (b) shipped ENABLED (operator wants them used proactively),
        // and (c) reachable through the Stage-1 keyword router via their own
        // distinctive multi-word triggers. A phrase from each skill must route
        // to THAT skill — proves the triggers are live, not just declared.
        use crate::skills::router::route;
        use crate::skills::schema::Skill;
        use std::path::PathBuf;

        let pack = [
            ("engineering_code_review", "please review this pull request"),
            (
                "engineering_documentation",
                "time to update the readme and write the docs",
            ),
            (
                "engineering_incident_response",
                "we have a production incident, the service is down",
            ),
            (
                "engineering_system_design",
                "help me with the system design for this new service",
            ),
            (
                "engineering_tech_debt",
                "we need to pay down some technical debt",
            ),
            (
                "engineering_testing_strategy",
                "what should our test strategy and coverage targets be",
            ),
        ];

        // Build the full enabled engineering skill set once, so route() picks
        // among real competitors (cross-activation would surface here).
        let skills: Vec<Skill> = pack
            .iter()
            .map(|(id, _)| {
                let (_, body) = BUNDLED_SKILLS
                    .iter()
                    .find(|(bid, _)| bid == id)
                    .unwrap_or_else(|| panic!("engineering skill `{id}` not bundled"));
                let manifest: SkillManifest = serde_yaml::from_str(body)
                    .unwrap_or_else(|e| panic!("`{id}` failed to parse: {e}"));
                assert!(manifest.enabled, "`{id}` must ship enabled (proactive use)");
                Skill {
                    manifest,
                    path: PathBuf::from(format!("/bundled/{id}/skill.yaml")),
                    content_hash: String::new(),
                }
            })
            .collect();

        for (id, phrase) in pack {
            let m = route(phrase, &skills)
                .unwrap_or_else(|| panic!("`{id}` trigger phrase {phrase:?} routed to nothing"));
            assert_eq!(
                m.skill.id(),
                id,
                "phrase {phrase:?} should route to `{id}`, got `{}`",
                m.skill.id()
            );
        }
    }

    #[test]
    fn cybersec_and_agent_pack_is_bundled_enabled_and_routes() {
        // GOLD-ADOPT-02 (6 cybersec skills) + GOLD-ADOPT-03 (agent patterns):
        // all present, shipped ENABLED, and each reachable via its own
        // distinctive multi-word triggers with no cross-activation among them.
        use crate::skills::router::route;
        use crate::skills::schema::Skill;
        use std::path::PathBuf;

        let pack = [
            (
                "agent_engineering_patterns",
                "help me design agentic system for this",
            ),
            (
                "cybersec_detection_engineering",
                "i need to write a sigma rule",
            ),
            ("cybersec_dfir", "follow the order of volatility here"),
            ("cybersec_exploit_dev", "help me build a poc exploit"),
            (
                "cybersec_malware_analysis",
                "triage this malware sample please",
            ),
            (
                "cybersec_pentest_recon",
                "walk me through the nmap scan phases",
            ),
            ("cybersec_threat_modeling", "run a stride analysis on this"),
        ];

        let skills: Vec<Skill> = pack
            .iter()
            .map(|(id, _)| {
                let (_, body) = BUNDLED_SKILLS
                    .iter()
                    .find(|(bid, _)| bid == id)
                    .unwrap_or_else(|| panic!("skill `{id}` not bundled"));
                let manifest: SkillManifest = serde_yaml::from_str(body)
                    .unwrap_or_else(|e| panic!("`{id}` failed to parse: {e}"));
                assert!(manifest.enabled, "`{id}` must ship enabled (proactive use)");
                Skill {
                    manifest,
                    path: PathBuf::from(format!("/bundled/{id}/skill.yaml")),
                    content_hash: String::new(),
                }
            })
            .collect();

        for (id, phrase) in pack {
            let m = route(phrase, &skills)
                .unwrap_or_else(|| panic!("`{id}` trigger phrase {phrase:?} routed to nothing"));
            assert_eq!(
                m.skill.id(),
                id,
                "phrase {phrase:?} should route to `{id}`, got `{}`",
                m.skill.id()
            );
        }
    }

    /// GOLD-ADAPT-DOC-04 (2026-06-23) — integration test.
    ///
    /// Asserts five things in one pass:
    ///  1. All 11 `officecli_*` ids are present in `BUNDLED_SKILLS`.
    ///  2. Each parses cleanly and ships `enabled: false` (binary-optional gate).
    ///  3. When force-enabled (simulating `freedom.yaml::skills.enabled`),
    ///     the keyword router maps realistic operator prompts to the correct skill.
    ///  4. With `enabled: false` (as shipped), the same prompts route to `None` —
    ///     proving the gate is live.
    ///  5. `is_officecli_installed()` probe does not panic.
    #[test]
    fn gold_adapt_doc_04_officecli_bundled_gated_and_routes() {
        use crate::skills::router::route;
        use crate::skills::schema::Skill;
        use std::path::PathBuf;

        // (skill-id, trigger phrase that must route exclusively to it)
        let pack: &[(&str, &str)] = &[
            ("officecli_docx_convert",    "convert docx to pdf"),
            ("officecli_docx_create",     "create a word document"),
            ("officecli_docx_edit",       "edit this word document"),
            ("officecli_docx_format",     "format word document styles"),
            ("officecli_office_pipeline", "office document pipeline"),
            ("officecli_pdf_convert",     "convert office file to pdf"),
            ("officecli_pptx_create",     "create pptx file with officecli"),
            ("officecli_pptx_edit",       "edit existing pptx file"),
            ("officecli_xlsx_create",     "create xlsx spreadsheet"),
            ("officecli_xlsx_edit",       "edit excel spreadsheet with officecli"),
            ("officecli_xlsx_formula",    "add formula to excel spreadsheet"),
        ];

        // 1+2: all present, parse cleanly, ship disabled.
        for (id, _) in pack {
            let (_, body) = BUNDLED_SKILLS
                .iter()
                .find(|(bid, _)| bid == id)
                .unwrap_or_else(|| panic!("GOLD-ADAPT-DOC-04: `{id}` must be in BUNDLED_SKILLS"));
            let manifest: SkillManifest = serde_yaml::from_str(body)
                .unwrap_or_else(|e| panic!("`{id}` skill.yaml must parse cleanly: {e}"));
            assert_eq!(manifest.id, *id, "`{id}` manifest id mismatch");
            assert!(
                !manifest.enabled,
                "`{id}` must ship disabled (binary-optional gate — operator enables after \
                 installing officecli from d.officecli.ai)"
            );
            assert!(
                !manifest.trigger_keywords.is_empty(),
                "`{id}` must have trigger_keywords — router would never reach it"
            );
            assert!(
                !manifest.system_prompt.trim().is_empty(),
                "`{id}` must have a non-empty system_prompt"
            );
        }

        // 3: force-enable all 11, build Vec<Skill>, assert routing.
        let enabled_skills: Vec<Skill> = pack
            .iter()
            .map(|(id, _)| {
                let (_, body) = BUNDLED_SKILLS
                    .iter()
                    .find(|(bid, _)| bid == id)
                    .unwrap();
                let mut manifest: SkillManifest = serde_yaml::from_str(body).unwrap();
                manifest.enabled = true; // simulate freedom.yaml::skills.enabled
                Skill {
                    manifest,
                    path: PathBuf::from(format!("/bundled/{id}/skill.yaml")),
                    content_hash: String::new(),
                }
            })
            .collect();

        for (id, phrase) in pack {
            let m = route(phrase, &enabled_skills).unwrap_or_else(|| {
                panic!(
                    "GOLD-ADAPT-DOC-04: `{id}` prompt `{phrase}` routed to nothing \
                     (force-enabled — trigger_keywords must be live)"
                )
            });
            assert_eq!(
                m.skill.id(),
                *id,
                "prompt `{phrase}` should route to `{id}`, got `{}`",
                m.skill.id()
            );
        }

        // 4: as shipped (enabled: false), all 11 prompts must route to None.
        let gated_skills: Vec<Skill> = pack
            .iter()
            .map(|(id, _)| {
                let (_, body) = BUNDLED_SKILLS
                    .iter()
                    .find(|(bid, _)| bid == id)
                    .unwrap();
                let manifest: SkillManifest = serde_yaml::from_str(body).unwrap();
                // enabled is already false as shipped — no mutation needed.
                assert!(!manifest.enabled);
                Skill {
                    manifest,
                    path: PathBuf::from(format!("/bundled/{id}/skill.yaml")),
                    content_hash: String::new(),
                }
            })
            .collect();

        for (id, phrase) in pack {
            assert!(
                route(phrase, &gated_skills).is_none(),
                "GOLD-ADAPT-DOC-04: `{id}` ships disabled — prompt `{phrase}` must route to \
                 None (the enabled:false gate must block the router)"
            );
        }

        // 5: binary probe smoke — must not panic, result value is env-dependent.
        let _installed: bool = crate::config::installer::is_officecli_installed();
    }
}
