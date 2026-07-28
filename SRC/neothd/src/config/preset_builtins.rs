//! ZF-01 — compiled-in preset bundles.
//!
//! NEOTH ships ~75 default-OFF feature flags; hand-toggling them is
//! DAU-hostile. These four built-ins bundle them into one choice:
//!
//!   - `full-auto`       broad automation on, $25/day cap, Full autonomy
//!                       (routed through the full-auto consent ceremony);
//!                       separate explicit-opt-in features stay off
//!   - `balanced`        background intelligence on, no cost/egress
//!                       surprises, $10/day cap
//!   - `essentials`      just chat, $5/day cap — enable things later
//!   - `local-sovereign` no cloud media, no model downloads, $0 cap
//!
//! Plain Rust constructors (not embedded YAML) so a malformed bundle is
//! a compile-time problem; the `builtin_*_apply_*` tests below apply
//! each one to a default config — the round-trip path validation in
//! [`super::presets`] turns any typo'd override path into a loud test
//! failure instead of a stealth no-op.
//!
//! NEVER in any built-in (per the security floor):
//!   - `sovereign_buddy`, `self_activation.*`, `security.*` (denylist),
//!   - `recursive_mas.enabled` (third-party sidecar — own ceremony),
//!   - `babel.federate` (only egress path — runtime consent gate),
//!   - listener/infra features that need operator config to be useful
//!     (webhook_manager, oai_serve, companion, cluster).
//!   - `dream.cron_enabled`: unattended Dream work is always a separate,
//!     explicit `neoth dream cron enable` operator decision.

use std::collections::BTreeMap;

use super::presets::Preset;

/// Names of the compiled-in presets, display order. Operator presets in
/// `presets.yaml` SHADOW a built-in of the same name (explicit wins).
pub const BUILTIN_NAMES: &[&str] = &["full-auto", "balanced", "essentials", "local-sovereign"];

/// Resolve a built-in by name. `None` for unknown names.
pub fn builtin_by_name(name: &str) -> Option<Preset> {
    match name {
        "full-auto" => Some(builtin_full_auto()),
        "balanced" => Some(builtin_balanced()),
        "essentials" => Some(builtin_essentials()),
        "local-sovereign" => Some(builtin_local_sovereign()),
        _ => None,
    }
}

fn on(paths: &[&str]) -> BTreeMap<String, serde_yaml::Value> {
    paths
        .iter()
        .map(|p| (p.to_string(), serde_yaml::Value::Bool(true)))
        .collect()
}

/// The "background intelligence" set: local-only automation with no
/// metered cost, no egress, no hardware requirement. Shared by
/// `balanced`, `full-auto` (superset) and `local-sovereign`.
const BACKGROUND_SET: &[&str] = &[
    "proactive.enabled",
    "checkin_cron.enabled",
    "guidance_cron.enabled",
    "synthesis_cron.enabled",
    "session_health.enabled",
    "watchdog.enabled",
    "monitor.enabled",
    "consolidation_sweep.enabled",
    "profile_adapt.enabled",
    "pattern_cron.enabled",
    "loop_config.enabled",
    "drift_alert.enabled",
    "token_anomaly.enabled",
    "recall_latency.enabled",
    "resource_watch.enabled",
    "regression_anchor.enabled",
    "session_sort_cron.enabled",
    "self_wiki.enabled",
    "self_improvement_collector.enabled",
    "contradiction_resolve.enabled",
    "auto_skill_extract.enabled",
    "skill_curator.enabled",
    "council.groundtruth_injection",
];

/// COST / egress-adjacent extras only `full-auto` flips (each lands in
/// the consent diff where warn-listed).
const FULL_AUTO_EXTRAS: &[&str] = &[
    "ecology.enabled",
    "kanban_sse.enabled",
    "arxiv.enabled",
    "arxiv_skill_scan.enabled",
    "email_ingest_cron.enabled",
    "media.dictation_enabled",
    "media.cloud_stt_enabled",
    "media.cloud_tts_enabled",
    "media.cloud_vision_enabled",
    "task_engine.decompose_non_coding",
];

/// Broad automation bundle. `autonomy: full` is NOT written directly — apply
/// reports it and the CLI/GUI routes through the full-auto ceremony
/// (`neoth autonomy full-auto`), which also enables the full bundled
/// skill library and emits the 0xDD sudomode audit anchor. Dream cron remains a
/// separate explicit opt-in.
pub fn builtin_full_auto() -> Preset {
    let mut overrides = on(BACKGROUND_SET);
    overrides.extend(on(FULL_AUTO_EXTRAS));
    Preset {
        description: Some(
            "Broad automation on, $25/day cap, full autonomy (asks once). \
             Dream cron remains a separate explicit opt-in."
                .into(),
        ),
        daily_usd_cap: Some(25.0),
        autonomy: Some("full".into()),
        overrides,
        ..Default::default()
    }
}

/// Background intelligence without cost/egress surprises.
pub fn builtin_balanced() -> Preset {
    Preset {
        description: Some(
            "Smart background features, no cost surprises. $10/day cap, standard autonomy.".into(),
        ),
        daily_usd_cap: Some(10.0),
        autonomy: Some("standard".into()),
        overrides: on(BACKGROUND_SET),
        ..Default::default()
    }
}

/// Fastest path to a working chat — nothing extra.
pub fn builtin_essentials() -> Preset {
    Preset {
        description: Some("Just chat. $5/day cap. Enable extras later in Settings.".into()),
        daily_usd_cap: Some(5.0),
        autonomy: Some("standard".into()),
        ..Default::default()
    }
}

/// Background intelligence, zero cloud spend, no model downloads, no
/// cloud media. For air-gapped / privacy-first operators.
pub fn builtin_local_sovereign() -> Preset {
    let mut overrides = on(BACKGROUND_SET);
    for path in [
        "updater.allow_huggingface_downloads",
        "media.cloud_stt_enabled",
        "media.cloud_tts_enabled",
        "media.cloud_vision_enabled",
        "media.video_frame_upload_enabled",
    ] {
        overrides.insert(path.to_string(), serde_yaml::Value::Bool(false));
    }
    Preset {
        description: Some(
            "No cloud media, no downloads, $0 cap. Local background intelligence only.".into(),
        ),
        daily_usd_cap: Some(0.0),
        autonomy: Some("elevated".into()),
        overrides,
        ..Default::default()
    }
}

/// One row of the merged `neoth preset list` view.
#[derive(Clone, Debug, PartialEq)]
pub struct PresetRow {
    pub name: String,
    pub builtin: bool,
    pub description: String,
}

/// Merged name list for `neoth preset list`: built-ins first (display
/// order), then operator presets (alphabetical, minus shadowed names).
pub fn list_all(home: &std::path::Path) -> anyhow::Result<(Vec<PresetRow>, Option<String>)> {
    let file = super::presets::load(home)?;
    let mut rows = Vec::new();
    for name in BUILTIN_NAMES {
        if file.presets.contains_key(*name) {
            continue; // operator preset shadows the built-in
        }
        rows.push(PresetRow {
            name: (*name).to_string(),
            builtin: true,
            description: builtin_by_name(name)
                .and_then(|p| p.description)
                .unwrap_or_default(),
        });
    }
    for (name, preset) in &file.presets {
        rows.push(PresetRow {
            name: name.clone(),
            builtin: false,
            description: preset.description.clone().unwrap_or_default(),
        });
    }
    Ok((rows, file.active))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::presets::{PRESET_DENYLIST_ROOTS, plan_apply, upsert};
    use tempfile::tempdir;

    #[test]
    fn every_builtin_name_resolves() {
        for name in BUILTIN_NAMES {
            let p = builtin_by_name(name).expect(name);
            assert!(p.description.is_some(), "{name} needs a description");
        }
        assert!(builtin_by_name("ghost").is_none());
    }

    #[test]
    fn builtins_round_trip_serde() {
        for name in BUILTIN_NAMES {
            let p = builtin_by_name(name).unwrap();
            let yaml = serde_yaml::to_string(&p).unwrap();
            let back: Preset = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(p, back, "{name} serde round-trip");
        }
    }

    /// The load-bearing test: applying each built-in to an EMPTY home
    /// exercises the full merge + the round-trip path validation — any
    /// typo'd override path fails HERE instead of being a stealth no-op
    /// in production.
    #[test]
    fn builtin_apply_plans_cleanly_and_paths_are_known() {
        for name in BUILTIN_NAMES {
            let dir = tempdir().unwrap();
            let p = builtin_by_name(name).unwrap();
            let (report, body) = plan_apply(dir.path(), &p)
                .unwrap_or_else(|e| panic!("built-in `{name}` failed to plan: {e}"));
            // The merged body must load as a valid FreedomConfig.
            let cfg: crate::config::FreedomConfig = serde_yaml::from_str(&body).unwrap();
            let _ = cfg;
            assert!(report.preset_applied, "{name}");
        }
    }

    #[test]
    fn full_auto_flips_the_flags_and_requests_ceremony() {
        let dir = tempdir().unwrap();
        let p = builtin_full_auto();
        let (report, body) = plan_apply(dir.path(), &p).unwrap();
        // Autonomy full must NOT be written — ceremony-routed.
        assert_eq!(report.autonomy_requested.as_deref(), Some("full"));
        assert!(!body.contains("autonomy: full"), "ceremony bypass!");
        let cfg: crate::config::FreedomConfig = serde_yaml::from_str(&body).unwrap();
        assert!(cfg.checkin_cron.enabled);
        assert!(cfg.proactive.enabled);
        assert!(
            !cfg.dreaming.enabled,
            "even full-auto must not imply unattended Dream work"
        );
        assert!(cfg.consolidation_sweep.enabled);
        assert!(cfg.council.groundtruth_injection);
        assert!(cfg.media.cloud_stt_enabled);
        assert!(cfg.task_engine.decompose_non_coding);
        // Cost cap is set + surfaced in the consent diff.
        assert!(body.contains("daily_usd_cap: 25"));
        assert!(
            report
                .warn_changes
                .iter()
                .any(|(p, _, _)| p == "media.cloud_stt_enabled"),
            "cloud media must land in the consent diff: {:?}",
            report.warn_changes
        );
        // Never touched by any built-in.
        assert!(!cfg.sovereign_buddy);
        assert!(!cfg.self_activation.enabled);
        assert!(!cfg.recursive_mas.enabled);
        assert!(!cfg.babel.federate);
    }

    #[test]
    fn local_sovereign_disables_downloads_and_cloud_media() {
        let dir = tempdir().unwrap();
        let (report, body) = plan_apply(dir.path(), &builtin_local_sovereign()).unwrap();
        let cfg: crate::config::FreedomConfig = serde_yaml::from_str(&body).unwrap();
        assert!(!cfg.updater.allow_huggingface_downloads);
        assert!(!cfg.media.cloud_stt_enabled);
        assert!(cfg.proactive.enabled, "background set still on");
        assert_eq!(report.autonomy_requested, None, "elevated writes directly");
        assert!(body.contains("autonomy: elevated"));
    }

    #[test]
    fn no_builtin_touches_denylist_roots() {
        for name in BUILTIN_NAMES {
            let p = builtin_by_name(name).unwrap();
            for key in p.overrides.keys() {
                let root = key.split('.').next().unwrap();
                assert!(
                    !PRESET_DENYLIST_ROOTS.contains(&root),
                    "built-in `{name}` override `{key}` hits the denylist"
                );
            }
        }
    }

    #[test]
    fn no_builtin_enables_dream_cron() {
        for name in BUILTIN_NAMES {
            let dir = tempdir().unwrap();
            let preset = builtin_by_name(name).unwrap();
            assert!(
                !preset.overrides.contains_key("dream.cron_enabled")
                    && !preset.overrides.contains_key("dreaming.enabled"),
                "built-in `{name}` must leave Dream cron to explicit operator opt-in"
            );
            let (_, body) = plan_apply(dir.path(), &preset).unwrap();
            let cfg: crate::config::FreedomConfig = serde_yaml::from_str(&body).unwrap();
            assert!(
                !cfg.dreaming.enabled,
                "built-in `{name}` implicitly enabled Dream cron"
            );
        }
    }

    #[test]
    fn operator_preset_shadows_builtin_in_list_and_resolve() {
        let dir = tempdir().unwrap();
        upsert(
            dir.path(),
            "full-auto",
            Preset {
                description: Some("mine".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let (rows, _) = list_all(dir.path()).unwrap();
        let hits: Vec<_> = rows.iter().filter(|r| r.name == "full-auto").collect();
        assert_eq!(hits.len(), 1, "shadowed built-in must not double-list");
        assert!(!hits[0].builtin, "the surviving row is the operator preset");
        let resolved = crate::config::presets::resolve(dir.path(), "full-auto").unwrap();
        assert_eq!(resolved.description.as_deref(), Some("mine"));
    }

    #[test]
    fn list_all_orders_builtins_first() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), "aaa-mine", Preset::default()).unwrap();
        let (rows, _) = list_all(dir.path()).unwrap();
        assert_eq!(rows[0].name, "full-auto");
        assert!(rows[0].builtin);
        assert_eq!(rows.last().unwrap().name, "aaa-mine");
        assert!(!rows.last().unwrap().builtin);
    }
}
