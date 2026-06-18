//! Provider preset bundles — QM-8 Phase 1.
//!
//! A "preset" is a named bundle of operator-tweakable settings that
//! can be loaded as a single atomic change instead of editing a
//! dozen `freedom.yaml` keys by hand. Typical use cases:
//!
//!   - "cloud-heavy"      Anthropic on Right, OpenAI on Left,
//!                        local_qwen on Cerebellum, $10/day cap.
//!   - "fully-local"      local_qwen everywhere, $0 cap, Eur display.
//!   - "frugal"           Haiku + GPT-4o-mini bound, $1 cap.
//!   - "weekend-deep"     Opus on Right, expanded recursion depth,
//!                        $25 cap.
//!
//! Storage: `~/.neoth/presets.yaml`. Multiple presets, one of them
//! optionally marked as `active`. The active preset's values are
//! merged INTO `freedom.yaml` on load — operator's edits to
//! freedom.yaml between preset switches survive (manual edits are
//! upstream of preset overrides for fields the preset doesn't set).
//!
//! Apply semantics: `apply(name, home)` merges the named preset's
//! values into the current freedom.yaml + writes it back atomically.
//! Fields the preset doesn't set are left untouched. Mutually
//! exclusive with the Slint panel's "preset save" path that snaps
//! the current freedom.yaml into a new preset entry.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One named preset bundle. Every field is optional so the operator
/// can scope a preset narrowly (e.g. only swap hemisphere bindings)
/// without forcing them to set every knob.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Preset {
    /// Operator-readable description for `neoth preset list`.
    pub description: Option<String>,
    /// Per-role provider id. Keys: `left` / `right` / `cerebellum`.
    pub hemispheres: BTreeMap<String, String>,
    /// Per-role model id (overrides the hemisphere default). Keys
    /// mirror `hemispheres`.
    pub models: BTreeMap<String, String>,
    /// Daily spend ceiling — USD canonical (gate-stable across
    /// `usage_currency` switches).
    pub daily_usd_cap: Option<f64>,
    /// Display currency for `neoth usage` + GUI dashboard. USD if
    /// unset (the in-process default lives in Currency::default).
    pub usage_currency: Option<String>,
    /// Council recursion depth ceiling. Defaults to 2 in spec.
    pub max_recursion_depth: Option<u32>,
    /// Per-message call cap. Defaults to 15 in spec.
    pub max_calls_per_user_message: Option<u32>,
    /// Council selection mode (`legacy_majority` / `consensus_or_best`).
    pub selection_mode: Option<String>,
    /// Autonomy level (`strict` / `standard` / `elevated` / `full`).
    /// When set, takes effect after `apply()` — operator confirms
    /// via the autonomy gate's normal flow.
    pub autonomy: Option<String>,
    /// ODY-27 — text prepended to every USER message while this preset is
    /// active (e.g. an output-format directive). `None`/empty = no prefix.
    /// Per-message wrap, NOT a system-prompt layer — keeps the system prompt
    /// clean + prefix-cache-friendly while still steering output shape.
    pub inject_prefix: Option<String>,
    /// ODY-27 — text appended to every USER message while this preset is
    /// active. `None`/empty = no suffix.
    pub inject_suffix: Option<String>,
}

/// Top-level `presets.yaml` shape. Multiple named presets + one
/// optional `active` pointer.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct PresetFile {
    pub active: Option<String>,
    pub presets: BTreeMap<String, Preset>,
}

/// ODY-27 — wrap a user message with the active preset's `inject_prefix` /
/// `inject_suffix` (per-message, NOT a system-prompt layer). When both are
/// `None`/empty the original prompt is returned borrowed (zero-copy). Each
/// injected directive is separated from the message by a blank line so it
/// reads as its own paragraph.
pub fn wrap_user_prompt<'a>(prompt: &'a str, preset: &Preset) -> std::borrow::Cow<'a, str> {
    let prefix = preset.inject_prefix.as_deref().filter(|s| !s.is_empty());
    let suffix = preset.inject_suffix.as_deref().filter(|s| !s.is_empty());
    match (prefix, suffix) {
        (None, None) => std::borrow::Cow::Borrowed(prompt),
        (p, s) => {
            let mut out = String::new();
            if let Some(p) = p {
                out.push_str(p);
                out.push_str("\n\n");
            }
            out.push_str(prompt);
            if let Some(s) = s {
                out.push_str("\n\n");
                out.push_str(s);
            }
            std::borrow::Cow::Owned(out)
        }
    }
}

/// Default path: `<neoth_home>/presets.yaml`.
pub fn default_path(home: &Path) -> PathBuf {
    home.join("presets.yaml")
}

/// Read the preset file. Missing → empty default. Malformed YAML is
/// a hard error — silent fallback would mask a typo that hides
/// every operator preset.
pub fn load(home: &Path) -> Result<PresetFile> {
    let path = default_path(home);
    if !path.exists() {
        return Ok(PresetFile::default());
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("read presets at {}", path.display()))?;
    let file: PresetFile = serde_yaml::from_str(&body)
        .with_context(|| format!("parse presets YAML at {}", path.display()))?;
    Ok(file)
}

/// Write the preset file atomically. Atomic = write to `<path>.tmp`
/// then rename — survives a crash mid-write without leaving a
/// half-written presets.yaml.
pub fn save(home: &Path, file: &PresetFile) -> Result<()> {
    let path = default_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create presets dir {}", parent.display()))?;
    }
    let tmp = path.with_extension("yaml.tmp");
    let body = serde_yaml::to_string(file).with_context(|| "serialize presets YAML")?;
    std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

/// List every preset's name (sorted alphabetically) + the active one.
pub fn list(home: &Path) -> Result<(Vec<String>, Option<String>)> {
    let file = load(home)?;
    let names: Vec<String> = file.presets.keys().cloned().collect();
    Ok((names, file.active))
}

/// Add or overwrite a preset entry.
pub fn upsert(home: &Path, name: &str, preset: Preset) -> Result<()> {
    let mut file = load(home)?;
    file.presets.insert(name.to_string(), preset);
    save(home, &file)
}

/// Remove a preset. `Ok(false)` when the name was absent (idempotent).
pub fn remove(home: &Path, name: &str) -> Result<bool> {
    let mut file = load(home)?;
    let existed = file.presets.remove(name).is_some();
    // Clear `active` if it pointed to the removed entry.
    if file.active.as_deref() == Some(name) {
        file.active = None;
    }
    if existed {
        save(home, &file)?;
    }
    Ok(existed)
}

/// Mark a preset as `active`. Returns error when the name doesn't
/// exist — silently activating a non-existent preset would be a
/// stealth no-op.
pub fn set_active(home: &Path, name: &str) -> Result<()> {
    let mut file = load(home)?;
    if !file.presets.contains_key(name) {
        anyhow::bail!("preset `{}` not found", name);
    }
    file.active = Some(name.to_string());
    save(home, &file)
}

/// Clear the active marker. Idempotent; `Ok(false)` when nothing
/// was active.
pub fn clear_active(home: &Path) -> Result<bool> {
    let mut file = load(home)?;
    let had = file.active.is_some();
    file.active = None;
    if had {
        save(home, &file)?;
    }
    Ok(had)
}

/// Apply a named preset's values INTO `freedom.yaml`. Atomic merge
/// (read → mutate → write `.tmp` → rename). Fields the preset
/// doesn't set are left untouched — operator manual edits between
/// preset switches survive for the un-set fields.
///
/// Returns the report of what was changed so the CLI/UI can show
/// the operator a confirmation diff. Side effect: writes
/// `~/.neoth/freedom.yaml` atomically.
///
/// The merge target uses a `serde_yaml::Value` walk so the daemon
/// doesn't need to know every field the preset can touch — adding
/// a new preset knob in `Preset` doesn't require updating apply
/// logic, just round-trips through YAML.
pub fn apply(home: &Path, name: &str) -> Result<ApplyReport> {
    let file = load(home)?;
    let preset = file
        .presets
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("preset `{}` not found", name))?
        .clone();
    apply_preset_to_freedom_yaml(home, &preset)
}

/// Same as `apply` but takes an already-resolved `Preset` value.
/// Public for callers (Slint panel "save current state as preset
/// + apply", scripted apply paths) that work with a Preset they
/// constructed in-process.
pub fn apply_preset_to_freedom_yaml(home: &Path, preset: &Preset) -> Result<ApplyReport> {
    let freedom_path = home.join("freedom.yaml");
    let original = if freedom_path.exists() {
        std::fs::read_to_string(&freedom_path)
            .with_context(|| format!("read {}", freedom_path.display()))?
    } else {
        String::new()
    };
    let mut root: serde_yaml::Value = if original.is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&original)
            .with_context(|| format!("parse {}", freedom_path.display()))?
    };
    let mapping = match &mut root {
        serde_yaml::Value::Mapping(m) => m,
        _ => anyhow::bail!("freedom.yaml is not a YAML mapping"),
    };
    let mut report = ApplyReport::default();
    if let Some(cap) = preset.daily_usd_cap {
        ensure_council_block(mapping);
        set_nested(mapping, "council", "daily_usd_cap", &mut report, |m, k| {
            insert_value(m, k, serde_yaml::Value::from(cap));
        });
    }
    if let Some(currency) = preset.usage_currency.as_ref() {
        let was = mapping.insert(
            serde_yaml::Value::from("usage_currency"),
            serde_yaml::Value::from(currency.clone()),
        );
        if was != Some(serde_yaml::Value::from(currency.clone())) {
            report.fields_changed.push("usage_currency".into());
        }
    }
    if let Some(depth) = preset.max_recursion_depth {
        ensure_council_block(mapping);
        set_nested(
            mapping,
            "council",
            "max_recursion_depth",
            &mut report,
            |m, k| {
                insert_value(m, k, serde_yaml::Value::from(depth));
            },
        );
    }
    if let Some(calls) = preset.max_calls_per_user_message {
        ensure_council_block(mapping);
        set_nested(
            mapping,
            "council",
            "max_calls_per_user_message",
            &mut report,
            |m, k| {
                insert_value(m, k, serde_yaml::Value::from(calls));
            },
        );
    }
    if let Some(mode) = preset.selection_mode.as_ref() {
        ensure_council_block(mapping);
        set_nested(mapping, "council", "selection_mode", &mut report, |m, k| {
            insert_value(m, k, serde_yaml::Value::from(mode.clone()));
        });
    }
    if let Some(level) = preset.autonomy.as_ref() {
        let was = mapping.insert(
            serde_yaml::Value::from("autonomy"),
            serde_yaml::Value::from(level.clone()),
        );
        if was != Some(serde_yaml::Value::from(level.clone())) {
            report.fields_changed.push("autonomy".into());
        }
    }
    if !preset.hemispheres.is_empty() || !preset.models.is_empty() {
        let mut inference_mapping = match mapping
            .get(serde_yaml::Value::from("inference"))
            .and_then(|v| v.as_mapping())
        {
            Some(m) => m.clone(),
            None => serde_yaml::Mapping::new(),
        };
        for (role, provider) in &preset.hemispheres {
            let role_key = serde_yaml::Value::from(role.clone());
            let mut role_mapping = inference_mapping
                .get(&role_key)
                .and_then(|v| v.as_mapping())
                .cloned()
                .unwrap_or_default();
            role_mapping.insert(
                serde_yaml::Value::from("provider"),
                serde_yaml::Value::from(provider.clone()),
            );
            if let Some(model) = preset.models.get(role) {
                role_mapping.insert(
                    serde_yaml::Value::from("model"),
                    serde_yaml::Value::from(model.clone()),
                );
            }
            inference_mapping.insert(role_key, serde_yaml::Value::Mapping(role_mapping));
            report.fields_changed.push(format!("inference.{role}"));
        }
        mapping.insert(
            serde_yaml::Value::from("inference"),
            serde_yaml::Value::Mapping(inference_mapping),
        );
    }
    // Atomic write — same .tmp + rename pattern as save().
    let tmp = freedom_path.with_extension("yaml.tmp");
    let body = serde_yaml::to_string(&root)?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &freedom_path)?;
    report.preset_applied = true;
    Ok(report)
}

/// Diff report from `apply()`. Surfaces what changed so the
/// CLI/UI shows a confirmation summary.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ApplyReport {
    pub preset_applied: bool,
    pub fields_changed: Vec<String>,
}

fn ensure_council_block(mapping: &mut serde_yaml::Mapping) {
    if mapping
        .get(serde_yaml::Value::from("council"))
        .and_then(|v| v.as_mapping())
        .is_none()
    {
        mapping.insert(
            serde_yaml::Value::from("council"),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }
}

fn set_nested<F: FnOnce(&mut serde_yaml::Mapping, &str)>(
    mapping: &mut serde_yaml::Mapping,
    block: &str,
    key: &str,
    report: &mut ApplyReport,
    mutate: F,
) {
    let block_key = serde_yaml::Value::from(block);
    let mut inner = mapping
        .get(&block_key)
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    mutate(&mut inner, key);
    mapping.insert(block_key, serde_yaml::Value::Mapping(inner));
    report.fields_changed.push(format!("{block}.{key}"));
}

fn insert_value(mapping: &mut serde_yaml::Mapping, key: &str, value: serde_yaml::Value) {
    mapping.insert(serde_yaml::Value::from(key), value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn wrap_user_prompt_injects_prefix_and_suffix() {
        // ODY-27: prefix prepended + suffix appended, each its own paragraph;
        // None/empty are no-ops (zero-copy borrow when both absent).
        let plain = Preset::default();
        assert!(
            matches!(
                wrap_user_prompt("hi", &plain),
                std::borrow::Cow::Borrowed(_)
            ),
            "no-inject must be zero-copy"
        );
        assert_eq!(wrap_user_prompt("hi", &plain), "hi");

        let pref = Preset {
            inject_prefix: Some("Answer in JSON.".into()),
            ..Default::default()
        };
        assert_eq!(
            wrap_user_prompt("list colours", &pref),
            "Answer in JSON.\n\nlist colours"
        );

        let suf = Preset {
            inject_suffix: Some("Be terse.".into()),
            ..Default::default()
        };
        assert_eq!(
            wrap_user_prompt("explain x", &suf),
            "explain x\n\nBe terse."
        );

        let both = Preset {
            inject_prefix: Some("P".into()),
            inject_suffix: Some("S".into()),
            ..Default::default()
        };
        assert_eq!(wrap_user_prompt("M", &both), "P\n\nM\n\nS");

        // Empty strings count as absent — no spurious blank lines.
        let empty = Preset {
            inject_prefix: Some(String::new()),
            inject_suffix: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(wrap_user_prompt("m", &empty), "m");
    }

    fn cloud_heavy_preset() -> Preset {
        let mut hemis = BTreeMap::new();
        hemis.insert("left".into(), "openai_api".into());
        hemis.insert("right".into(), "claude_cli".into());
        hemis.insert("cerebellum".into(), "local_qwen".into());
        Preset {
            description: Some("Anthropic + OpenAI cloud, local Cerebellum".into()),
            hemispheres: hemis,
            daily_usd_cap: Some(10.0),
            usage_currency: Some("USD".into()),
            max_recursion_depth: Some(2),
            max_calls_per_user_message: Some(15),
            ..Default::default()
        }
    }

    #[test]
    fn load_missing_file_returns_empty_default() {
        let dir = tempdir().unwrap();
        let file = load(dir.path()).unwrap();
        assert!(file.presets.is_empty());
        assert!(file.active.is_none());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempdir().unwrap();
        let mut file = PresetFile::default();
        file.presets
            .insert("cloud-heavy".into(), cloud_heavy_preset());
        file.active = Some("cloud-heavy".into());
        save(dir.path(), &file).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded, file);
    }

    #[test]
    fn upsert_adds_new_preset() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), "frugal", Preset::default()).unwrap();
        let (names, _) = list(dir.path()).unwrap();
        assert_eq!(names, vec!["frugal"]);
    }

    #[test]
    fn upsert_overwrites_existing_preset() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), "p", Preset::default()).unwrap();
        let new = Preset {
            description: Some("updated".into()),
            ..Default::default()
        };
        upsert(dir.path(), "p", new.clone()).unwrap();
        let f = load(dir.path()).unwrap();
        assert_eq!(f.presets.get("p"), Some(&new));
    }

    #[test]
    fn list_returns_sorted_names_and_active_marker() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), "zeta", Preset::default()).unwrap();
        upsert(dir.path(), "alpha", Preset::default()).unwrap();
        upsert(dir.path(), "middle", Preset::default()).unwrap();
        set_active(dir.path(), "middle").unwrap();
        let (names, active) = list(dir.path()).unwrap();
        assert_eq!(names, vec!["alpha", "middle", "zeta"]);
        assert_eq!(active.as_deref(), Some("middle"));
    }

    #[test]
    fn remove_is_idempotent_and_clears_active_when_matched() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), "p", Preset::default()).unwrap();
        set_active(dir.path(), "p").unwrap();
        assert!(remove(dir.path(), "p").unwrap());
        let f = load(dir.path()).unwrap();
        assert!(f.presets.is_empty());
        assert!(
            f.active.is_none(),
            "active must clear when its preset is removed"
        );
        // Removing again is Ok(false).
        assert!(!remove(dir.path(), "p").unwrap());
    }

    #[test]
    fn set_active_errors_when_name_missing() {
        let dir = tempdir().unwrap();
        let err = set_active(dir.path(), "ghost").unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn clear_active_is_idempotent() {
        let dir = tempdir().unwrap();
        assert!(!clear_active(dir.path()).unwrap());
        upsert(dir.path(), "p", Preset::default()).unwrap();
        set_active(dir.path(), "p").unwrap();
        assert!(clear_active(dir.path()).unwrap());
        let f = load(dir.path()).unwrap();
        assert!(f.active.is_none());
    }

    #[test]
    fn save_uses_atomic_rename() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), "p", Preset::default()).unwrap();
        // No `.tmp` should be left behind.
        let tmp = default_path(dir.path()).with_extension("yaml.tmp");
        assert!(!tmp.exists());
    }

    #[test]
    fn preset_serde_skips_unset_fields() {
        let preset = Preset {
            description: Some("just description".into()),
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&preset).unwrap();
        // Optional fields with None/empty should render compactly.
        assert!(yaml.contains("description"));
        // Models map is empty → still serialised as `models: {}` since
        // `#[serde(default)]` keeps the field. Pin the contract so a
        // YAML hand-edit knows what to expect.
        assert!(yaml.contains("models:"));
    }

    #[test]
    fn malformed_yaml_is_hard_error() {
        let dir = tempdir().unwrap();
        std::fs::write(default_path(dir.path()), ": : :\n").unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn apply_creates_freedom_yaml_when_missing() {
        let dir = tempdir().unwrap();
        let preset = Preset {
            daily_usd_cap: Some(7.5),
            usage_currency: Some("EUR".into()),
            ..Default::default()
        };
        upsert(dir.path(), "test", preset).unwrap();
        let report = apply(dir.path(), "test").unwrap();
        assert!(report.preset_applied);
        assert!(
            report
                .fields_changed
                .contains(&"usage_currency".to_string())
        );
        assert!(
            report
                .fields_changed
                .contains(&"council.daily_usd_cap".to_string())
        );
        let body = std::fs::read_to_string(dir.path().join("freedom.yaml")).unwrap();
        assert!(body.contains("usage_currency: EUR"));
        assert!(body.contains("daily_usd_cap: 7.5"));
    }

    #[test]
    fn apply_preserves_unmentioned_fields() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "operator_id: sam\nprovider_kind: claude_cli\n",
        )
        .unwrap();
        let preset = Preset {
            daily_usd_cap: Some(2.0),
            ..Default::default()
        };
        apply_preset_to_freedom_yaml(dir.path(), &preset).unwrap();
        let body = std::fs::read_to_string(dir.path().join("freedom.yaml")).unwrap();
        assert!(body.contains("operator_id: sam"));
        assert!(body.contains("provider_kind: claude_cli"));
        assert!(body.contains("daily_usd_cap: 2"));
    }

    #[test]
    fn apply_merges_hemisphere_bindings() {
        let dir = tempdir().unwrap();
        let mut hemis = BTreeMap::new();
        hemis.insert("left".into(), "openai_api".into());
        hemis.insert("right".into(), "claude_cli".into());
        let mut models = BTreeMap::new();
        models.insert("left".into(), "gpt-5.5".into());
        let preset = Preset {
            hemispheres: hemis,
            models,
            ..Default::default()
        };
        let report = apply_preset_to_freedom_yaml(dir.path(), &preset).unwrap();
        assert!(
            report
                .fields_changed
                .contains(&"inference.left".to_string())
        );
        assert!(
            report
                .fields_changed
                .contains(&"inference.right".to_string())
        );
        let body = std::fs::read_to_string(dir.path().join("freedom.yaml")).unwrap();
        assert!(body.contains("inference:"));
        assert!(body.contains("openai_api"));
        assert!(body.contains("claude_cli"));
        assert!(body.contains("gpt-5.5"));
    }

    #[test]
    fn apply_unknown_preset_errors() {
        let dir = tempdir().unwrap();
        let err = apply(dir.path(), "ghost").unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn apply_atomic_no_tmp_left() {
        let dir = tempdir().unwrap();
        let preset = Preset {
            usage_currency: Some("USD".into()),
            ..Default::default()
        };
        apply_preset_to_freedom_yaml(dir.path(), &preset).unwrap();
        let tmp = dir.path().join("freedom.yaml.tmp");
        assert!(!tmp.exists());
    }
}
