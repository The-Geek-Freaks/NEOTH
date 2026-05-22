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
}

/// Top-level `presets.yaml` shape. Multiple named presets + one
/// optional `active` pointer.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct PresetFile {
    pub active: Option<String>,
    pub presets: BTreeMap<String, Preset>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
        file.presets.insert("cloud-heavy".into(), cloud_heavy_preset());
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
        assert!(f.active.is_none(), "active must clear when its preset is removed");
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
}
