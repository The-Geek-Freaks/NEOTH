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
    /// ZF-01 — generic dotted-path overrides merged into `freedom.yaml`
    /// (e.g. `"checkin_cron.enabled" → true`). Lets a preset flip ANY
    /// config flag without per-field plumbing. Guard rails:
    ///   - [`PRESET_DENYLIST_ROOTS`] paths are refused at apply time
    ///     (autonomy/sovereign/self-activation/security/secrets).
    ///   - Unknown paths fail LOUD via a round-trip parse check —
    ///     `FreedomConfig` ignores unknown keys, so a typo'd path would
    ///     otherwise be a stealth no-op.
    ///   - `Value::Null` removes the key.
    pub overrides: BTreeMap<String, serde_yaml::Value>,
}

/// ZF-01 — top-level `freedom.yaml` keys a preset override may NEVER
/// touch. Escalation paths (autonomy/sovereign/self-activation) have
/// their own consent ceremonies; `security` is the policy gate itself;
/// the rest are secrets, identity, or code-execution vectors
/// (provider_binary/endpoint redirect, hook_chain shell commands).
pub const PRESET_DENYLIST_ROOTS: &[&str] = &[
    "autonomy",
    "sovereign_buddy",
    "self_activation",
    "security",
    "operator_id",
    "provider_kind",
    "provider_key",
    "provider_binary",
    "provider_endpoint",
    "telegram_token",
    "telegram_user_id",
    "hook_chain",
];

/// ZF-01 — paths whose change is security/cost/privacy-relevant: the
/// apply surface shows an explicit old→new consent diff before writing.
pub const PRESET_WARN_PATHS: &[&str] = &[
    "media.cloud_stt_enabled",
    "media.cloud_tts_enabled",
    "media.cloud_vision_enabled",
    "media.video_frame_upload_enabled",
    "recursive_mas.enabled",
    "proactive.enabled",
    "updater.allow_huggingface_downloads",
    "council.daily_usd_cap",
];

/// ZF-01 — `inject_prefix`/`inject_suffix` ceiling. An unbounded prefix
/// rides every user turn (token bloat + injection surface).
pub const MAX_INJECT_LEN: usize = 2000;

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
    // ZF-01 — built-ins are activatable too (they show up in `preset
    // list`); consumers of the active pointer resolve via [`resolve`],
    // which falls back to the compiled-in set.
    if !file.presets.contains_key(name)
        && super::preset_builtins::builtin_by_name(name).is_none()
    {
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
    let preset = resolve(home, name)?;
    apply_preset_to_freedom_yaml(home, &preset)
}

/// ZF-01 — resolve a preset name: operator presets in `presets.yaml`
/// SHADOW built-ins of the same name (explicit wins); unknown names
/// fall back to the compiled-in set.
pub fn resolve(home: &Path, name: &str) -> Result<Preset> {
    let file = load(home)?;
    if let Some(p) = file.presets.get(name) {
        return Ok(p.clone());
    }
    super::preset_builtins::builtin_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("preset `{}` not found", name))
}

/// ZF-01 — plan an apply WITHOUT writing: returns the report + the
/// merged YAML body. Callers show the consent diff, then hand the body
/// to [`commit_planned`]. `apply_preset_to_freedom_yaml` = plan+commit
/// in one step for non-interactive callers.
pub fn plan_apply(home: &Path, preset: &Preset) -> Result<(ApplyReport, String)> {
    plan_apply_inner(home, preset)
}

/// ZF-01 — atomically write a body produced by [`plan_apply`].
pub fn commit_planned(home: &Path, body: &str) -> Result<()> {
    let freedom_path = home.join("freedom.yaml");
    let tmp = freedom_path.with_extension("yaml.tmp");
    std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &freedom_path)
        .with_context(|| format!("rename {} → {}", tmp.display(), freedom_path.display()))?;
    Ok(())
}

/// Same as `apply` but takes an already-resolved `Preset` value.
/// Public for callers (Slint panel "save current state as preset
/// + apply", scripted apply paths) that work with a Preset they
/// constructed in-process.
pub fn apply_preset_to_freedom_yaml(home: &Path, preset: &Preset) -> Result<ApplyReport> {
    let (report, body) = plan_apply_inner(home, preset)?;
    commit_planned(home, &body)?;
    Ok(report)
}

fn plan_apply_inner(home: &Path, preset: &Preset) -> Result<(ApplyReport, String)> {
    // Guard rails BEFORE any merge work: denylist + inject ceilings.
    for key in preset.overrides.keys() {
        let root = key.split('.').next().unwrap_or(key);
        if PRESET_DENYLIST_ROOTS.contains(&root) {
            anyhow::bail!(
                "preset override `{key}` is security-critical and cannot be set via a \
                 preset — use the dedicated CLI command (e.g. `neoth autonomy`, \
                 `neoth self-activate`) instead"
            );
        }
    }
    for (label, v) in [
        ("inject_prefix", &preset.inject_prefix),
        ("inject_suffix", &preset.inject_suffix),
    ] {
        if let Some(s) = v {
            if s.len() > MAX_INJECT_LEN {
                anyhow::bail!(
                    "preset {label} is {} bytes — max {MAX_INJECT_LEN} (rides every user turn)",
                    s.len()
                );
            }
        }
    }

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
    // ZF-01 — snapshot warn-path values BEFORE any mutation (typed fields
    // AND overrides) so the consent diff shows the operator's true
    // old→new. Review wave 2026-07-04: snapshotting after the typed
    // daily_usd_cap write made cap changes invisible in the diff.
    let warn_before: Vec<Option<serde_yaml::Value>> = PRESET_WARN_PATHS
        .iter()
        .map(|p| lookup_dotted(mapping, p))
        .collect();
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
        if level == "full" {
            // ZF-01 — `full` is NEVER written directly: it must route
            // through the full-auto consent ceremony (`neoth autonomy
            // full-auto`, TTY confirm or GUI token). The caller reads
            // `autonomy_requested` and runs the ceremony after commit.
            report.autonomy_requested = Some(level.clone());
        } else {
            let was = mapping.insert(
                serde_yaml::Value::from("autonomy"),
                serde_yaml::Value::from(level.clone()),
            );
            if was != Some(serde_yaml::Value::from(level.clone())) {
                report.fields_changed.push("autonomy".into());
            }
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
    merge_overrides(mapping, &preset.overrides, &mut report)?;

    for (path, old) in PRESET_WARN_PATHS.iter().zip(warn_before) {
        let new = lookup_dotted(mapping, path);
        if new != old && preset_touches(preset, path) {
            report.warn_changes.push((
                (*path).to_string(),
                yaml_scalar_display(old.as_ref()),
                yaml_scalar_display(new.as_ref()),
            ));
        }
    }

    let body = serde_yaml::to_string(&root)?;
    // ZF-01 — fail LOUD on typo'd override paths: FreedomConfig ignores
    // unknown keys on load, so without this check a misspelled path is a
    // stealth no-op. Round-trip the merged body through FreedomConfig and
    // assert every override path survived.
    if !preset.overrides.is_empty() {
        validate_overrides_known(&body, &preset.overrides)?;
    }
    report.preset_applied = true;
    Ok((report, body))
}

/// ZF-01 — merge dotted-path overrides into the YAML mapping.
/// Intermediate mappings are created on demand; an existing NON-mapping
/// node on the path is a hard error (silent clobber would destroy
/// operator data); `Value::Null` removes the leaf key.
fn merge_overrides(
    mapping: &mut serde_yaml::Mapping,
    overrides: &BTreeMap<String, serde_yaml::Value>,
    report: &mut ApplyReport,
) -> Result<()> {
    for (path, value) in overrides {
        let segments: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
        let Some((leaf, parents)) = segments.split_last() else {
            anyhow::bail!("override path `{path}` is empty");
        };
        let mut cur = &mut *mapping;
        for seg in parents {
            let key = serde_yaml::Value::from(*seg);
            if !cur.contains_key(&key) {
                cur.insert(key.clone(), serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
            }
            cur = match cur.get_mut(&key) {
                Some(serde_yaml::Value::Mapping(m)) => m,
                Some(_) => anyhow::bail!(
                    "override path `{path}`: existing value at `{seg}` is not a mapping — \
                     refusing to overwrite"
                ),
                None => unreachable!("inserted above"),
            };
        }
        let leaf_key = serde_yaml::Value::from(*leaf);
        let changed = if value.is_null() {
            cur.remove(&leaf_key).is_some()
        } else {
            cur.insert(leaf_key, value.clone()) != Some(value.clone())
        };
        if changed {
            report.fields_changed.push(path.clone());
        }
    }
    Ok(())
}

/// Walk a dotted path through nested mappings; `None` when absent.
fn lookup_dotted(mapping: &serde_yaml::Mapping, path: &str) -> Option<serde_yaml::Value> {
    let mut cur = mapping;
    let segments: Vec<&str> = path.split('.').collect();
    let (leaf, parents) = segments.split_last()?;
    for seg in parents {
        cur = cur.get(serde_yaml::Value::from(*seg))?.as_mapping()?;
    }
    cur.get(serde_yaml::Value::from(*leaf)).cloned()
}

/// Whether this preset explicitly sets the given warn path (via the
/// overrides map or the typed `daily_usd_cap` field). Warn diffs only
/// fire for values the PRESET changed, not pre-existing operator state.
fn preset_touches(preset: &Preset, path: &str) -> bool {
    if preset.overrides.contains_key(path) {
        return true;
    }
    path == "council.daily_usd_cap" && preset.daily_usd_cap.is_some()
}

fn yaml_scalar_display(v: Option<&serde_yaml::Value>) -> String {
    match v {
        None => "(unset)".to_string(),
        Some(v) => serde_yaml::to_string(v)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "?".into()),
    }
}

/// ZF-01 — assert every override path survives a FreedomConfig
/// round-trip. Unknown keys are dropped by serde on load; a dropped
/// path means the preset author misspelled it.
fn validate_overrides_known(
    merged_yaml: &str,
    overrides: &BTreeMap<String, serde_yaml::Value>,
) -> Result<()> {
    let parsed: crate::config::FreedomConfig = serde_yaml::from_str(merged_yaml)
        .context("merged freedom.yaml no longer parses as FreedomConfig")?;
    let round_tripped =
        serde_yaml::to_value(&parsed).context("re-serialize FreedomConfig for path check")?;
    let rt_map = round_tripped
        .as_mapping()
        .context("round-tripped FreedomConfig is not a mapping")?;
    for (path, value) in overrides {
        // Removed keys can't be presence-checked after the round-trip.
        if value.is_null() {
            continue;
        }
        if lookup_dotted(rt_map, path).is_none() {
            anyhow::bail!(
                "override path `{path}` is not a known freedom.yaml field \
                 (check spelling) — refusing to write a stealth no-op"
            );
        }
    }
    Ok(())
}

/// Diff report from `apply()`. Surfaces what changed so the
/// CLI/UI shows a confirmation summary.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ApplyReport {
    pub preset_applied: bool,
    pub fields_changed: Vec<String>,
    /// ZF-01 — set when the preset asked for `autonomy: full`; the value
    /// is NOT written by apply — the caller runs the full-auto consent
    /// ceremony (`neoth autonomy full-auto`) after commit.
    pub autonomy_requested: Option<String>,
    /// ZF-01 — `(path, old, new)` for [`PRESET_WARN_PATHS`] this preset
    /// changed; surfaced as a consent diff before commit.
    pub warn_changes: Vec<(String, String, String)>,
}

fn ensure_council_block(mapping: &mut serde_yaml::Mapping) {
    // ZF-01 — only create the block when ABSENT; an existing non-mapping
    // value is left untouched (set_nested records the skip) instead of
    // being silently clobbered by an empty mapping.
    if !mapping.contains_key(serde_yaml::Value::from("council")) {
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
    // ZF-01 — a non-mapping value under `block` (malformed manual edit)
    // must not be silently replaced: preserve it and record the skip so
    // the operator sees WHY the field didn't change.
    if let Some(existing) = mapping.get(&block_key) {
        if !existing.is_mapping() {
            report
                .fields_changed
                .push(format!("{block}.{key} (SKIPPED: `{block}` is not a mapping)"));
            return;
        }
    }
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
