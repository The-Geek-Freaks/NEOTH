//! `neoth preset` — operator CLI surface for QM-8 provider preset
//! bundles. The Slint panel (Phase 2) consumes the same primitives.

use std::path::Path;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::config::presets;

#[derive(Args, Debug, Clone)]
pub struct PresetArgs {
    #[command(subcommand)]
    pub action: PresetAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PresetAction {
    /// List every saved preset + the active one (if any).
    List,
    /// Show one preset's full body as YAML.
    Show {
        name: String,
    },
    /// Remove a preset entry (idempotent — missing name is Ok).
    Delete {
        name: String,
    },
    /// Mark a preset as the active bundle. Future loads apply it.
    Activate {
        name: String,
    },
    /// Clear the active marker without deleting any preset.
    Deactivate,
    /// QM-8 Phase 1.5: merge a preset's values INTO `freedom.yaml`.
    /// Atomic write — survives a mid-write crash via `.tmp` + rename.
    /// Fields the preset doesn't set are left untouched in
    /// `freedom.yaml`, so manual edits between switches survive.
    Apply {
        name: String,
    },
}

pub fn run(home: &Path, args: PresetArgs) -> Result<()> {
    match args.action {
        PresetAction::List => run_list(home),
        PresetAction::Show { name } => run_show(home, &name),
        PresetAction::Delete { name } => run_delete(home, &name),
        PresetAction::Activate { name } => run_activate(home, &name),
        PresetAction::Deactivate => run_deactivate(home),
        PresetAction::Apply { name } => run_apply(home, &name),
    }
}

fn run_apply(home: &Path, name: &str) -> Result<()> {
    let report = presets::apply(home, name)?;
    if report.fields_changed.is_empty() {
        println!("applied preset `{name}` (no changes — preset was empty)");
    } else {
        println!("applied preset `{name}` ({} fields):", report.fields_changed.len());
        for f in &report.fields_changed {
            println!("  • {f}");
        }
    }
    Ok(())
}

fn run_list(home: &Path) -> Result<()> {
    let (names, active) = presets::list(home)?;
    if names.is_empty() {
        println!("(no presets — run `neoth preset --help` to see how to save one)");
        return Ok(());
    }
    for name in &names {
        let marker = if active.as_deref() == Some(name) {
            " *"
        } else {
            "  "
        };
        println!("{marker} {name}");
    }
    Ok(())
}

fn run_show(home: &Path, name: &str) -> Result<()> {
    let file = presets::load(home)?;
    let preset = file
        .presets
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("preset `{}` not found", name))?;
    let yaml = serde_yaml::to_string(preset)?;
    println!("{yaml}");
    Ok(())
}

fn run_delete(home: &Path, name: &str) -> Result<()> {
    if presets::remove(home, name)? {
        println!("removed preset `{name}`");
    } else {
        println!("preset `{name}` was not present (no-op)");
    }
    Ok(())
}

fn run_activate(home: &Path, name: &str) -> Result<()> {
    presets::set_active(home, name)?;
    println!("active preset → `{name}`");
    Ok(())
}

fn run_deactivate(home: &Path) -> Result<()> {
    if presets::clear_active(home)? {
        println!("active preset cleared");
    } else {
        println!("no active preset (no-op)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::presets::{upsert, Preset};
    use tempfile::tempdir;

    #[test]
    fn run_list_with_no_presets_prints_hint_without_error() {
        let dir = tempdir().unwrap();
        run_list(dir.path()).unwrap();
    }

    #[test]
    fn run_list_renders_active_marker() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), "frugal", Preset::default()).unwrap();
        upsert(dir.path(), "weekend", Preset::default()).unwrap();
        presets::set_active(dir.path(), "weekend").unwrap();
        // We don't capture stdout — smoke-only.
        run_list(dir.path()).unwrap();
    }

    #[test]
    fn run_show_existing_preset_succeeds() {
        let dir = tempdir().unwrap();
        upsert(
            dir.path(),
            "frugal",
            Preset {
                description: Some("test".into()),
                ..Default::default()
            },
        )
        .unwrap();
        run_show(dir.path(), "frugal").unwrap();
    }

    #[test]
    fn run_show_unknown_preset_errors() {
        let dir = tempdir().unwrap();
        let err = run_show(dir.path(), "ghost").unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn run_delete_unknown_is_noop() {
        let dir = tempdir().unwrap();
        run_delete(dir.path(), "ghost").unwrap();
    }

    #[test]
    fn run_activate_then_deactivate_roundtrip() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), "p", Preset::default()).unwrap();
        run_activate(dir.path(), "p").unwrap();
        let f = presets::load(dir.path()).unwrap();
        assert_eq!(f.active.as_deref(), Some("p"));
        run_deactivate(dir.path()).unwrap();
        let f = presets::load(dir.path()).unwrap();
        assert!(f.active.is_none());
    }
}
