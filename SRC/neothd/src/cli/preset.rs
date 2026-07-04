//! `neoth preset` — operator CLI surface for QM-8 provider preset
//! bundles. The Slint panel (Phase 2) consumes the same primitives.

use std::path::Path;

use anyhow::{Context, Result};
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
    List {
        /// Emit machine-readable JSON (`{presets:[{name,active}], active}`) —
        /// consumed by the GUI preset selector (SPEC-05). Default: a table.
        #[arg(long)]
        json: bool,
    },
    /// Show one preset's full body as YAML.
    Show { name: String },
    /// Remove a preset entry (idempotent — missing name is Ok).
    Delete { name: String },
    /// Mark a preset as the active bundle. Future loads apply it.
    Activate { name: String },
    /// Clear the active marker without deleting any preset.
    Deactivate,
    /// QM-8 Phase 1.5: merge a preset's values INTO `freedom.yaml`.
    /// Atomic write — survives a mid-write crash via `.tmp` + rename.
    /// Fields the preset doesn't set are left untouched in
    /// `freedom.yaml`, so manual edits between switches survive.
    /// Built-in bundles (full-auto / balanced / essentials /
    /// local-sovereign) apply the same way; security-relevant changes
    /// show a consent diff first.
    Apply {
        name: String,
        /// Skip the consent-diff confirmation (scripted applies).
        #[arg(long)]
        yes: bool,
        /// Print the apply plan as JSON WITHOUT writing anything —
        /// the GUI renders its consent modal from this.
        #[arg(long)]
        dry_run: bool,
        /// GUI ceremony pass-through for presets that request
        /// `autonomy: full` (see `neoth autonomy full-auto`).
        #[arg(long, hide = true)]
        gui_confirmed: bool,
        /// Daemon-minted single-use token accompanying --gui-confirmed.
        #[arg(long, hide = true)]
        gui_token: Option<String>,
    },
}

pub async fn run(home: &Path, args: PresetArgs) -> Result<()> {
    match args.action {
        PresetAction::List { json } => run_list(home, json),
        PresetAction::Show { name } => run_show(home, &name),
        PresetAction::Delete { name } => run_delete(home, &name),
        PresetAction::Activate { name } => run_activate(home, &name),
        PresetAction::Deactivate => run_deactivate(home),
        PresetAction::Apply {
            name,
            yes,
            dry_run,
            gui_confirmed,
            gui_token,
        } => run_apply(home, &name, yes, dry_run, gui_confirmed, gui_token).await,
    }
}

async fn run_apply(
    home: &Path,
    name: &str,
    yes: bool,
    dry_run: bool,
    gui_confirmed: bool,
    gui_token: Option<String>,
) -> Result<()> {
    let preset = presets::resolve(home, name)?;
    let (report, body) = presets::plan_apply(home, &preset)?;

    if dry_run {
        // GUI consent-modal feed: full plan, nothing written.
        println!("{}", apply_report_json(name, &report));
        return Ok(());
    }

    // ZF-01 — consent diff BEFORE anything is written. `--yes` skips;
    // non-TTY without --yes fails closed (a cron must not silently flip
    // cloud-media/cost flags).
    if !report.warn_changes.is_empty() && !yes && !gui_confirmed {
        use std::io::{IsTerminal, Write};
        eprintln!("preset `{name}` changes security/cost-relevant settings:");
        for (path, old, new) in &report.warn_changes {
            eprintln!("  • {path}: {old} → {new}");
        }
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "refusing to apply without confirmation (stdin is not a terminal) — \
                 re-run with --yes to accept the changes above"
            );
        }
        eprint!("Apply? [y/N]: ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("read apply confirmation")?;
        let ans = line.trim().to_ascii_lowercase();
        if ans != "y" && ans != "yes" {
            anyhow::bail!("aborted: preset `{name}` not applied");
        }
    }

    // P1 — fail-closed: a preset can change provider / cloud-fallback / rail /
    // autonomy-adjacent fields, so under `required_for_oneshot_permission_events`
    // the apply REFUSES if the `0xDA PRESET_APPLIED` audit cannot be written
    // (live daemon + unreachable audit-RPC listener). Identical contract to the
    // external-task-write gate.
    let cfg = crate::config::FreedomConfig::load_from_default_path().unwrap_or_default();
    let audit_home = crate::config::FreedomConfig::default_neoth_home();
    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile()),
        Ok(Some(_))
    );
    crate::daemon::audit_rpc::enforce_required_audit(
        cfg.audit_rpc.required_for_oneshot_permission_events,
        daemon_live,
        &audit_home,
    )
    .context("preset apply refused: required audit cannot be written")?;

    // ZF-01 (review wave 2026-07-04) — the full-auto ceremony runs BEFORE
    // commit: an aborted ceremony must leave NOTHING applied (previously
    // the feature flags were already committed + the reload sentinel
    // fired when the operator answered `n`). The ceremony writes
    // autonomy + skills.enable_all_bundled itself, so the plan is
    // recomputed on the post-ceremony freedom.yaml — otherwise the
    // commit would clobber the ceremony's writes with the stale body.
    let body = if report.autonomy_requested.as_deref() == Some("full") {
        crate::cli::autonomy::run_autonomy(
            crate::cli::autonomy::AutonomyArgs {
                action: crate::cli::autonomy::AutonomyAction::FullAuto {
                    gui_confirmed,
                    gui_token,
                },
            },
            crate::cli::OutputFormat::Table,
        )
        .await
        .context("FULL-AUTO was not enabled — preset NOT applied")?;
        let (_report2, body2) = presets::plan_apply(home, &preset)?;
        body2
    } else {
        body
    };

    presets::commit_planned(home, &body)?;

    // P1 — durable record: WHICH preset, WHICH field NAMES changed (never the
    // values), from WHICH surface. One-shot-writer-or-audit-RPC path.
    let now = crate::time::now_unix_secs();
    let payload = serde_json::to_vec(&serde_json::json!({
        "name": name,
        "fields_changed": report.fields_changed,
        "source": "cli",
        "ts_unix": now,
    }))
    .unwrap_or_default();
    crate::cli::todo::emit_oneshot_audit(
        crate::wal::events::EVENT_TYPE_PRESET_APPLIED,
        payload,
        "PRESET_APPLIED",
    )
    .await;

    if report.fields_changed.is_empty() && report.autonomy_requested.is_none() {
        println!("applied preset `{name}` (no changes — preset was empty)");
    } else {
        println!(
            "applied preset `{name}` ({} fields):",
            report.fields_changed.len()
        );
        for f in &report.fields_changed {
            println!("  • {f}");
        }
    }

    // ZF-01 — nudge the running daemon's reload poller (best-effort; the
    // daemon may not be running).
    let sentinel = audit_home.join(crate::config::reload::RELOAD_SENTINEL_NAME);
    let _ = std::fs::write(&sentinel, b"preset-apply");
    let cron_flips = report
        .fields_changed
        .iter()
        .filter(|f| f.ends_with(".enabled"))
        .count();
    if cron_flips > 0 {
        println!(
            "note: {cron_flips} background task(s) start on the next daemon (re)start — \
             live settings apply within ~2s via the reload poller."
        );
    }

    Ok(())
}

/// JSON plan for `--dry-run` (GUI consent modal). PURE.
fn apply_report_json(name: &str, report: &crate::config::presets::ApplyReport) -> String {
    serde_json::json!({
        "name": name,
        "fields_changed": report.fields_changed,
        "autonomy_requested": report.autonomy_requested,
        "warn_changes": report
            .warn_changes
            .iter()
            .map(|(p, old, new)| serde_json::json!({"path": p, "old": old, "new": new}))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

fn run_list(home: &Path, json: bool) -> Result<()> {
    let (rows, active) = crate::config::preset_builtins::list_all(home)?;
    if json {
        println!("{}", preset_list_json(&rows, active.as_deref()));
        return Ok(());
    }
    for row in &rows {
        let marker = if active.as_deref() == Some(row.name.as_str()) {
            "*"
        } else {
            " "
        };
        let tag = if row.builtin { "[built-in]" } else { "[yours]   " };
        println!("{marker} {:<16} {tag}  {}", row.name, row.description);
    }
    Ok(())
}

/// Build the `neoth preset list --json` body:
/// `{presets:[{name,active,builtin,description}], active}`. PURE —
/// consumed by the GUI preset selector (SPEC-05). `builtin` and
/// `description` are additive fields; existing consumers keyed on
/// `name`/`active` keep working.
fn preset_list_json(
    rows: &[crate::config::preset_builtins::PresetRow],
    active: Option<&str>,
) -> String {
    let presets: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "name": row.name,
                "active": active == Some(row.name.as_str()),
                "builtin": row.builtin,
                "description": row.description,
            })
        })
        .collect();
    serde_json::json!({
        "presets": presets,
        "active": active,
    })
    .to_string()
}

fn run_show(home: &Path, name: &str) -> Result<()> {
    let preset = presets::resolve(home, name)?;
    let yaml = serde_yaml::to_string(&preset)?;
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
    use crate::config::presets::{Preset, upsert};
    use tempfile::tempdir;

    #[test]
    fn run_list_with_no_presets_prints_hint_without_error() {
        let dir = tempdir().unwrap();
        run_list(dir.path(), false).unwrap();
        run_list(dir.path(), true).unwrap(); // json path on empty
    }

    #[test]
    fn run_list_renders_active_marker() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), "frugal", Preset::default()).unwrap();
        upsert(dir.path(), "weekend", Preset::default()).unwrap();
        presets::set_active(dir.path(), "weekend").unwrap();
        // We don't capture stdout — smoke-only.
        run_list(dir.path(), false).unwrap();
        run_list(dir.path(), true).unwrap();
    }

    #[test]
    fn preset_list_json_marks_active_and_tags_builtins() {
        use crate::config::preset_builtins::PresetRow;
        let rows = vec![
            PresetRow {
                name: "full-auto".into(),
                builtin: true,
                description: "Everything on.".into(),
            },
            PresetRow {
                name: "weekend".into(),
                builtin: false,
                description: String::new(),
            },
        ];
        let out = preset_list_json(&rows, Some("weekend"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["active"], "weekend");
        let arr = v["presets"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["name"], "full-auto");
        assert_eq!(arr[0]["active"], false);
        assert_eq!(arr[0]["builtin"], true);
        assert_eq!(arr[0]["description"], "Everything on.");
        assert_eq!(arr[1]["name"], "weekend");
        assert_eq!(arr[1]["active"], true);
        assert_eq!(arr[1]["builtin"], false);
    }

    #[test]
    fn preset_list_json_empty_and_no_active() {
        let out = preset_list_json(&[], None);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v["active"].is_null());
        assert_eq!(v["presets"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn apply_report_json_carries_plan() {
        let report = crate::config::presets::ApplyReport {
            preset_applied: true,
            fields_changed: vec!["proactive.enabled".into()],
            autonomy_requested: Some("full".into()),
            warn_changes: vec![(
                "media.cloud_stt_enabled".into(),
                "(unset)".into(),
                "true".into(),
            )],
        };
        let v: serde_json::Value =
            serde_json::from_str(&apply_report_json("full-auto", &report)).unwrap();
        assert_eq!(v["name"], "full-auto");
        assert_eq!(v["autonomy_requested"], "full");
        assert_eq!(v["warn_changes"][0]["path"], "media.cloud_stt_enabled");
        assert_eq!(v["warn_changes"][0]["new"], "true");
    }

    #[test]
    fn run_show_resolves_builtins() {
        let dir = tempdir().unwrap();
        run_show(dir.path(), "full-auto").unwrap();
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
