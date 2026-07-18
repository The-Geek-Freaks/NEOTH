//! GOLD-R4-05 — CLI↔GUI capability-parity drift guard.
//!
//! Sibling of the DOC-01 drift infra in [`super::docgen`]: that one keeps the
//! CLI *reference* from drifting; this one keeps the CLI↔GUI *capability map*
//! from drifting. Every non-hidden `neoth <verb>` subcommand must have an
//! explicit triage entry in [`INVENTORY`] — either the GUI nav key that
//! surfaces it (a `root.nav("…")` key in `neothd-gui/ui/app_shell.slint`) or
//! an explicit CLI-only justification. When a new subcommand is added to the
//! clap tree and nobody classifies it, [`every_cli_capability_is_triaged`]
//! fails and prints the offending verb — the drift is caught at test time
//! instead of shipping a capability with no GUI decision.
//!
//! Top-level navigation is not operation parity. [`OPERATION_INVENTORY`] adds
//! a checked, intentionally incomplete second layer for capabilities that were
//! previously misclassified as CLI-only. It binds each live CLI leaf operation
//! to its GUI callback, Rust handler, dispatch token, and receipt/readback
//! posture. `Partial` and `Unwired` rows are release gaps, not green checks.
//! This guard therefore does **not** claim GOLD-R4-05 complete; expand it as
//! additional day-two operations are wired.
//!
//! The verb set is enumerated live from the clap `Command` tree (auto-fresh,
//! no hand-transcription), so the only maintenance is: add a row when you add
//! a subcommand. The reverse guard flags INVENTORY rows whose verb no longer
//! exists (rename/removal), and a third guard catches typos in the GUI nav
//! keys the inventory references.
//!
//! Feature-gated verbs: a `#[cfg(feature = "…")]`-gated subcommand (currently
//! only `cluster`) is added to the inventory by `full_inventory()` under the
//! SAME cfg, so the inventory and the live set stay symmetric whether the
//! feature is on or off — no false "stale" failure with the feature off, and
//! (when CI runs `--all-features`) no forward bypass where a gated verb ships
//! un-triaged. Add future gated verbs the same way.

#![cfg(test)]

use clap::CommandFactory;
use std::collections::{BTreeSet, HashSet};

use super::Cli;

/// Where a CLI capability is surfaced.
#[derive(Clone, Copy)]
enum Surface {
    /// Reachable in the GUI via this `root.nav("<key>")` key (app_shell.slint).
    Gui(&'static str),
    /// Intentionally CLI-only; the string is the reason (daemon process,
    /// one-shot pipe, shell integration, internal RPC, …).
    CliOnly(&'static str),
}
use Surface::{CliOnly, Gui};

/// Runtime evidence the GUI checks after invoking a CLI operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Evidence {
    /// A strict Rust type or verifier rejects malformed/mismatched output.
    Typed(&'static str),
    /// Output is consumed, but only as free-form text or a lenient parser.
    Untyped(&'static str),
    /// No receipt or readback is checked.
    Missing,
}

/// Honest operation-level parity state. A panel or callback alone is never
/// enough to use `Verified`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationState {
    Verified,
    Partial(&'static str),
    Unwired(&'static str),
}

/// One concrete GUI/CLI operation contract. Tokens are checked against the
/// actual Slint and Rust sources below, while `cli_path` is checked against the
/// live nested clap tree.
#[derive(Clone, Copy, Debug)]
struct OperationParity {
    id: &'static str,
    capability: &'static str,
    cli_path: &'static str,
    gui_nav: &'static str,
    gui_surface: &'static str,
    ui_callback: Option<&'static str>,
    rust_handler: Option<&'static str>,
    dispatch_token: Option<&'static str>,
    receipt: Evidence,
    readback: Evidence,
    state: OperationState,
}

/// Extract the real `root.nav("...")` keys from the compiled GUI source. This
/// deliberately avoids a second hand-maintained navigation inventory: a new,
/// renamed or removed panel changes the test input in the same commit.
fn live_gui_nav_keys() -> HashSet<&'static str> {
    const APP_SHELL: &str = include_str!("../../../neothd-gui/ui/app_shell.slint");
    APP_SHELL
        .split("root.nav(\"")
        .skip(1)
        .filter_map(|tail| tail.split_once("\")").map(|(key, _)| key))
        .collect()
}

/// One CLI capability can legitimately own more than one product view. The
/// cluster command owns the configuration/control panel and the operational
/// mesh view; keeping that relationship explicit prevents `mesh` from being a
/// permanently unowned exception in the reverse drift guard.
const ADDITIONAL_GUI_NAV_OWNERS: &[(&str, &str)] = &[("mesh", "cluster")];

/// Operation-level inventory for the capabilities whose old top-level
/// `CliOnly` labels hid real GUI surfaces. It is deliberately compact: every
/// live leaf below backup/OMI/interface is represented, plus the still-unwired
/// restore operation adjacent to the GUI's read-only rollback preview.
const OPERATION_INVENTORY: &[OperationParity] = &[
    OperationParity {
        id: "backup.create-default",
        capability: "backup",
        cli_path: "backup",
        gui_nav: "config",
        gui_surface: "Config > Maintenance > Backup now",
        ui_callback: Some("backup-now-clicked"),
        rust_handler: Some("window.on_settings_backup_now_clicked"),
        dispatch_token: Some(".arg(\"backup\")"),
        receipt: Evidence::Untyped("String::from_utf8_lossy"),
        readback: Evidence::Missing,
        state: OperationState::Partial(
            "GUI exposes only the default backup and trusts status text; custom output, WAL, credential flags, and archive readback remain CLI-only",
        ),
    },
    OperationParity {
        id: "omi.status",
        capability: "omi",
        cli_path: "omi status",
        gui_nav: "privacy",
        gui_surface: "Privacy > OMI > Refresh",
        ui_callback: Some("omi-refresh-clicked"),
        rust_handler: Some("window.on_omi_refresh"),
        dispatch_token: Some("fetch_omi_snapshot()"),
        receipt: Evidence::Untyped("parse_omi_status"),
        readback: Evidence::Untyped("apply_omi_snapshot"),
        state: OperationState::Partial(
            "malformed or failed status reads collapse to OmiSnapshot defaults instead of a visible typed error",
        ),
    },
    OperationParity {
        id: "omi.probe",
        capability: "omi",
        cli_path: "omi probe",
        gui_nav: "privacy",
        gui_surface: "Privacy > OMI > Probe local",
        ui_callback: Some("omi-probe-clicked"),
        rust_handler: Some("window.on_omi_probe"),
        dispatch_token: Some("[\"probe\".to_string()]"),
        receipt: Evidence::Untyped("run_omi_subcommand"),
        readback: Evidence::Missing,
        state: OperationState::Partial(
            "probe success is free-form stdout with no typed endpoint receipt",
        ),
    },
    OperationParity {
        id: "omi.set-credentials",
        capability: "omi",
        cli_path: "omi set-credentials",
        gui_nav: "privacy",
        gui_surface: "Privacy > OMI > Save and reload",
        ui_callback: Some("omi-save-clicked"),
        rust_handler: Some("window.on_omi_save"),
        dispatch_token: Some("save_omi_settings("),
        receipt: Evidence::Untyped("persist_omi_credentials_via_cli"),
        readback: Evidence::Untyped("fetch_omi_snapshot"),
        state: OperationState::Partial(
            "credential update checks only exit status and the follow-up status read can silently default",
        ),
    },
    OperationParity {
        id: "omi.purge",
        capability: "omi",
        cli_path: "omi purge",
        gui_nav: "privacy",
        gui_surface: "Privacy > OMI > Permanently purge conversation",
        ui_callback: Some("omi-purge-clicked"),
        rust_handler: Some("window.on_omi_purge"),
        dispatch_token: Some("[\"purge\".into(), conversation_id, \"--yes\".into()]"),
        receipt: Evidence::Untyped("run_omi_subcommand"),
        readback: Evidence::Untyped("fetch_omi_snapshot"),
        state: OperationState::Partial(
            "privacy deletion has confirmation UI but no typed deletion/tombstone receipt",
        ),
    },
    OperationParity {
        id: "omi.resume",
        capability: "omi",
        cli_path: "omi resume",
        gui_nav: "privacy",
        gui_surface: "Privacy > OMI > Resume sanitizer",
        ui_callback: Some("omi-resume-clicked"),
        rust_handler: Some("window.on_omi_resume"),
        dispatch_token: Some("[\"resume\".into(), \"--review-note\".into(), note]"),
        receipt: Evidence::Untyped("run_omi_subcommand"),
        readback: Evidence::Untyped("fetch_omi_snapshot"),
        state: OperationState::Partial(
            "resume acknowledgement and halt-state readback are not typed",
        ),
    },
    OperationParity {
        id: "omi.enforce-retention",
        capability: "omi",
        cli_path: "omi enforce-retention",
        gui_nav: "privacy",
        gui_surface: "Privacy > OMI > Run retention",
        ui_callback: Some("omi-retention-clicked"),
        rust_handler: Some("window.on_omi_retention"),
        dispatch_token: Some("[\"enforce-retention\".into()]"),
        receipt: Evidence::Untyped("run_omi_subcommand"),
        readback: Evidence::Untyped("fetch_omi_snapshot"),
        state: OperationState::Partial(
            "retention result and deletion counts are not typed or bound",
        ),
    },
    OperationParity {
        id: "omi.allow-reimport",
        capability: "omi",
        cli_path: "omi allow-reimport",
        gui_nav: "privacy",
        gui_surface: "Privacy > OMI > Allow re-import",
        ui_callback: Some("omi-reimport-clicked"),
        rust_handler: Some("window.on_omi_reimport"),
        dispatch_token: Some("[\"allow-reimport\".into(), conversation_id, \"--yes\".into()]"),
        receipt: Evidence::Untyped("run_omi_subcommand"),
        readback: Evidence::Untyped("fetch_omi_snapshot"),
        state: OperationState::Partial(
            "tombstone removal is not returned in a typed, request-bound receipt",
        ),
    },
    OperationParity {
        id: "interface.show",
        capability: "interface",
        cli_path: "interface show",
        gui_nav: "config",
        gui_surface: "first-run interface chooser boot state",
        ui_callback: None,
        rust_handler: Some("load_gui_interface_preference"),
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Typed("GuiInterfacePreferenceRecord"),
        state: OperationState::Partial(
            "GUI consumes the canonical record at boot but has no explicit day-two show/refresh action",
        ),
    },
    OperationParity {
        id: "interface.set-gui",
        capability: "interface",
        cli_path: "interface set",
        gui_nav: "config",
        gui_surface: "first-run interface chooser > GUI",
        ui_callback: Some("gui-mode-chosen"),
        rust_handler: Some("window.on_gui_mode_chosen"),
        dispatch_token: Some("set_interface_preference_via_cli"),
        receipt: Evidence::Typed("GuiInterfaceSetAcknowledgement"),
        readback: Evidence::Typed("validate_interface_set_result"),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "interface.set-cli-day-two",
        capability: "interface",
        cli_path: "interface set",
        gui_nav: "config",
        gui_surface: "Config > Open CLI",
        ui_callback: Some("settings-open-cli-clicked"),
        rust_handler: Some("window.on_settings_open_cli_clicked"),
        dispatch_token: Some("switch_to_cli(&bin, &home)"),
        receipt: Evidence::Typed("TerminalHandshake"),
        readback: Evidence::Missing,
        state: OperationState::Partial(
            "authenticated terminal readiness proves commit ordering, but the GUI does not read back the saved CLI preference before handoff",
        ),
    },
    OperationParity {
        id: "restore.archive",
        capability: "restore",
        cli_path: "restore",
        gui_nav: "config",
        gui_surface: "Config > Maintenance (preview only; no restore action)",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired(
            "Config can preview rollback snapshots, but archive restore has no GUI action or receipt",
        ),
    },
];

/// The canonical capability inventory: every non-hidden CLI verb → its surface.
/// Adding a `neoth` subcommand without adding a row here fails the drift test.
const INVENTORY: &[(&str, Surface)] = &[
    (
        "init",
        CliOnly("first-run setup wizard; GUI has its own onboarding"),
    ),
    ("serve", CliOnly("daemon foreground process")),
    ("chat", Gui("chat")),
    ("fact-check", CliOnly("one-shot verification pipe")),
    ("capabilities", Gui("overview")),
    ("loop", Gui("loops")),
    ("risk-confirm", CliOnly("interactive confirm RPC for hooks")),
    ("edit", CliOnly("headless self-edit apply")),
    ("recall", Gui("memory")),
    ("recall-score", Gui("memory")),
    ("update", CliOnly("model/catalog refresh pipe")),
    ("release", CliOnly("authenticated-release helper")),
    ("supervisor", CliOnly("process supervisor")),
    ("jobs", Gui("bg-jobs")),
    ("code", Gui("coding")),
    ("kanban", Gui("coding")),
    ("moral-core", Gui("tweaks")),
    ("autonomy", Gui("privacy")),
    ("sudomode", CliOnly("elevation toggle")),
    ("recipe", Gui("automation")),
    ("dream", Gui("dreaming")),
    ("transfer", CliOnly("identity transfer pipe")),
    ("identity", Gui("config")),
    ("credential", Gui("credentials")),
    ("computer-use", CliOnly("headless computer-use driver")),
    ("self-improve", Gui("evolve")),
    ("self-knowledge", Gui("selfdev")),
    ("self-activate", CliOnly("self-activation trigger")),
    ("self-edit", CliOnly("headless self-edit")),
    ("okf", CliOnly("objective/key-flow runner")),
    ("reflect", Gui("selfdev")),
    ("recon", CliOnly("recon pipeline")),
    ("cron", Gui("automation")),
    ("interface", Gui("config")),
    ("gui", CliOnly("launches the GUI itself")),
    ("memory", Gui("memory")),
    ("ctx", Gui("memory")),
    ("skills", Gui("plugins")),
    ("mode", Gui("mode-registry")),
    ("glossary", Gui("wiki")),
    ("privacy", Gui("privacy")),
    ("terminal", CliOnly("embedded terminal launcher")),
    ("tour", CliOnly("onboarding tour")),
    ("groundtruth", Gui("groundtruth")),
    ("import", CliOnly("data import pipe")),
    ("telemetry", Gui("privacy")),
    ("adr", Gui("adr-browser")),
    ("backup", Gui("config")),
    ("paperless", CliOnly("paperless integration pipe")),
    ("proactive", Gui("automation")),
    ("webhook", CliOnly("webhook server")),
    ("updater", CliOnly("self-updater")),
    ("installer", CliOnly("installer")),
    ("reload", CliOnly("config hot-reload trigger")),
    ("restore", CliOnly("backup restore pipe")),
    ("verify", CliOnly("integrity verify pipe")),
    ("trust", Gui("privacy")),
    ("email", Gui("channels")),
    ("calendar", Gui("calendar")),
    ("ecology", Gui("resources")),
    ("checkpoint", CliOnly("state checkpoint pipe")),
    ("security", Gui("privacy")),
    ("companion", Gui("companion")),
    ("status", Gui("overview")),
    ("hardware", Gui("resources")),
    ("models", Gui("catalog")),
    ("review", Gui("coding")),
    ("goal", Gui("loops")),
    ("ingest", CliOnly("ingest pipe")),
    ("hysteria", CliOnly("hysteria transport daemon")),
    ("cloud", CliOnly("cloud sync pipe")),
    // NOTE: `cluster` is `#[cfg(feature = "cluster")]`-gated in the enum, so it
    // is NOT in this unconditional slice — it is added by `full_inventory()`
    // under the same cfg to keep INVENTORY and the live verb set symmetric in
    // both feature configs. Any future `#[cfg(feature = "…")]`-gated verb MUST
    // be added the same way (a cfg-gated push), and CI runs `--all-features` so
    // the triage guard sees every gated verb.
    ("ouro", Gui("evolve")),
    ("cost", Gui("quota")),
    ("fetch", CliOnly("url fetch pipe")),
    ("arxiv", CliOnly("arxiv ingest pipe")),
    ("babel", Gui("babel")),
    ("search", Gui("memory")),
    ("github", CliOnly("github integration pipe")),
    ("slack", Gui("channels")),
    ("todo", Gui("coding")),
    ("lease", CliOnly("resource lease pipe")),
    ("feedback", CliOnly("feedback submit pipe")),
    ("fs", CliOnly("filesystem tool surface")),
    ("os", CliOnly("os tool surface")),
    ("tts", CliOnly("text-to-speech pipe")),
    ("dictate", CliOnly("speech dictation pipe")),
    ("omi", Gui("privacy")),
    ("doctor", Gui("doctor")),
    ("monitor", Gui("resources")),
    ("migrate", Gui("migrate-history")),
    ("buddy", Gui("buddyconfig")),
    ("rmas", CliOnly("recursive-MAS sidecar")),
    ("keys", Gui("config")),
    ("events", Gui("wal")),
    ("schema", CliOnly("schema dump pipe")),
    ("wal", Gui("wal")),
    ("completions", CliOnly("shell completions generator")),
    ("export", CliOnly("data export pipe")),
    ("obsidian", Gui("obsidian")),
    ("profile", Gui("config")),
    ("quota", Gui("quota")),
    ("hooks", Gui("hooks")),
    ("agents", Gui("agents")),
    ("slash", Gui("slash")),
    ("tweaks", Gui("tweaks")),
    ("permissions", Gui("privacy")),
    ("refusal", Gui("privacy")),
    ("consent", Gui("privacy")),
    ("catalog", Gui("catalog")),
    ("code-map", Gui("coding")),
    ("graph", Gui("memgraph")),
    ("code-intel", Gui("coding")),
    ("distill", CliOnly("memory distillation pipe")),
    ("trace-replay", CliOnly("trace replay debug pipe")),
    ("deps-scan", CliOnly("dependency scan pipe")),
    ("memory-eval", Gui("memory")),
    ("eval", CliOnly("eval harness pipe")),
    ("device-profile", Gui("config")),
    ("onboarding-status", Gui("overview")),
    ("demo", CliOnly("demo runner")),
    ("council", Gui("council-weights")),
    ("rollback", CliOnly("state rollback pipe")),
    ("mcp", Gui("mcp")),
    ("hemispheres", Gui("hemispheres")),
    ("usage", Gui("quota")),
    ("meter", Gui("quota")),
    ("preset", Gui("config")),
    ("self-dev", Gui("selfdev")),
    ("provider", Gui("catalog")),
    ("connect", CliOnly("connect pairing pipe")),
    ("undo", CliOnly("undo last action pipe")),
    ("channel", Gui("channels")),
    ("plugin", Gui("plugins")),
    ("n8n", Gui("n8n")),
];

/// The full inventory for the ACTIVE feature set: the unconditional [`INVENTORY`]
/// plus every `#[cfg(feature = "…")]`-gated verb, each added under the same cfg
/// so the inventory tracks exactly what `live_verbs()` enumerates in this build.
fn full_inventory() -> Vec<(&'static str, Surface)> {
    let mut inv = INVENTORY.to_vec();
    #[cfg(feature = "cluster")]
    inv.push(("cluster", Gui("cluster")));
    inv
}

/// Live, non-hidden top-level subcommand names from the clap tree.
fn live_verbs() -> Vec<String> {
    Cli::command()
        .get_subcommands()
        .filter(|s| !s.is_hide_set())
        .map(|s| s.get_name().to_string())
        .collect()
}

/// Enumerate visible leaf operations below one top-level capability. This is
/// the nested equivalent of [`live_verbs`]: adding an OMI/interface subcommand
/// without an operation row fails instead of inheriting a false top-level
/// green state.
fn live_leaf_operation_paths(capability: &str) -> Vec<String> {
    fn visit(command: &clap::Command, prefix: &str, paths: &mut Vec<String>) {
        let mut children = command
            .get_subcommands()
            .filter(|child| !child.is_hide_set())
            .peekable();
        if children.peek().is_none() {
            paths.push(prefix.to_string());
            return;
        }
        for child in children {
            let child_path = format!("{prefix} {}", child.get_name());
            visit(child, &child_path, paths);
        }
    }

    let root = Cli::command();
    let command = root.find_subcommand(capability).unwrap_or_else(|| {
        panic!("operation inventory references missing capability `{capability}`")
    });
    let mut paths = Vec::new();
    visit(command, capability, &mut paths);
    paths
}

#[test]
fn every_cli_capability_is_triaged_for_gui_parity() {
    // Floor guard: if a clap upgrade ever breaks enumeration and returns an
    // empty set, the membership asserts below would pass vacuously (green =
    // false confidence). NEOTH has ~100 verbs; anything under 50 is a bug.
    assert!(
        live_verbs().len() > 50,
        "clap enumeration returned {} subcommands — expected ~100; enumeration is broken",
        live_verbs().len()
    );

    let inv = full_inventory();
    let known: HashSet<&str> = inv.iter().map(|(v, _)| *v).collect();
    let undocumented: Vec<String> = live_verbs()
        .into_iter()
        .filter(|v| !known.contains(v.as_str()))
        .collect();
    assert!(
        undocumented.is_empty(),
        "CLI verb(s) lack a GUI-parity triage entry — add each to INVENTORY in \
         cli/parity_drift.rs as Gui(\"<nav-key>\") or CliOnly(\"<reason>\"): {undocumented:?}"
    );

    // Every row must carry a real surface: a non-empty nav key or a non-empty
    // CLI-only justification (an empty string is an un-triaged placeholder).
    let empty: Vec<&str> = inv
        .iter()
        .filter(|(_, surface)| match surface {
            Gui(key) => key.is_empty(),
            CliOnly(reason) => reason.is_empty(),
        })
        .map(|(verb, _)| *verb)
        .collect();
    assert!(
        empty.is_empty(),
        "INVENTORY rows with an empty surface (needs a nav key or a CLI-only reason): {empty:?}"
    );
}

#[test]
fn inventory_has_no_stale_verbs() {
    let live: HashSet<String> = live_verbs().into_iter().collect();
    let stale: Vec<&str> = full_inventory()
        .iter()
        .map(|(v, _)| *v)
        .filter(|v| !live.contains(*v))
        .collect();
    assert!(
        stale.is_empty(),
        "INVENTORY rows reference verbs that no longer exist in the CLI \
         (rename/removal) — update cli/parity_drift.rs: {stale:?}"
    );
}

#[test]
fn gui_targets_reference_real_nav_keys() {
    let navset = live_gui_nav_keys();
    let bad: Vec<(&str, &str)> = full_inventory()
        .iter()
        .filter_map(|(verb, surface)| match surface {
            Gui(key) if !navset.contains(key) => Some((*verb, *key)),
            _ => None,
        })
        .collect();
    assert!(
        bad.is_empty(),
        "INVENTORY Gui() targets that match no app_shell.slint nav key \
         (typo, or panel was renamed/removed) — (verb, bad-key): {bad:?}"
    );
}

#[test]
fn every_gui_nav_key_has_a_capability_owner() {
    let inventory = full_inventory();
    let mut represented: HashSet<&str> = inventory
        .iter()
        .filter_map(|(_, surface)| match surface {
            Gui(key) => Some(*key),
            CliOnly(_) => None,
        })
        .collect();
    let live_verbs: HashSet<String> = live_verbs().into_iter().collect();
    for (nav_key, owner_verb) in ADDITIONAL_GUI_NAV_OWNERS {
        assert!(
            live_verbs.contains(*owner_verb),
            "GUI nav alias `{nav_key}` references missing CLI owner `{owner_verb}`"
        );
        represented.insert(nav_key);
    }

    let unowned: Vec<&str> = live_gui_nav_keys()
        .into_iter()
        .filter(|key| !represented.contains(key))
        .collect();
    assert!(
        unowned.is_empty(),
        "GUI nav key(s) have no CLI capability owner — classify the matching \
         verb in INVENTORY or ADDITIONAL_GUI_NAV_OWNERS: {unowned:?}"
    );
}

#[test]
fn formerly_false_cli_only_capabilities_reference_real_gui_surfaces() {
    let inventory = full_inventory();
    for (capability, expected_nav) in [
        ("backup", "config"),
        ("omi", "privacy"),
        ("interface", "config"),
    ] {
        let actual = inventory
            .iter()
            .find_map(|(verb, surface)| (*verb == capability).then_some(*surface))
            .unwrap_or_else(|| panic!("missing capability `{capability}`"));
        assert!(
            matches!(actual, Gui(nav) if nav == expected_nav),
            "`{capability}` has a real GUI surface and must not regress to CLI-only"
        );
    }
}

#[test]
fn operation_inventory_tracks_live_nested_cli_leaves() {
    let capabilities: BTreeSet<&str> = OPERATION_INVENTORY
        .iter()
        .map(|operation| operation.capability)
        .collect();
    for capability in capabilities {
        let live: BTreeSet<String> = live_leaf_operation_paths(capability).into_iter().collect();
        let declared: BTreeSet<&str> = OPERATION_INVENTORY
            .iter()
            .filter(|operation| operation.capability == capability)
            .map(|operation| operation.cli_path)
            .collect();
        let missing: Vec<&str> = live
            .iter()
            .filter(|path| !declared.contains(path.as_str()))
            .map(String::as_str)
            .collect();
        let stale: Vec<&str> = declared
            .iter()
            .filter(|path| !live.contains(**path))
            .copied()
            .collect();
        assert!(
            missing.is_empty() && stale.is_empty(),
            "operation inventory drift for `{capability}` — missing {missing:?}, stale {stale:?}"
        );
    }
}

#[test]
fn operation_inventory_binds_gui_callbacks_handlers_and_evidence() {
    const GUI_UI: &str = concat!(
        include_str!("../../../neothd-gui/ui/main.slint"),
        "\n",
        include_str!("../../../neothd-gui/ui/settings.slint")
    );
    const GUI_RUST: &str = include_str!("../../../neothd-gui/src/main.rs");

    fn callback_handler_body<'a>(source: &'a str, anchor: &str) -> &'a str {
        let tail = source
            .split_once(anchor)
            .unwrap_or_else(|| panic!("missing Rust handler `{anchor}`"))
            .1;
        tail.split_once("\n    window.on_")
            .map_or(tail, |(body, _)| body)
    }

    let mut ids = BTreeSet::new();
    let nav_keys = live_gui_nav_keys();
    for operation in OPERATION_INVENTORY {
        assert!(
            ids.insert(operation.id),
            "duplicate operation id `{}`",
            operation.id
        );
        assert!(
            operation.cli_path == operation.capability
                || operation
                    .cli_path
                    .starts_with(&format!("{} ", operation.capability)),
            "operation `{}` path is outside capability `{}`",
            operation.id,
            operation.capability
        );
        assert!(
            nav_keys.contains(operation.gui_nav),
            "operation `{}` references missing GUI nav `{}`",
            operation.id,
            operation.gui_nav
        );
        assert!(
            !operation.gui_surface.trim().is_empty(),
            "operation `{}` is missing its concrete GUI surface",
            operation.id
        );
        if let Some(callback) = operation.ui_callback {
            assert!(
                GUI_UI.contains(callback),
                "operation `{}` references missing Slint callback `{callback}`",
                operation.id
            );
        }
        if let Some(handler) = operation.rust_handler {
            assert!(
                GUI_RUST.contains(handler),
                "operation `{}` references missing Rust handler `{handler}`",
                operation.id
            );
        }
        if let Some(dispatch) = operation.dispatch_token {
            let handler = operation
                .rust_handler
                .expect("a dispatch token requires a Rust handler anchor");
            assert!(
                callback_handler_body(GUI_RUST, handler).contains(dispatch),
                "operation `{}` handler `{handler}` does not contain dispatch token `{dispatch}`",
                operation.id
            );
        }
        for (kind, evidence) in [
            ("receipt", operation.receipt),
            ("readback", operation.readback),
        ] {
            if let Evidence::Typed(token) | Evidence::Untyped(token) = evidence {
                assert!(
                    GUI_RUST.contains(token),
                    "operation `{}` {kind} evidence token `{token}` is stale",
                    operation.id
                );
            }
        }
        match operation.state {
            OperationState::Verified => {
                assert!(operation.ui_callback.is_some());
                assert!(operation.rust_handler.is_some());
                assert!(operation.dispatch_token.is_some());
                assert!(matches!(operation.receipt, Evidence::Typed(_)));
                assert!(matches!(operation.readback, Evidence::Typed(_)));
            }
            OperationState::Partial(gap) => {
                assert!(
                    !gap.trim().is_empty(),
                    "operation `{}` hides its parity gap",
                    operation.id
                );
                assert!(
                    operation.rust_handler.is_some(),
                    "partial operation `{}` needs a real handler; otherwise mark it unwired",
                    operation.id
                );
            }
            OperationState::Unwired(gap) => {
                assert!(
                    !gap.trim().is_empty(),
                    "operation `{}` hides its unwired reason",
                    operation.id
                );
                assert!(operation.ui_callback.is_none());
                assert!(operation.rust_handler.is_none());
                assert!(operation.dispatch_token.is_none());
                assert_eq!(operation.receipt, Evidence::Missing);
                assert_eq!(operation.readback, Evidence::Missing);
            }
        }
    }
}

#[test]
fn operation_inventory_keeps_r4_05_gaps_explicit() {
    let partial: BTreeSet<&str> = OPERATION_INVENTORY
        .iter()
        .filter(|operation| matches!(operation.state, OperationState::Partial(_)))
        .map(|operation| operation.id)
        .collect();
    let unwired: BTreeSet<&str> = OPERATION_INVENTORY
        .iter()
        .filter(|operation| matches!(operation.state, OperationState::Unwired(_)))
        .map(|operation| operation.id)
        .collect();

    for expected in [
        "backup.create-default",
        "omi.status",
        "omi.probe",
        "omi.set-credentials",
        "omi.purge",
        "omi.resume",
        "omi.enforce-retention",
        "omi.allow-reimport",
        "interface.show",
        "interface.set-cli-day-two",
    ] {
        assert!(
            partial.contains(expected),
            "`{expected}` must remain explicitly partial until its typed receipt/readback gap is fixed"
        );
    }
    assert_eq!(unwired, BTreeSet::from(["restore.archive"]));
}
