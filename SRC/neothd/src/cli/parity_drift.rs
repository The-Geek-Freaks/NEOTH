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
use std::collections::HashSet;

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
    ("interface", CliOnly("interface-preference setter")),
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
    ("backup", CliOnly("backup pipe")),
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
    ("omi", CliOnly("OMI wearable integration pipe")),
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
