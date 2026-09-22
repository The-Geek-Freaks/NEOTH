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
    /// The pair is `(handler anchor, evidence token)`.
    Typed(&'static str, &'static str),
    /// Output is consumed, but only as free-form text or a lenient parser.
    /// The pair is `(handler anchor, evidence token)`.
    Untyped(&'static str, &'static str),
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

const fn unwired_operation(
    id: &'static str,
    capability: &'static str,
    cli_path: &'static str,
    gui_nav: &'static str,
    gui_surface: &'static str,
    gap: &'static str,
) -> OperationParity {
    OperationParity {
        id,
        capability,
        cli_path,
        gui_nav,
        gui_surface,
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired(gap),
    }
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
/// live leaf below backup/OMI/interface/models/buddy is represented, plus the
/// still-unwired restore operation adjacent to the GUI's read-only rollback
/// preview. This prevents a nested local-model CLI leaf from silently escaping
/// the GUI parity ledger.
const OPERATION_INVENTORY: &[OperationParity] = &[
    OperationParity {
        id: "backup.create-default",
        capability: "backup",
        cli_path: "backup",
        gui_nav: "config",
        gui_surface: "Config > Maintenance > Backup now",
        ui_callback: Some("backup-now-clicked"),
        rust_handler: Some("window.on_settings_backup_now_clicked"),
        dispatch_token: Some("&[\"backup\"]"),
        receipt: Evidence::Typed("window.on_settings_backup_now_clicked", "BackupAck"),
        readback: Evidence::Typed(
            "window.on_settings_backup_now_clicked",
            "verify_and_read_back",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "backup.mirror-status",
        capability: "backup",
        cli_path: "backup mirror status",
        gui_nav: "config",
        gui_surface: "Config > Maintenance > Vault mirror status",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired(
            "the GUI exposes vault-mirror repair only; it has no mirror-status projection",
        ),
    },
    OperationParity {
        id: "backup.mirror-run",
        capability: "backup",
        cli_path: "backup mirror run",
        gui_nav: "config",
        gui_surface: "Config > Maintenance > Vault mirror",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired(
            "the GUI does not start a policy-gated WAL mirror publication",
        ),
    },
    OperationParity {
        id: "backup.mirror-repair",
        capability: "backup",
        cli_path: "backup mirror repair",
        gui_nav: "config",
        gui_surface: "Config > Maintenance > Vault mirror repair",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired(
            "the GUI repair action uses the buddy vault-mirror protocol, not this CLI leaf",
        ),
    },
    OperationParity {
        id: "models.ollama.status",
        capability: "models",
        cli_path: "models ollama status",
        gui_nav: "resources",
        gui_surface: "Resources > Ollama models status",
        ui_callback: None,
        rust_handler: Some("fn fetch_local_models_status"),
        dispatch_token: Some("[\"models\", \"ollama\", \"status\"]"),
        receipt: Evidence::Untyped("fn fetch_local_models_status", "validate_neothd_probe_exit"),
        readback: Evidence::Typed("fn fetch_local_models_status", "parse_local_models_status"),
        state: OperationState::Partial(
            "Resources refreshes the typed daemon snapshot during its bounded background probe; it has no separate status button",
        ),
    },
    OperationParity {
        id: "models.ollama.pull",
        capability: "models",
        cli_path: "models ollama pull",
        gui_nav: "resources",
        gui_surface: "Resources > Ollama models > Pull",
        ui_callback: Some("local-model-pull"),
        rust_handler: Some("fn start_local_model_action"),
        dispatch_token: Some("vec![\"models\", \"ollama\", cli, &target]"),
        receipt: Evidence::Typed("fn start_local_model_action", "LocalModelActionAck"),
        readback: Evidence::Typed(
            "fn start_local_model_action",
            "local_models_snapshot_binds_action",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "models.ollama.update",
        capability: "models",
        cli_path: "models ollama update",
        gui_nav: "resources",
        gui_surface: "Resources > Ollama models > Update",
        ui_callback: Some("local-model-update"),
        rust_handler: Some("fn start_local_model_action"),
        dispatch_token: Some("vec![\"models\", \"ollama\", cli, &target]"),
        receipt: Evidence::Typed("fn start_local_model_action", "LocalModelActionAck"),
        readback: Evidence::Typed(
            "fn start_local_model_action",
            "local_models_snapshot_binds_action",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "models.ollama.prune",
        capability: "models",
        cli_path: "models ollama prune",
        gui_nav: "resources",
        gui_surface: "Resources > Ollama models > Prune",
        ui_callback: Some("local-model-prune"),
        rust_handler: Some("fn start_local_model_action"),
        dispatch_token: Some("vec![\"models\", \"ollama\", cli, &target]"),
        receipt: Evidence::Typed("fn start_local_model_action", "LocalModelActionAck"),
        readback: Evidence::Typed(
            "fn start_local_model_action",
            "local_models_snapshot_binds_action",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "models.ollama.cancel",
        capability: "models",
        cli_path: "models ollama cancel",
        gui_nav: "resources",
        gui_surface: "Resources > Ollama models > Cancel",
        ui_callback: Some("local-model-cancel"),
        rust_handler: Some("fn start_local_model_action"),
        dispatch_token: Some("vec![\"models\", \"ollama\", cli, &target]"),
        receipt: Evidence::Typed("fn start_local_model_action", "LocalModelActionAck"),
        readback: Evidence::Typed(
            "fn start_local_model_action",
            "local_models_snapshot_binds_action",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "models.ollama.retry",
        capability: "models",
        cli_path: "models ollama retry",
        gui_nav: "resources",
        gui_surface: "Resources > Ollama models > Retry",
        ui_callback: Some("local-model-retry"),
        rust_handler: Some("fn start_local_model_action"),
        dispatch_token: Some("vec![\"models\", \"ollama\", cli, &target]"),
        receipt: Evidence::Typed("fn start_local_model_action", "LocalModelActionAck"),
        readback: Evidence::Typed(
            "fn start_local_model_action",
            "local_models_snapshot_binds_action",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "models.list",
        capability: "models",
        cli_path: "models list",
        gui_nav: "catalog",
        gui_surface: "Model Catalog",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired(
            "the GUI catalog does not invoke the managed-model list leaf",
        ),
    },
    OperationParity {
        id: "models.catalog",
        capability: "models",
        cli_path: "models catalog",
        gui_nav: "catalog",
        gui_surface: "Chat regenerate picker",
        ui_callback: None,
        rust_handler: Some("let provider_kind ="),
        dispatch_token: Some("[\"models\", \"catalog\", \"--output\", \"json\"]"),
        receipt: Evidence::Untyped("let provider_kind =", "run_neothd_probe"),
        readback: Evidence::Missing,
        state: OperationState::Partial(
            "the picker consumes a parsed catalog but has no typed operation receipt/readback",
        ),
    },
    OperationParity {
        id: "models.pull",
        capability: "models",
        cli_path: "models pull",
        gui_nav: "catalog",
        gui_surface: "Model Catalog",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired("managed artifact downloads have no GUI action"),
    },
    OperationParity {
        id: "models.prune",
        capability: "models",
        cli_path: "models prune",
        gui_nav: "catalog",
        gui_surface: "Model Catalog",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired("managed artifact pruning has no GUI action"),
    },
    OperationParity {
        id: "models.recommend",
        capability: "models",
        cli_path: "models recommend",
        gui_nav: "resources",
        gui_surface: "Configuration > local provider model picker",
        ui_callback: None,
        rust_handler: Some("fn fetch_hemisphere_model_ids"),
        dispatch_token: Some(".arg(\"models\")"),
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Partial(
            "the picker parses recommendation output but has no typed operation receipt/readback",
        ),
    },
    OperationParity {
        id: "models.fit",
        capability: "models",
        cli_path: "models fit",
        gui_nav: "resources",
        gui_surface: "Resources",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired(
            "the GUI does not expose the CLI bandwidth and VRAM fit calculator",
        ),
    },
    OperationParity {
        id: "models.bge-m3.list",
        capability: "models",
        cli_path: "models bge-m3 list",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired("the GUI does not invoke the pinned BGE-M3 lifecycle alias"),
    },
    OperationParity {
        id: "models.bge-m3.status",
        capability: "models",
        cli_path: "models bge-m3 status",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired("the GUI does not invoke the pinned BGE-M3 lifecycle alias"),
    },
    OperationParity {
        id: "models.bge-m3.pull",
        capability: "models",
        cli_path: "models bge-m3 pull",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired("the GUI does not invoke the pinned BGE-M3 lifecycle alias"),
    },
    OperationParity {
        id: "models.bge-m3.repair",
        capability: "models",
        cli_path: "models bge-m3 repair",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired("the GUI does not invoke the pinned BGE-M3 lifecycle alias"),
    },
    OperationParity {
        id: "models.bge-m3.prune",
        capability: "models",
        cli_path: "models bge-m3 prune",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired("the GUI does not invoke the pinned BGE-M3 lifecycle alias"),
    },
    OperationParity {
        id: "models.embedding.list",
        capability: "models",
        cli_path: "models embedding list",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: None,
        rust_handler: None,
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Unwired("the GUI has no selected-embedding lifecycle action"),
    },
    OperationParity {
        id: "models.embedding.status",
        capability: "models",
        cli_path: "models embedding status",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: None,
        rust_handler: Some("fn fetch_embedding_models_status_for"),
        dispatch_token: Some("surface.cli_prefix().to_vec()"),
        receipt: Evidence::Untyped(
            "fn fetch_embedding_models_status_for",
            "validate_neothd_probe_exit",
        ),
        readback: Evidence::Typed(
            "fn fetch_embedding_models_status_for",
            "parse_embedding_models_status",
        ),
        state: OperationState::Partial(
            "the Resources refresh has a typed status DTO but no explicit status control or retained receipt",
        ),
    },
    OperationParity {
        id: "models.embedding.select",
        capability: "models",
        cli_path: "models embedding select",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: Some("embedding-model-changed"),
        rust_handler: Some("fn register_embedding_model_callbacks"),
        dispatch_token: Some("EmbeddingCommandSurface::Models, \"select\""),
        receipt: Evidence::Typed(
            "fn run_embedding_model_command",
            "parse_embedding_models_status",
        ),
        readback: Evidence::Typed(
            "fn register_embedding_model_callbacks",
            "snapshot.selected_model != expected_model",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "models.embedding.probe",
        capability: "models",
        cli_path: "models embedding probe",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: Some("embedding-model-probe"),
        rust_handler: Some("fn register_embedding_model_callbacks"),
        dispatch_token: Some("EmbeddingCommandSurface::Models, \"probe\""),
        receipt: Evidence::Typed(
            "fn run_embedding_model_command",
            "parse_embedding_models_status",
        ),
        readback: Evidence::Typed(
            "fn start_embedding_model_action",
            "embedding_snapshot_is_fresh_ready_for",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "models.embedding.pull",
        capability: "models",
        cli_path: "models embedding pull",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: Some("embedding-model-pull"),
        rust_handler: Some("fn register_embedding_model_callbacks"),
        dispatch_token: Some("EmbeddingCommandSurface::Models, \"pull\""),
        receipt: Evidence::Typed(
            "fn run_embedding_model_command",
            "parse_embedding_models_status",
        ),
        readback: Evidence::Typed(
            "fn start_embedding_model_action",
            "snapshot.selected_model != expected_model",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "models.embedding.repair",
        capability: "models",
        cli_path: "models embedding repair",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: Some("embedding-model-repair"),
        rust_handler: Some("fn register_embedding_model_callbacks"),
        dispatch_token: Some("EmbeddingCommandSurface::Models, \"repair\""),
        receipt: Evidence::Typed(
            "fn run_embedding_model_command",
            "parse_embedding_models_status",
        ),
        readback: Evidence::Typed(
            "fn start_embedding_model_action",
            "snapshot.selected_model != expected_model",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "models.embedding.prune",
        capability: "models",
        cli_path: "models embedding prune",
        gui_nav: "resources",
        gui_surface: "Resources > local embedding model",
        ui_callback: Some("embedding-model-prune"),
        rust_handler: Some("fn register_embedding_model_callbacks"),
        dispatch_token: Some("EmbeddingCommandSurface::Models, \"prune\""),
        receipt: Evidence::Typed(
            "fn run_embedding_model_command",
            "parse_embedding_models_status",
        ),
        readback: Evidence::Typed(
            "fn start_embedding_model_action",
            "snapshot.selected_model != expected_model",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "buddy.status",
        capability: "buddy",
        cli_path: "buddy status",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > Refresh",
        ui_callback: Some("bc-refresh-clicked"),
        rust_handler: Some("window.on_bc_refresh_clicked"),
        dispatch_token: Some("refresh_buddyconfig"),
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Partial(
            "the refresh projects a parsed Buddy snapshot but does not retain a typed status receipt",
        ),
    },
    unwired_operation(
        "buddy.embedding.list",
        "buddy",
        "buddy embedding list",
        "buddyconfig",
        "Buddy Config > local embedding model",
        "Buddy Config uses the selected-model status envelope and does not expose a separate list command",
    ),
    OperationParity {
        id: "buddy.embedding.status",
        capability: "buddy",
        cli_path: "buddy embedding status",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > local embedding model > Refresh",
        ui_callback: None,
        rust_handler: Some("fn fetch_embedding_models_status_for"),
        dispatch_token: Some("surface.cli_prefix().to_vec()"),
        receipt: Evidence::Untyped(
            "fn fetch_embedding_models_status_for",
            "validate_neothd_probe_exit",
        ),
        readback: Evidence::Typed(
            "fn fetch_embedding_models_status_for",
            "parse_embedding_models_status",
        ),
        state: OperationState::Partial(
            "the Buddy refresh projects a typed selected-model status DTO but has no separate retained status receipt",
        ),
    },
    OperationParity {
        id: "buddy.embedding.select",
        capability: "buddy",
        cli_path: "buddy embedding select",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > local embedding model > Selected model",
        ui_callback: Some("bc-embedding-model-changed"),
        rust_handler: Some("fn start_buddy_embedding_model_selection"),
        dispatch_token: Some("EmbeddingCommandSurface::Buddy, \"select\""),
        receipt: Evidence::Typed(
            "fn run_embedding_model_command",
            "parse_embedding_models_status",
        ),
        readback: Evidence::Typed(
            "fn start_buddy_embedding_model_selection",
            "snapshot.selected_model != expected_model",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "buddy.embedding.probe",
        capability: "buddy",
        cli_path: "buddy embedding probe",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > local embedding model > Verify",
        ui_callback: Some("bc-embedding-probe"),
        rust_handler: Some("fn register_buddy_embedding_callbacks"),
        dispatch_token: Some("EmbeddingCommandSurface::Buddy, \"probe\""),
        receipt: Evidence::Typed(
            "fn run_embedding_model_command",
            "parse_embedding_models_status",
        ),
        readback: Evidence::Typed(
            "fn start_embedding_model_action",
            "embedding_snapshot_is_fresh_ready_for",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "buddy.embedding.pull",
        capability: "buddy",
        cli_path: "buddy embedding pull",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > local embedding model > Pull",
        ui_callback: Some("bc-embedding-pull"),
        rust_handler: Some("fn register_buddy_embedding_callbacks"),
        dispatch_token: Some("EmbeddingCommandSurface::Buddy, \"pull\""),
        receipt: Evidence::Typed(
            "fn run_embedding_model_command",
            "parse_embedding_models_status",
        ),
        readback: Evidence::Typed(
            "fn start_embedding_model_action",
            "snapshot.selected_model != expected_model",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "buddy.embedding.repair",
        capability: "buddy",
        cli_path: "buddy embedding repair",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > local embedding model > Repair",
        ui_callback: Some("bc-embedding-repair"),
        rust_handler: Some("fn register_buddy_embedding_callbacks"),
        dispatch_token: Some("EmbeddingCommandSurface::Buddy, \"repair\""),
        receipt: Evidence::Typed(
            "fn run_embedding_model_command",
            "parse_embedding_models_status",
        ),
        readback: Evidence::Typed(
            "fn start_embedding_model_action",
            "snapshot.selected_model != expected_model",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "buddy.embedding.prune",
        capability: "buddy",
        cli_path: "buddy embedding prune",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > local embedding model > Prune",
        ui_callback: Some("bc-embedding-prune"),
        rust_handler: Some("fn register_buddy_embedding_callbacks"),
        dispatch_token: Some("EmbeddingCommandSurface::Buddy, \"prune\""),
        receipt: Evidence::Typed(
            "fn run_embedding_model_command",
            "parse_embedding_models_status",
        ),
        readback: Evidence::Typed(
            "fn start_embedding_model_action",
            "snapshot.selected_model != expected_model",
        ),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "buddy.self-activation",
        capability: "buddy",
        cli_path: "buddy self-activation",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > Self-activation",
        ui_callback: Some("bc-selfact-toggle"),
        rust_handler: Some("window.on_bc_selfact_toggle"),
        dispatch_token: Some("[\"buddy\", \"self-activation\", flag]"),
        receipt: Evidence::Typed("window.on_bc_selfact_toggle", "BuddySelfActivationAck"),
        readback: Evidence::Typed("window.on_bc_selfact_toggle", "refresh_buddyconfig"),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "buddy.proactive",
        capability: "buddy",
        cli_path: "buddy proactive",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > Proactive",
        ui_callback: Some("bc-proactive-toggle"),
        rust_handler: Some("window.on_bc_proactive_toggle"),
        dispatch_token: Some("[\"buddy\", \"proactive\", flag]"),
        receipt: Evidence::Typed("window.on_bc_proactive_toggle", "BuddyProactiveAck"),
        readback: Evidence::Typed("window.on_bc_proactive_toggle", "refresh_buddyconfig"),
        state: OperationState::Verified,
    },
    unwired_operation(
        "buddy.vault-mirror.status",
        "buddy",
        "buddy vault-mirror status",
        "buddyconfig",
        "Buddy Config > Vault mirror status",
        "the GUI projects vault-mirror state through buddy status instead of this exact leaf",
    ),
    OperationParity {
        id: "buddy.vault-mirror.repair",
        capability: "buddy",
        cli_path: "buddy vault-mirror repair",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > Vault mirror repair",
        ui_callback: Some("bc-vault-mirror-repair"),
        rust_handler: Some("fn start_vault_mirror_repair"),
        dispatch_token: Some("[\"buddy\", \"vault-mirror\", \"repair\"]"),
        receipt: Evidence::Typed("fn start_vault_mirror_repair", "VaultMirrorRepairAck"),
        readback: Evidence::Typed(
            "fn start_vault_mirror_repair",
            "vault_mirror_readback_matches",
        ),
        state: OperationState::Verified,
    },
    #[cfg(feature = "cluster")]
    OperationParity {
        id: "buddy.cluster.status",
        capability: "buddy",
        cli_path: "buddy cluster status",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > Cluster membership",
        ui_callback: None,
        rust_handler: Some("fn fetch_buddy_cluster_status"),
        dispatch_token: Some("[\"--output\", \"json\", \"buddy\", \"cluster\", \"status\"]"),
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Partial(
            "the GUI projects a parsed cluster snapshot but does not retain a typed status receipt",
        ),
    },
    #[cfg(feature = "cluster")]
    unwired_operation(
        "buddy.cluster.invite",
        "buddy",
        "buddy cluster invite",
        "buddyconfig",
        "Buddy Config > Cluster pairing",
        "the GUI uses its separate pairing transaction rather than this exact CLI leaf",
    ),
    #[cfg(feature = "cluster")]
    unwired_operation(
        "buddy.cluster.confirm",
        "buddy",
        "buddy cluster confirm",
        "buddyconfig",
        "Buddy Config > Cluster pairing",
        "the GUI uses its separate pairing transaction rather than this exact CLI leaf",
    ),
    #[cfg(feature = "cluster")]
    unwired_operation(
        "buddy.cluster.revoke",
        "buddy",
        "buddy cluster revoke",
        "buddyconfig",
        "Buddy Config > Cluster membership",
        "the GUI uses its separate membership-revocation transaction rather than this exact CLI leaf",
    ),
    #[cfg(feature = "cluster")]
    OperationParity {
        id: "buddy.cluster.revoke-status",
        capability: "buddy",
        cli_path: "buddy cluster revoke-status",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > Cluster revocation status",
        ui_callback: None,
        rust_handler: Some("fn fetch_buddy_revocation_status"),
        dispatch_token: Some("[\"buddy\", \"cluster\", \"revoke-status\", request_id]"),
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Partial(
            "the GUI validates the response but does not retain a typed revocation-status receipt",
        ),
    },
    #[cfg(feature = "cluster")]
    OperationParity {
        id: "buddy.cluster.revoke-unresolved",
        capability: "buddy",
        cli_path: "buddy cluster revoke-unresolved",
        gui_nav: "buddyconfig",
        gui_surface: "Buddy Config > Unresolved revocations",
        ui_callback: None,
        rust_handler: Some("fn fetch_buddy_revocation_health"),
        dispatch_token: Some("[\"buddy\", \"cluster\", \"revoke-unresolved\"]"),
        receipt: Evidence::Missing,
        readback: Evidence::Missing,
        state: OperationState::Partial(
            "the GUI validates the health response but does not retain a typed readback receipt",
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
        dispatch_token: Some("fetch_verified_omi_snapshot"),
        receipt: Evidence::Typed("fn fetch_verified_omi_snapshot", "OmiStatusAck"),
        readback: Evidence::Typed(
            "fn fetch_verified_omi_snapshot",
            "omi_snapshot_from_status_ack",
        ),
        state: OperationState::Verified,
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
        receipt: Evidence::Typed("window.on_omi_probe", "OmiProbeAck"),
        // Probe is read-only: semantic verification of its strict response is
        // the readback, rather than a second state query.
        readback: Evidence::Typed("window.on_omi_probe", "acknowledgement.verify()"),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "omi.set-credentials",
        capability: "omi",
        cli_path: "omi set-credentials",
        gui_nav: "privacy",
        gui_surface: "First-run > OMI credentials > Finish",
        ui_callback: Some("finish-clicked"),
        rust_handler: Some("window.on_finish_clicked"),
        dispatch_token: Some("finish(&state)"),
        receipt: Evidence::Untyped("fn finish(", "persist_omi_credentials_via_cli"),
        readback: Evidence::Missing,
        state: OperationState::Partial(
            "the compatibility leaf is still used by first-run setup and checks only process exit; day-two settings use the stronger typed configure transaction",
        ),
    },
    OperationParity {
        id: "omi.configure",
        capability: "omi",
        cli_path: "omi configure",
        gui_nav: "privacy",
        gui_surface: "Privacy > OMI > Save and reload",
        ui_callback: Some("omi-save-clicked"),
        rust_handler: Some("window.on_omi_save"),
        dispatch_token: Some("save_omi_settings("),
        receipt: Evidence::Typed("fn save_omi_settings", "OmiConfigureAck"),
        readback: Evidence::Typed("window.on_omi_save", "fetch_verified_omi_snapshot"),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "omi.purge",
        capability: "omi",
        cli_path: "omi purge",
        gui_nav: "privacy",
        gui_surface: "Privacy > OMI > Permanently purge conversation",
        ui_callback: Some("omi-purge-clicked"),
        rust_handler: Some("window.on_omi_purge"),
        dispatch_token: Some("[\"purge\".into(), conversation_id.clone(), \"--yes\".into()]"),
        receipt: Evidence::Typed("window.on_omi_purge", "OmiDeletionAck"),
        readback: Evidence::Typed("window.on_omi_purge", "fetch_verified_omi_snapshot"),
        state: OperationState::Verified,
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
        receipt: Evidence::Typed("window.on_omi_resume", "OmiResumeAck"),
        readback: Evidence::Typed("window.on_omi_resume", "fetch_verified_omi_snapshot"),
        state: OperationState::Verified,
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
        receipt: Evidence::Typed("window.on_omi_retention", "OmiDeletionAck"),
        readback: Evidence::Typed("window.on_omi_retention", "fetch_verified_omi_snapshot"),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "omi.allow-reimport",
        capability: "omi",
        cli_path: "omi allow-reimport",
        gui_nav: "privacy",
        gui_surface: "Privacy > OMI > Allow re-import",
        ui_callback: Some("omi-reimport-clicked"),
        rust_handler: Some("window.on_omi_reimport"),
        dispatch_token: Some(
            "[\"allow-reimport\".into(), conversation_id.clone(), \"--yes\".into()]",
        ),
        receipt: Evidence::Typed("window.on_omi_reimport", "OmiAllowReimportAck"),
        readback: Evidence::Typed("window.on_omi_reimport", "fetch_verified_omi_snapshot"),
        state: OperationState::Verified,
    },
    OperationParity {
        id: "interface.show",
        capability: "interface",
        cli_path: "interface show",
        gui_nav: "config",
        gui_surface: "first-run interface chooser boot state",
        ui_callback: None,
        rust_handler: Some("fn load_gui_interface_preference"),
        dispatch_token: None,
        receipt: Evidence::Missing,
        readback: Evidence::Typed(
            "fn load_gui_interface_preference",
            "GuiInterfacePreferenceRecord",
        ),
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
        receipt: Evidence::Typed(
            "fn parse_interface_set_acknowledgement",
            "GuiInterfaceSetAcknowledgement",
        ),
        readback: Evidence::Typed(
            "fn validate_interface_set_result",
            "load_gui_interface_preference(home)?",
        ),
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
        receipt: Evidence::Typed("fn launch_cli_terminal", "TerminalHandshake"),
        readback: Evidence::Typed("fn switch_to_cli", "verify_saved_interface_is_cli"),
        state: OperationState::Verified,
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
    (
        "recall-parity-harness",
        CliOnly(
            "offline provenance-evaluation harness; it consumes operator-supplied evidence files and has no GUI workflow or dispatch authority",
        ),
    ),
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
    (
        "context",
        CliOnly(
            "authenticated daemon control-plane client for local context import; no GUI import flow",
        ),
    ),
    (
        "history",
        CliOnly(
            "private historical-export onboarding: interactive no-follow capture and the per-subject scan/preview/review/reject/purge workflow have no GUI dispatch authority; the GUI transcript switcher is read-only session history, not this import surface",
        ),
    ),
    ("skills", Gui("plugins")),
    ("mode", Gui("mode-registry")),
    ("glossary", Gui("wiki")),
    ("privacy", Gui("privacy")),
    ("terminal", CliOnly("embedded terminal launcher")),
    ("tour", CliOnly("onboarding tour")),
    ("groundtruth", Gui("groundtruth")),
    ("citation", Gui("chat")),
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
    (
        "research",
        CliOnly("operator-owned deep-research lifecycle pipe"),
    ),
    ("babel", Gui("babel")),
    ("search", Gui("memory")),
    ("github", CliOnly("github integration pipe")),
    ("slack", Gui("channels")),
    ("todo", Gui("coding")),
    ("lease", CliOnly("resource lease pipe")),
    ("feedback", Gui("chat")),
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
        // A command with an optional subcommand also has a real default
        // operation at its own path. `backup` is the current example: it
        // writes an archive when no `mirror` subcommand is selected.
        if !command.is_subcommand_required_set() {
            paths.push(prefix.to_string());
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

fn rust_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) == Some(&b'r') {
        let hashes = bytes[start + 1..]
            .iter()
            .take_while(|byte| **byte == b'#')
            .count();
        let quote = start + 1 + hashes;
        if bytes.get(quote) == Some(&b'"') {
            return (quote + 1..bytes.len()).find_map(|end_quote| {
                (bytes[end_quote] == b'"'
                    && bytes
                        .get(end_quote + 1..end_quote + 1 + hashes)
                        .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#')))
                .then_some(end_quote + 1 + hashes)
            });
        }
    }

    match bytes.get(start).copied()? {
        b'"' => {
            let mut cursor = start + 1;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'\\' => cursor = cursor.saturating_add(2),
                    b'"' => return Some(cursor + 1),
                    _ => cursor += 1,
                }
            }
            None
        }
        b'\'' => {
            let value = start + 1;
            let value_end = if bytes.get(value) == Some(&b'\\') {
                match bytes.get(value + 1).copied()? {
                    b'u' if bytes.get(value + 2) == Some(&b'{') => bytes[value + 3..]
                        .iter()
                        .position(|byte| *byte == b'}')
                        .map(|offset| value + 4 + offset)?,
                    b'x' => value + 4,
                    _ => value + 2,
                }
            } else {
                value
                    + std::str::from_utf8(&bytes[value..])
                        .ok()?
                        .chars()
                        .next()?
                        .len_utf8()
            };
            (bytes.get(value_end) == Some(&b'\'')).then_some(value_end + 1)
        }
        _ => None,
    }
}

/// Remove Rust comments without changing byte offsets or touching literals.
/// Keeping offsets stable lets the handler extractor slice the original source.
fn strip_rust_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if let Some(end) = rust_literal_end(bytes, cursor) {
            cursor = end;
            continue;
        }
        let comment_start = cursor;
        if bytes[cursor..].starts_with(b"//") {
            while cursor < bytes.len() && !matches!(bytes[cursor], b'\r' | b'\n') {
                cursor += 1;
            }
        } else if bytes[cursor..].starts_with(b"/*") {
            let mut depth = 1_u32;
            cursor += 2;
            while cursor < bytes.len() && depth > 0 {
                if bytes[cursor..].starts_with(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if bytes[cursor..].starts_with(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
        } else {
            cursor += 1;
            continue;
        }
        for byte in &mut output[comment_start..cursor] {
            if !matches!(*byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(output).expect("masking valid Rust source preserves UTF-8")
}

fn operation_handler_source<'a>(source: &'a str, anchor: &str) -> &'a str {
    let uncommented = strip_rust_comments(source);
    let bytes = uncommented.as_bytes();
    let start = uncommented
        .find(anchor)
        .unwrap_or_else(|| panic!("missing Rust handler `{anchor}`"));
    let mut cursor = start + anchor.len();
    while cursor < bytes.len() && bytes[cursor] != b'{' {
        if let Some(end) = rust_literal_end(bytes, cursor) {
            cursor = end;
        } else {
            cursor += 1;
        }
    }
    assert!(cursor < bytes.len(), "Rust handler `{anchor}` has no body");

    let mut depth = 1_u32;
    cursor += 1;
    while cursor < bytes.len() {
        if let Some(end) = rust_literal_end(bytes, cursor) {
            cursor = end;
            continue;
        }
        match bytes[cursor] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=cursor];
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    panic!("Rust handler `{anchor}` has an unterminated body");
}

fn compact_rust(source: &str) -> String {
    strip_rust_comments(source)
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .replace(",]", "]")
}

fn handler_contains_token(source: &str, handler: &str, token: &str) -> bool {
    compact_rust(operation_handler_source(source, handler)).contains(&compact_rust(token))
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
            operation_handler_source(GUI_RUST, handler);
        }
        if let Some(dispatch) = operation.dispatch_token {
            let handler = operation
                .rust_handler
                .expect("a dispatch token requires a Rust handler anchor");
            assert!(
                handler_contains_token(GUI_RUST, handler, dispatch),
                "operation `{}` handler `{handler}` does not contain dispatch token `{dispatch}`",
                operation.id
            );
        }
        for (kind, evidence) in [
            ("receipt", operation.receipt),
            ("readback", operation.readback),
        ] {
            if let Evidence::Typed(handler, token) | Evidence::Untyped(handler, token) = evidence {
                assert!(
                    handler_contains_token(GUI_RUST, handler, token),
                    "operation `{}` {kind} handler `{handler}` does not contain evidence token `{token}`",
                    operation.id
                );
            }
        }
        match operation.state {
            OperationState::Verified => {
                assert!(operation.ui_callback.is_some());
                assert!(operation.rust_handler.is_some());
                assert!(operation.dispatch_token.is_some());
                assert!(matches!(operation.receipt, Evidence::Typed(..)));
                assert!(matches!(operation.readback, Evidence::Typed(..)));
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
fn operation_evidence_in_another_handler_does_not_count() {
    const GUI_RUST: &str = r#"
    window.on_target(move || {
        show_pending();
    });
    window.on_other(move || {
        dispatch_target();
        let _: TargetReceipt = receive();
        read_back_target();
    });
"#;

    for token in ["dispatch_target()", "TargetReceipt", "read_back_target()"] {
        assert!(!handler_contains_token(GUI_RUST, "window.on_target", token));
        assert!(handler_contains_token(GUI_RUST, "window.on_other", token));
    }
}

#[test]
fn operation_evidence_in_comments_does_not_count() {
    const GUI_RUST: &str = r###"
    window.on_target(move || {
        // dispatch_target();
        /* TargetReceipt */
        /* read_back_target();
           /* nested block comments are legal Rust */
        */
        let url = "https://example.test/a//b";
        let raw = r#"/* literal, not a comment */"#;
        let brace = '}';
    });
    window.on_other(move || {});
"###;

    for token in ["dispatch_target()", "TargetReceipt", "read_back_target()"] {
        assert!(!handler_contains_token(GUI_RUST, "window.on_target", token));
    }
    let stripped = strip_rust_comments(GUI_RUST);
    assert!(stripped.contains("https://example.test/a//b"));
    assert!(stripped.contains("r#\"/* literal, not a comment */\"#"));
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
        "omi.set-credentials",
        "interface.show",
        "models.ollama.status",
        "models.catalog",
        "models.recommend",
        "models.embedding.status",
        "buddy.status",
        "buddy.embedding.status",
    ] {
        assert!(
            partial.contains(expected),
            "`{expected}` must remain explicitly partial until its typed receipt/readback gap is fixed"
        );
    }
    #[cfg(feature = "cluster")]
    for expected in [
        "buddy.cluster.status",
        "buddy.cluster.revoke-status",
        "buddy.cluster.revoke-unresolved",
    ] {
        assert!(
            partial.contains(expected),
            "`{expected}` must remain explicitly partial until its typed receipt/readback gap is fixed"
        );
    }

    let mut expected_unwired = BTreeSet::from([
        "backup.mirror-status",
        "backup.mirror-run",
        "backup.mirror-repair",
        "models.list",
        "models.pull",
        "models.prune",
        "models.fit",
        "models.bge-m3.list",
        "models.bge-m3.status",
        "models.bge-m3.pull",
        "models.bge-m3.repair",
        "models.bge-m3.prune",
        "models.embedding.list",
        "buddy.embedding.list",
        "buddy.vault-mirror.status",
        "restore.archive",
    ]);
    #[cfg(feature = "cluster")]
    expected_unwired.extend([
        "buddy.cluster.invite",
        "buddy.cluster.confirm",
        "buddy.cluster.revoke",
    ]);
    assert_eq!(unwired, expected_unwired);
}
