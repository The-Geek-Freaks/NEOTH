//! Write-side I/O for the `neoth init` wizard (GOLD-ARCH-05): secure dir/file
//! creation, atomic writes, config + .initialized marker persistence, summary
//! and post-write steps. Split out of `cli/init.rs`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use super::{
    InitArgs, OperatorRole, ProviderKind, WizardState, WizardStep, spawn_daemon_detached,
    try_inline_consent_grant, write_first_tour_marker,
};

/// Defaults owned by the onboarding contract rather than by `FreedomConfig`.
/// The config-level audit-RPC default stays off for source/manual configs, but
/// a successful fresh wizard enables the loopback listener so one-shot CLIs
/// can append to the daemon-owned WAL. `--force` hydration may overwrite this
/// with the operator's existing explicit choice.
pub(crate) fn fresh_wizard_state() -> WizardState {
    let mut state = WizardState::default();
    state.audit_rpc.enabled = true;
    state
}

/// Hydrate every complete config object owned by the init wizard before a
/// `--force` run. Steps then mutate only the answers they actually collect;
/// advanced known fields retain their prior values, while the YAML merge in
/// [`write_config`] preserves unknown future fields as well.
pub(crate) fn hydrate_existing_init_state(
    neoth_dir: &std::path::Path,
    state: &mut WizardState,
) -> Result<()> {
    let path = neoth_dir.join("freedom.yaml");
    if !path.exists() {
        return Ok(());
    }
    let existing = match crate::config::FreedomConfig::load_from_path(&path) {
        Ok(existing) => existing,
        Err(error) => {
            tracing::warn!(
                %error,
                path = %path.display(),
                "existing freedom.yaml is corrupt; init recovery is starting from safe defaults"
            );
            return Ok(());
        }
    };
    state.secrets_backend = existing.secrets_backend;
    state.operator_id = existing.operator_id;
    state.language_primary = existing.language_primary;
    state.language_code = existing.language_code;
    state.role = existing.role;
    state.role_custom = existing.role_custom;
    state.provider_kind = existing.provider_kind;
    state.provider_binary = existing.provider_binary;
    state.provider_endpoint = existing.provider_endpoint;
    state.provider_model = existing.provider_model;
    state.provider_region = existing.provider_region;
    state.provider_api_version = existing.provider_api_version;
    state.telegram_user_id = existing.telegram_user_id;
    state.autonomy = existing.autonomy;
    state.custom_autonomy = existing.custom_autonomy;
    state.inference = existing.inference;
    // `load_from_path` supplements these from credentials/keychain. Hydration
    // is for public config only: do not pull effective secrets back into wizard
    // state and accidentally migrate keychain values into freedom.yaml/file.
    state.inference.left.key = None;
    state.inference.right.key = None;
    state.inference.cerebellum.key = None;
    state.inference.default_slot.key = None;
    state.auto_update = existing.auto_update;
    state.plugins = existing.plugins;
    state.supervisor = existing.supervisor;
    state.companion = existing.companion;
    state.omi = existing.omi;
    state.audit_rpc = existing.audit_rpc;
    state.onboarding_complete = existing.onboarding_complete;
    state.chat_onboarding_completed = existing.chat_onboarding_completed;
    Ok(())
}

/// Step 9 (post-write) — optional ground-truth Q&A. Always interactive.
///
/// Operator gets one confirm prompt. If they decline, the daemon is fully
/// usable; ground truth can be added later. Failures here log and continue
/// so a bad question bank doesn't block the freshly-written config.
pub(crate) fn maybe_run_groundtruth_qa(state: &WizardState) -> Result<()> {
    #[cfg(feature = "wizard")]
    {
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Seed ground-truth facts now? (~5 min Q&A — can skip / run later)")
            .default(true)
            .interact()
            .context("groundtruth Q&A opt-in")?;
        if !want {
            println!(
                "  Skipped. Re-run any time: `neoth groundtruth ask` or \
                 `neoth groundtruth add \"...\"`."
            );
            return Ok(());
        }

        let bank = match crate::cli::groundtruth_wizard::load_bank() {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "ground-truth Q&A skipped: bank load failed");
                return Ok(());
            }
        };
        let lang = state.language_primary.as_deref().unwrap_or("en");
        let answers = match crate::cli::groundtruth_wizard::run_qa(&bank, lang) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "ground-truth Q&A aborted");
                return Ok(());
            }
        };
        let now_ns = crate::time::now_unix_ns_i64(); // ARCH-07b: exact semantics match
        let db = crate::memory::store::default_path();
        match crate::cli::groundtruth_wizard::persist_answers(&db, &bank, &answers, lang, now_ns) {
            Ok(n) => println!("  {n} ground-truth row(s) stored."),
            Err(e) => tracing::warn!(error = %e, "ground-truth persist failed"),
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        let _ = state;
        println!(
            "(no TTY wizard available; run `neoth groundtruth ask` from a terminal to seed facts)"
        );
    }
    Ok(())
}

/// R-05 (Session 24) — final wizard step (interactive only). Offers
/// `Start NEOTH now? [Y/n]`. On Yes:
///   1. Spawns `neoth serve` as a detached background process so the
///      operator's terminal returns immediately + the daemon survives
///      the wizard process exit.
///   2. Drops the [`FIRST_TOUR_MARKER`] file so the next interactive
///      `neoth chat` session prepends the "Hi, I'm running. Want a
///      quick tour?" greeting.
///   3. Prints a confirmation line with the spawned PID + suggested
///      first command.
///
/// On No: prints a hint pointing at `neoth serve` and the same first-
/// tour suggestion. The marker is still written so a later
/// operator-initiated `neoth serve` + `neoth chat` lands in the same
/// onboarding-aware path.
pub(crate) fn step9_offer_start_daemon(neoth_dir: &std::path::Path) -> Result<()> {
    #[cfg(feature = "wizard")]
    {
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Start NEOTH now?")
            .default(true)
            .interact()
            .context("auto-start daemon confirm")?;

        // Always drop the first-tour marker — operator might start
        // the daemon later by hand, and the next chat session should
        // still feel like the first.
        if let Err(e) = write_first_tour_marker(neoth_dir) {
            tracing::warn!(error = %e, "first-tour marker write failed (cosmetic)");
        }

        if want {
            match spawn_daemon_detached() {
                Ok(pid) => println!(
                    "✓ NEOTH daemon started (pid {pid}). \
                     Try: `neoth chat \"give me a tour\"`",
                ),
                Err(e) => {
                    tracing::warn!(error = %e, "auto-start spawn failed");
                    println!(
                        "Couldn't auto-start the daemon ({e}). \
                         Run `neoth serve` from a new terminal, then \
                         `neoth chat \"give me a tour\"`."
                    );
                }
            }
        } else {
            println!(
                "Start NEOTH any time with `neoth serve`. \
                 First-chat suggestion: `neoth chat \"give me a tour\"`."
            );
        }
        Ok(())
    }
    #[cfg(not(feature = "wizard"))]
    {
        // No dialoguer build → leave the marker so the operator's
        // first chat session still gets the tour, and tell them how
        // to start the daemon.
        let _ = write_first_tour_marker(neoth_dir);
        println!(
            "Start NEOTH with `neoth serve` (run in a separate terminal). \
             First-chat suggestion: `neoth chat \"give me a tour\"`."
        );
        Ok(())
    }
}

pub(crate) fn step8_summary(args: &InitArgs, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 8: summary");
    // Step 7 (autonomy) already pushed `7`; pushing again here corrupted
    // `.initialized.steps_completed` so a partial-resume couldn't tell
    // whether step 7 had actually run. Step 8 is its own marker.
    state.steps_completed.push(WizardStep::Summary as u8);
    let role_display = match state.role {
        Some(OperatorRole::Developer) => "developer",
        Some(OperatorRole::SecurityResearcher) => "security-researcher",
        Some(OperatorRole::Founder) => "founder",
        Some(OperatorRole::DataScientist) => "data-scientist",
        Some(OperatorRole::Writer) => "writer",
        Some(OperatorRole::None) | None => "none",
    };
    // COR-13: as_provider_id() canonicalises the status form; Skip/None
    // both render "none" (was "(none)" here, "unconfigured" in jobs,
    // "unknown" in serve).
    let provider_display = state
        .provider_kind
        .map(|k| k.as_provider_id())
        .unwrap_or("none");
    println!("\n[9/9] Setup Complete\n");
    println!(
        "  Operator:  {}",
        state.operator_id.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  Language:  {} / code: {}",
        state.language_primary.as_deref().unwrap_or("en"),
        state.language_code.as_deref().unwrap_or("en")
    );
    println!("  Role:      {role_display}");
    println!("  Provider:  {provider_display}");
    // Render the actually configured wizard channels only.
    let channels = configured_channels(state);
    let channel_line = match channels.as_slice() {
        [] => "none".to_string(),
        [one] => match one.as_str() {
            "telegram" => "Telegram".to_string(),
            other => other.to_string(),
        },
        [primary, secondary] => {
            fn pretty(s: &str) -> &str {
                match s {
                    "telegram" => "Telegram",
                    other => other,
                }
            }
            format!(
                "{} (primary) / {} (secondary)",
                pretty(primary),
                pretty(secondary)
            )
        }
        many => many.join(", "),
    };
    println!("  Channel:   {channel_line}");
    if state.omi.enabled {
        let mode = match state.omi.mode {
            crate::config::OmiIngestMode::DeveloperApi => "developer_api",
            crate::config::OmiIngestMode::NativeIngest => "native_ingest",
            crate::config::OmiIngestMode::Both => "both",
            crate::config::OmiIngestMode::LegacyMemories => "legacy_memories",
        };
        println!(
            "  OMI:       enabled ({mode}, {} day retention; transcript/audio/image/video = {}/{}/{}/{})",
            state.omi.retention_days,
            state.omi.retain_transcripts,
            state.omi.audio_enabled,
            state.omi.visual_enabled,
            state.omi.video_enabled,
        );
    } else {
        println!("  OMI:       disabled (privacy default)");
    }
    // JV-IMP-08: surface import intent so migration operators see it confirmed.
    if let Some(ref p) = state.import_memory {
        println!(
            "  Import:    {} (run `neoth-migrate dry-run --manifest {}` to preview)",
            p.display(),
            p.display()
        );
    }
    // Pick #34 (Session 14, operator-flow audit-fix Flow#1): surface
    // the consent-gate requirement BEFORE the operator runs `neoth
    // chat` and hits the consent-prompt cold. The gate exists for
    // every cloud provider (V03-08 + A-2 hard rule) — operators who
    // never read the docs reach `chat` first, see a consent-failure
    // error with no context, and don't know which command unblocks
    // them. The hint here connects wizard → consent → chat in one
    // operator-visible breath.
    // Canonical cloud classifier (GOLD-SEC-09 / A-25) — the prior inline
    // set MISSED AnthropicApi + Cohere, so operators picking those got no
    // inline consent pre-grant and hit an opaque consent-failure on first
    // `neoth chat`. Route through `consent::is_cloud` (the single source).
    let cloud_provider = state.provider_kind.is_some_and(crate::consent::is_cloud);
    if cloud_provider {
        // V03-08 — don't just PRINT the consent command (a noob ignores
        // it, runs `neoth chat`, hits an opaque consent-failure, and
        // stops). Offer to grant it inline now so first chat just works.
        // Interactive TTY only; non-interactive / decline / no-wizard
        // falls back to the printed hint. `consent::grant` is idempotent.
        let granted_inline = try_inline_consent_grant(args, state.provider_kind, provider_display);
        if !granted_inline {
            println!(
                "\n  Consent gate (V03-08): `neoth chat` will prompt you to grant cloud-egress consent\n  \
                 for `{provider_display}` on first run. Pre-grant with:\n  \
                 `neoth consent grant {provider_display}`"
            );
        }
    }
    if !args.dry_run {
        println!("\nNext: neoth chat  |  neothd  |  neoth profile show");
    }
    println!("\nneoth knows. Good luck.");
    Ok(())
}

pub(crate) fn run_reconfigure_menu(_args: &InitArgs) -> Result<()> {
    println!("Neoth is already initialized.");
    println!();
    println!("To reconfigure individual sections, use:");
    println!("  neoth hemispheres set     # configure or change an LLM provider");
    println!("  neoth channel add <kind>  # add a chat channel");
    println!("  neoth profile show        # inspect operator profile");
    println!();
    println!("To re-run the full wizard from scratch, pass --force.");
    Ok(())
}

/// `.initialized` marker payload (F-22).
///
/// Written once at the end of `neoth init`. Backward-compatible reads
/// rely on `#[serde(default)]` so an older marker (without `neoth_version`,
/// `init_time_iso8601`, `provider_kind`, `channels`) still parses.
///
/// What each field is for:
///   - `wizard_version` — schema version of THIS struct. Bump when a
///     field becomes required so `read_marker` can flag stale markers.
///   - `neoth_version` — the daemon binary version that wrote it.
///     `neoth doctor` uses this to detect "marker says v0.1, binary is
///     v0.2 — operator might want to re-run wizard for new steps".
///   - `operator_id` — pinned identity. Mismatched ops on the
///     `freedom.yaml` carry the operator_id; the marker pins it for
///     boot-time cross-check (BS-9 isolation builds on this).
///   - `init_time_unix` — original epoch seconds (kept for old code).
///   - `init_time_iso8601` — same instant, human-readable.
///   - `steps_completed` — wizard step numbers that ran successfully.
///   - `provider_kind` — which LLM the wizard configured. `neoth doctor`
///     surfaces this so the operator can confirm at-a-glance.
///   - `channels` — sorted, stable list of channel ids configured at
///     onboarding (`["telegram"]`, etc).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitializedMarker {
    pub(crate) wizard_version: u8,
    #[serde(default)]
    pub(crate) neoth_version: String,
    pub(crate) operator_id: String,
    pub(crate) steps_completed: Vec<u8>,
    pub(crate) init_time_unix: u64,
    #[serde(default)]
    pub(crate) init_time_iso8601: String,
    #[serde(default)]
    pub(crate) provider_kind: Option<ProviderKind>,
    #[serde(default)]
    pub(crate) channels: Vec<String>,
    /// Present only for a marker committed by the GUI transaction bridge.
    /// `None` keeps every pre-bridge marker backward compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) gui_transaction_id: Option<String>,
    /// SHA-256 of the exact `freedom.yaml` bytes validated before the GUI
    /// marker became visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) config_sha256: Option<String>,
}

const MAX_INITIALIZED_MARKER_BYTES: u64 = 64 * 1024;
const MAX_INITIALIZATION_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const GUI_INIT_SCHEMA_VERSION: u8 = 1;
const GUI_INIT_PENDING_DIR: &str = ".gui-init";
const GUI_INIT_PENDING_FILE: &str = "pending.json";
const GUI_INIT_LOCK_FILE: &str = ".gui-init.lock";
const MAX_GUI_INIT_PENDING_BYTES: u64 = 8 * 1024;
const GUI_INIT_SECRET_HEX_LEN: usize = 64;
const MAX_GUI_COMPLETION_STDIN_BYTES: u64 = (GUI_INIT_SECRET_HEX_LEN + 2) as u64;
static GUI_INIT_PROCESS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuiInitPending {
    schema_version: u8,
    transaction_id: String,
    token: String,
    home: PathBuf,
    config_path: PathBuf,
    /// Digest of the marker visible when this transaction began. A matching
    /// digest is the old generation, not a completion proof.
    base_marker_sha256: Option<String>,
    created_unix: u64,
}

#[derive(Clone, Serialize)]
pub(crate) struct GuiInitBeginAcknowledgement {
    pub(crate) schema_version: u8,
    pub(crate) transaction_id: String,
    pub(crate) token: String,
    pub(crate) home: PathBuf,
    pub(crate) pending_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GuiInitCompletionAcknowledgement {
    pub(crate) schema_version: u8,
    pub(crate) completed: bool,
    pub(crate) ready: bool,
    pub(crate) transaction_id: String,
    pub(crate) home: PathBuf,
    pub(crate) marker_path: PathBuf,
}

struct InitializedMarkerFile {
    marker: InitializedMarker,
    sha256: String,
}

struct InitializationConfigFile {
    config: crate::config::FreedomConfig,
    sha256: String,
}

/// Canonical launcher/readiness boundary shared by bare CLI dispatch and the
/// daemon-owned GUI completion command. Missing halves mean onboarding is not
/// complete. Existing malformed state is never folded into "first run", where
/// a new wizard could overwrite the evidence.
pub(crate) fn initialized_home_is_ready(home: &std::path::Path) -> Result<bool> {
    let metadata = match std::fs::symlink_metadata(home) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", home.display())),
    };
    validate_directory_kind(home, &metadata)?;
    with_gui_init_lock(home, || initialized_home_is_ready_locked(home))
}

fn initialized_home_is_ready_locked(home: &std::path::Path) -> Result<bool> {
    let pending = read_gui_init_pending(home)?;
    let marker = read_initialized_marker(home)?;
    let config_path = home.join("freedom.yaml");
    let config = read_initialization_config(&config_path)?;

    if let Some(pending) = pending {
        let Some(marker) = marker else {
            if let Some(config) = &config {
                validated_config_operator(&config.config, &config_path)?;
            }
            return Ok(false);
        };
        let Some(config) = config else {
            anyhow::bail!(
                "{} exists while GUI transaction {} is pending, but {} is missing; finish or restart GUI onboarding",
                home.join(".initialized").display(),
                pending.transaction_id,
                config_path.display()
            );
        };
        validated_config_operator(&config.config, &config_path)?;

        let baseline_marker = pending.base_marker_sha256.as_deref() == Some(marker.sha256.as_str());
        if baseline_marker {
            // The old marker may name the previous operator/config while GUI
            // reconfiguration is preparing the replacement. The current
            // config is valid, but this generation has not committed yet.
            return Ok(false);
        }

        validate_marker_config_pair(&marker.marker, &config, home, &config_path)?;
        // The baseline generation returned false above. Therefore any marker
        // reaching this point is a different, fully validated commit: either
        // this GUI transaction's irreversible marker (crash before cleanup) or
        // a later completion that superseded the pending transaction. Both are
        // monotonically ready; only the stale pending record remains to clean.
        cleanup_gui_init_pending_best_effort(home);
        return Ok(true);
    }

    let (marker, config) = match (marker, config) {
        (None, None) => return Ok(false),
        // Legacy GUI onboarding wrote the complete, validated config but no
        // marker. A canonical operator identity is the minimum completion
        // proof; a parseable default YAML stub is still incomplete.
        (None, Some(config)) => {
            validated_config_operator(&config.config, &config_path)?;
            return Ok(true);
        }
        (Some(_), None) => {
            anyhow::bail!(
                "{} declares completed onboarding but {} is missing; run `neoth init --force` to repair the pair",
                home.join(".initialized").display(),
                config_path.display()
            );
        }
        (Some(marker), Some(config)) => (marker, config),
    };
    validate_marker_config_pair(&marker.marker, &config, home, &config_path)?;
    Ok(true)
}

fn validate_marker_config_pair(
    marker: &InitializedMarker,
    config: &InitializationConfigFile,
    home: &Path,
    config_path: &Path,
) -> Result<()> {
    let config_operator = validated_config_operator(&config.config, config_path)?;
    super::validate_operator_id(marker.operator_id.trim()).with_context(|| {
        format!(
            "initialization marker {} has an invalid operator_id",
            home.join(".initialized").display()
        )
    })?;
    if config_operator != marker.operator_id.trim() {
        anyhow::bail!(
            "initialization identity mismatch: {} names `{}` but {} names `{}`; run `neoth init --force` to repair the pair",
            home.join(".initialized").display(),
            marker.operator_id,
            config_path.display(),
            config_operator
        );
    }
    Ok(())
}

fn validated_config_operator<'a>(
    config: &'a crate::config::FreedomConfig,
    config_path: &std::path::Path,
) -> Result<&'a str> {
    let operator = config
        .operator_id
        .as_deref()
        .map(str::trim)
        .filter(|operator| !operator.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "initialization config {} has no operator_id; run `neoth init --force` to finish onboarding",
                config_path.display()
            )
        })?;
    super::validate_operator_id(operator).with_context(|| {
        format!(
            "initialization config {} has an invalid operator_id",
            config_path.display()
        )
    })?;
    Ok(operator)
}

fn read_initialized_marker(home: &std::path::Path) -> Result<Option<InitializedMarkerFile>> {
    let path = home.join(".initialized");
    let Some(bytes) = read_bounded_regular_file(&path, MAX_INITIALIZED_MARKER_BYTES)? else {
        return Ok(None);
    };
    let marker: InitializedMarker = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "initialization marker {} is malformed; run `neoth init --force` to repair it",
            path.display()
        )
    })?;
    validate_initialized_marker(&marker, &path)?;
    Ok(Some(InitializedMarkerFile {
        marker,
        sha256: sha256_hex(&bytes),
    }))
}

fn validate_initialized_marker(marker: &InitializedMarker, path: &std::path::Path) -> Result<()> {
    if !matches!(marker.wizard_version, 1 | 2) {
        anyhow::bail!(
            "initialization marker {} uses unsupported wizard_version {}; supported versions are 1 and 2; run `neoth init --force` to repair it",
            path.display(),
            marker.wizard_version
        );
    }
    if marker.operator_id.trim().is_empty() {
        anyhow::bail!(
            "initialization marker {} has an empty operator_id; run `neoth init --force` to repair it",
            path.display()
        );
    }
    if marker.steps_completed.is_empty() {
        anyhow::bail!(
            "initialization marker {} has no completed wizard steps; run `neoth init --force` to repair it",
            path.display()
        );
    }
    let mut seen_steps = std::collections::HashSet::new();
    for &raw in &marker.steps_completed {
        WizardStep::try_from(raw).with_context(|| {
            format!(
                "initialization marker {} contains unknown wizard step {raw}; run `neoth init --force` to repair it",
                path.display()
            )
        })?;
        seen_steps.insert(raw);
    }
    if marker.wizard_version == 1 {
        if let Some(missing) = (1u8..=7).find(|step| !seen_steps.contains(step)) {
            anyhow::bail!(
                "legacy initialization marker {} is missing completed core step {missing}; run `neoth init --force` to finish onboarding",
                path.display()
            );
        }
    } else if !seen_steps.contains(&u8::from(WizardStep::Summary)) {
        anyhow::bail!(
            "initialization marker {} does not include the completed Summary step; run `neoth init --force` to finish onboarding",
            path.display()
        );
    }
    if marker.init_time_unix == 0 {
        anyhow::bail!(
            "initialization marker {} has an invalid zero init_time_unix; run `neoth init --force` to repair it",
            path.display()
        );
    }

    if marker.wizard_version == 2 {
        if marker.neoth_version.trim().is_empty() {
            anyhow::bail!(
                "initialization marker {} has no neoth_version; run `neoth init --force` to repair it",
                path.display()
            );
        }
        let parsed_time = chrono::DateTime::parse_from_rfc3339(&marker.init_time_iso8601)
            .with_context(|| {
                format!(
                    "initialization marker {} has an invalid init_time_iso8601; run `neoth init --force` to repair it",
                    path.display()
                )
            })?;
        if parsed_time.timestamp() < 0 || parsed_time.timestamp() as u64 != marker.init_time_unix {
            anyhow::bail!(
                "initialization marker {} has disagreeing init timestamps; run `neoth init --force` to repair it",
                path.display()
            );
        }
        if marker
            .channels
            .iter()
            .any(|channel| channel.trim().is_empty())
            || marker.channels.windows(2).any(|pair| pair[0] >= pair[1])
        {
            anyhow::bail!(
                "initialization marker {} has non-canonical channels; run `neoth init --force` to repair it",
                path.display()
            );
        }
    }
    match (&marker.gui_transaction_id, &marker.config_sha256) {
        (None, None) => {}
        (Some(transaction_id), Some(config_sha256)) => {
            require_lower_hex_64(transaction_id, "GUI transaction id")?;
            require_lower_hex_64(config_sha256, "GUI config SHA-256")?;
            if marker.wizard_version != 2 {
                anyhow::bail!(
                    "initialization marker {} binds a GUI transaction with legacy wizard_version {}; run `neoth init --force` to repair it",
                    path.display(),
                    marker.wizard_version
                );
            }
        }
        _ => {
            anyhow::bail!(
                "initialization marker {} has an incomplete GUI transaction binding; run `neoth init --force` to repair it",
                path.display()
            );
        }
    }
    Ok(())
}

fn read_initialization_config(path: &Path) -> Result<Option<InitializationConfigFile>> {
    let Some(bytes) = read_bounded_regular_file(path, MAX_INITIALIZATION_CONFIG_BYTES)
        .with_context(|| format!("inspect initialization config {}", path.display()))?
    else {
        return Ok(None);
    };
    let config: crate::config::FreedomConfig = serde_yaml::from_slice(&bytes).with_context(|| {
        format!(
            "existing initialization config {} is invalid; run `neoth init --force` to repair it",
            path.display()
        )
    })?;
    config
        .companion
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid companion config: {error}"))?;
    config
        .swarm
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid swarm config: {error}"))?;
    config
        .cluster
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid cluster config: {error}"))?;
    Ok(Some(InitializationConfigFile {
        config,
        sha256: sha256_hex(&bytes),
    }))
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("{} must be a regular, non-symlink file", path.display());
    }
    if metadata.len() > max_bytes {
        anyhow::bail!("{} exceeds the {max_bytes}-byte limit", path.display());
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len().min(max_bytes) as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("{} exceeds the {max_bytes}-byte limit", path.display());
    }
    Ok(Some(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn require_lower_hex_64(value: &str, field: &str) -> Result<()> {
    if value.len() != GUI_INIT_SECRET_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("{field} must be exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn gui_init_pending_dir(home: &Path) -> PathBuf {
    home.join(GUI_INIT_PENDING_DIR)
}

fn gui_init_pending_path(home: &Path) -> PathBuf {
    gui_init_pending_dir(home).join(GUI_INIT_PENDING_FILE)
}

fn with_gui_init_lock<T>(home: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let _process_guard = GUI_INIT_PROCESS_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("GUI initialization process lock is poisoned"))?;
    let lock_path = home.join(GUI_INIT_LOCK_FILE);
    let _file_guard =
        crate::util::locked_file::lock_file_blocking(&lock_path, "GUI initialization transaction")?;
    action()
}

fn read_gui_init_pending(home: &Path) -> Result<Option<GuiInitPending>> {
    let pending_dir = gui_init_pending_dir(home);
    let metadata = match std::fs::symlink_metadata(&pending_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", pending_dir.display()));
        }
    };
    validate_private_directory_metadata(&pending_dir, &metadata)?;

    let pending_path = gui_init_pending_path(home);
    let file_metadata = match std::fs::symlink_metadata(&pending_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", pending_path.display()));
        }
    };
    validate_private_file_metadata(&pending_path, &file_metadata)?;
    let bytes = read_bounded_regular_file(&pending_path, MAX_GUI_INIT_PENDING_BYTES)?
        .ok_or_else(|| anyhow::anyhow!("GUI Pending-State disappeared while it was read"))?;
    let pending: GuiInitPending = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "GUI Pending-State {} is malformed; restart GUI onboarding after preserving it for diagnosis",
            pending_path.display()
        )
    })?;
    validate_gui_init_pending(&pending, home, &pending_path)?;
    Ok(Some(pending))
}

fn validate_gui_init_pending(pending: &GuiInitPending, home: &Path, path: &Path) -> Result<()> {
    if pending.schema_version != GUI_INIT_SCHEMA_VERSION {
        anyhow::bail!(
            "GUI Pending-State {} uses unsupported schema_version {}",
            path.display(),
            pending.schema_version
        );
    }
    require_lower_hex_64(&pending.transaction_id, "GUI transaction id")?;
    require_lower_hex_64(&pending.token, "GUI completion token")?;
    if let Some(base_marker_sha256) = &pending.base_marker_sha256 {
        require_lower_hex_64(base_marker_sha256, "GUI baseline marker SHA-256")?;
    }
    if pending.created_unix == 0 {
        anyhow::bail!(
            "GUI Pending-State {} has an invalid timestamp",
            path.display()
        );
    }

    let canonical_home = std::fs::canonicalize(home)
        .with_context(|| format!("canonicalize GUI initialization home {}", home.display()))?;
    let expected_config = canonical_home.join("freedom.yaml");
    if pending.home != canonical_home || pending.config_path != expected_config {
        anyhow::bail!(
            "GUI Pending-State {} is bound to a different home/config; preserve it and restart onboarding from {}",
            path.display(),
            canonical_home.display()
        );
    }
    Ok(())
}

fn validate_private_directory_metadata(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    validate_directory_kind(path, metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            anyhow::bail!("{} must have mode 0700", path.display());
        }
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_directory_dacl(path)
        .with_context(|| format!("verify private DACL on {}", path.display()))?;
    Ok(())
}

fn validate_directory_kind(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    let is_link_or_reparse = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let is_link_or_reparse = {
        use std::os::windows::fs::MetadataExt;
        is_link_or_reparse
            || metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
    };
    if is_link_or_reparse || !metadata.is_dir() {
        anyhow::bail!(
            "{} must be a private, non-symlink directory",
            path.display()
        );
    }
    Ok(())
}

fn validate_private_file_metadata(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("{} must be a private, non-symlink file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            anyhow::bail!("{} must have mode 0600", path.display());
        }
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_dacl(path)
        .with_context(|| format!("verify private DACL on {}", path.display()))?;
    Ok(())
}

fn gui_begin_ack(pending: &GuiInitPending) -> GuiInitBeginAcknowledgement {
    GuiInitBeginAcknowledgement {
        schema_version: GUI_INIT_SCHEMA_VERSION,
        transaction_id: pending.transaction_id.clone(),
        token: pending.token.clone(),
        home: pending.home.clone(),
        pending_path: gui_init_pending_path(&pending.home),
    }
}

pub(crate) fn parse_gui_completion_token(input: &str) -> Result<&str> {
    let token = input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(input);
    require_lower_hex_64(token, "GUI completion token")?;
    Ok(token)
}

pub(crate) fn read_gui_completion_token_from_stdin() -> Result<String> {
    let mut input = String::new();
    std::io::stdin()
        .lock()
        .take(MAX_GUI_COMPLETION_STDIN_BYTES + 1)
        .read_to_string(&mut input)
        .context("read bounded GUI completion token from stdin")?;
    if input.len() as u64 > MAX_GUI_COMPLETION_STDIN_BYTES {
        anyhow::bail!("GUI completion token input exceeds the bounded stdin contract");
    }
    Ok(parse_gui_completion_token(&input)?.to_string())
}

fn cleanup_gui_init_pending_best_effort(home: &Path) {
    let pending_path = gui_init_pending_path(home);
    if let Err(error) = std::fs::remove_file(&pending_path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            %error,
            path = %pending_path.display(),
            "GUI initialization committed; stale Pending-State cleanup will be retried"
        );
    }
    let pending_dir = gui_init_pending_dir(home);
    if let Err(error) = std::fs::remove_dir(&pending_dir)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            %error,
            path = %pending_dir.display(),
            "GUI initialization committed; Pending-State directory cleanup was best-effort"
        );
    }
}

pub(crate) fn ensure_dir_secure(dir: &std::path::Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) => validate_directory_kind(dir, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create parent directory {}", parent.display()))?;
            }
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                builder
            };
            #[cfg(not(unix))]
            let builder = std::fs::DirBuilder::new();
            if let Err(error) = builder.create(dir)
                && error.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(error)
                    .with_context(|| format!("create private directory {}", dir.display()));
            }
            let metadata = std::fs::symlink_metadata(dir)
                .with_context(|| format!("inspect created directory {}", dir.display()))?;
            validate_directory_kind(dir, &metadata)?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect directory {}", dir.display()));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms)
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    #[cfg(windows)]
    crate::wal::win_native::set_private_current_user_directory_dacl(dir)
        .with_context(|| format!("set private DACL on {}", dir.display()))?;
    let metadata = std::fs::symlink_metadata(dir)
        .with_context(|| format!("verify private directory {}", dir.display()))?;
    validate_private_directory_metadata(dir, &metadata)?;
    Ok(())
}

/// Open a file for exclusive create with mode 0600/current-user-only DACL
/// before the caller can write any bytes.
pub(crate) fn open_for_create_secure(path: &std::path::Path) -> Result<std::fs::File> {
    #[cfg(windows)]
    {
        crate::wal::win_native::create_private_file_new(path)
            .with_context(|| format!("secure create {}", path.display()))
    }

    #[cfg(not(windows))]
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(path)
            .with_context(|| format!("open_for_create {}", path.display()))?;
        Ok(file)
    }
}

fn private_temp_sibling(target: &Path) -> Result<PathBuf> {
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| anyhow::anyhow!("OS RNG unavailable for private temp name: {error}"))?;
    let mut name = target
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(format!(".{}.tmp", hex::encode(random)));
    Ok(target.with_file_name(name))
}

struct PrivateStage {
    path: Option<PathBuf>,
    file: Option<std::fs::File>,
}

impl PrivateStage {
    fn new(path: PathBuf, file: std::fs::File) -> Self {
        Self {
            path: Some(path),
            file: Some(file),
        }
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("private stage path is present")
    }

    #[cfg(windows)]
    fn file(&self) -> &std::fs::File {
        self.file.as_ref().expect("private stage file is present")
    }

    fn file_mut(&mut self) -> &mut std::fs::File {
        self.file.as_mut().expect("private stage file is present")
    }

    fn disarm_after_rename(mut self) {
        self.path = None;
    }

    #[cfg(not(windows))]
    fn remove_after_link(mut self) -> std::io::Result<()> {
        drop(self.file.take());
        let path = self.path.take().expect("private stage path is present");
        std::fs::remove_file(path)
    }
}

impl Drop for PrivateStage {
    fn drop(&mut self) {
        // The Windows primitive denies delete sharing. Close the exact handle
        // before removing an unpublished stage on every error/panic path.
        drop(self.file.take());
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn stage_private_file(target: &Path, bytes: &[u8]) -> Result<PrivateStage> {
    let temp = private_temp_sibling(target)?;
    let file = open_for_create_secure(&temp)?;
    let mut stage = PrivateStage::new(temp, file);
    let display = stage.path().display().to_string();
    stage
        .file_mut()
        .write_all(bytes)
        .with_context(|| format!("write private stage {display}"))?;
    stage
        .file_mut()
        .flush()
        .with_context(|| format!("flush private stage {display}"))?;
    stage
        .file_mut()
        .sync_all()
        .with_context(|| format!("fsync private stage {display}"))?;
    #[cfg(windows)]
    crate::wal::win_native::verify_private_file_handle(stage.file())
        .with_context(|| format!("verify private stage {display}"))?;
    #[cfg(not(windows))]
    {
        let metadata = std::fs::symlink_metadata(stage.path())
            .with_context(|| format!("verify private stage {display}"))?;
        validate_private_file_metadata(stage.path(), &metadata)?;
    }
    Ok(stage)
}

/// Publish a fully prepared private file only if the target is still absent.
/// A hard link is the single visibility point; after it succeeds every
/// remaining operation is warning-only so success cannot be rolled back by
/// temp cleanup or directory fsync.
fn publish_private_create_new(target: &Path, bytes: &[u8]) -> Result<bool> {
    let stage = stage_private_file(target, bytes)?;
    #[cfg(windows)]
    {
        match crate::wal::win_native::create_private_file_handle(stage.file(), target) {
            Ok(()) => {
                stage.disarm_after_rename();
                sync_parent_best_effort(target);
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                drop(stage);
                Ok(false)
            }
            Err(error) => {
                drop(stage);
                Err(error).with_context(|| {
                    format!(
                        "publish private state {} with create-if-absent semantics",
                        target.display()
                    )
                })
            }
        }
    }
    #[cfg(not(windows))]
    match std::fs::hard_link(stage.path(), target) {
        Ok(()) => {
            let temp = stage.path().to_path_buf();
            if let Err(error) = stage.remove_after_link() {
                warn!(
                    %error,
                    path = %temp.display(),
                    "private state is visible; staged hard-link cleanup was best-effort"
                );
            }
            sync_parent_best_effort(target);
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            drop(stage);
            Ok(false)
        }
        Err(error) => {
            drop(stage);
            Err(error).with_context(|| {
                format!(
                    "publish private state {} with create-if-absent semantics",
                    target.display()
                )
            })
        }
    }
}

/// Atomically replace the target with a fully prepared private file. The
/// rename is the marker commit point. Nothing after a successful rename can
/// turn the externally visible success into an error.
fn publish_private_replace_commit(target: &Path, bytes: &[u8]) -> Result<()> {
    let stage = stage_private_file(target, bytes)?;
    if let Err(error) = replace_file_commit(&stage, target) {
        drop(stage);
        return Err(error)
            .with_context(|| format!("publish committed marker {}", target.display()));
    }
    stage.disarm_after_rename();
    sync_parent_best_effort(target);
    Ok(())
}

#[cfg(not(windows))]
fn replace_file_commit(stage: &PrivateStage, target: &Path) -> std::io::Result<()> {
    std::fs::rename(stage.path(), target)
}

#[cfg(windows)]
fn replace_file_commit(stage: &PrivateStage, target: &Path) -> std::io::Result<()> {
    crate::wal::win_native::replace_private_file_handle(stage.file(), target)
}

fn sync_parent_best_effort(target: &Path) {
    #[cfg(unix)]
    if let Some(parent) = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && let Err(error) = std::fs::File::open(parent).and_then(|dir| dir.sync_all())
    {
        warn!(
            %error,
            path = %parent.display(),
            "visible private-state directory fsync was best-effort"
        );
    }
    #[cfg(not(unix))]
    let _ = target;
}

/// Atomic private write: stage under the final file's directory, fsync, replace
/// in one operation, then fsync the parent on Unix. The staged file receives
/// its private ACL/mode before the first byte; replacing it preserves that
/// protection without a remove-before-rename visibility gap.
#[cfg_attr(not(test), allow(dead_code))] // retained: exercised by unit tests; prod caller removed in Wave-3 refactor
pub(crate) fn write_atomically(target: &std::path::Path, contents: &[u8]) -> Result<()> {
    publish_private_replace_commit(target, contents)
        .with_context(|| format!("atomically replace private file {}", target.display()))
}

/// A3-tail: emit a `ConfigWrite` PRE_MUTATION_SNAPSHOT for the prior
/// freedom.yaml bytes before the reconfigure-flow rewrite. Honours the
/// operator's existing RollbackConfig when freedom.yaml is parseable;
/// falls back to defaults if the prior file is corrupt (still snapshot
/// it — corrupt bytes are exactly what an operator might want to roll
/// forward FROM during recovery).
pub(crate) async fn snapshot_existing_config(freedom_yaml: &std::path::Path) -> Result<Vec<u8>> {
    let pair = crate::config::snapshot_raw_config_pair(freedom_yaml)
        .with_context(|| format!("read prior {} for snapshot", freedom_yaml.display()))?;
    let prior_bytes = pair
        .freedom
        .ok_or_else(|| anyhow::anyhow!("{} disappeared before snapshot", freedom_yaml.display()))?;
    let rollback_policy = serde_yaml::from_slice::<crate::config::FreedomConfig>(&prior_bytes)
        .map(|config| config.rollback)
        .unwrap_or_default();
    let now_unix = crate::time::now_unix_i64();
    let home = freedom_yaml
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir).context("create WAL dir for init snapshot")?;
    let segment = wal_dir.join(format!("init-snapshot-{now_unix}.wal"));
    let (writer, join) = crate::wal::writer::spawn_for_home(segment, home.to_path_buf())
        .context("spawn WAL snapshot writer")?;
    let _ = crate::wal::snapshot::emit_if_policy_allows(
        &writer,
        &rollback_policy,
        crate::wal::snapshot::MutationKind::ConfigWrite,
        freedom_yaml.display().to_string(),
        &prior_bytes,
        now_unix,
        Some("init wizard rewriting existing freedom.yaml".to_string()),
    )
    .await
    .context("emit pre-mutation snapshot for init rewrite")?;
    drop(writer);
    let _ = join.await;
    // The public config snapshot API keeps its read buffer zeroizing. This
    // function's existing contract returns owned bytes to the caller, so copy
    // out while retaining automatic cleanup of the original allocation.
    Ok(prior_bytes.as_slice().to_vec())
}

pub(crate) fn ensure_snapshot_matches_source(source: Option<&str>, snapshot: &[u8]) -> Result<()> {
    anyhow::ensure!(
        source.is_some_and(|current| current.as_bytes() == snapshot),
        "freedom.yaml changed after its rollback snapshot was written; refusing to attach a stale snapshot to a different mutation — retry init"
    );
    Ok(())
}

pub(crate) fn stage_omi_file_override(
    credentials: &mut crate::config::credentials::Credentials,
    update: &crate::cli::omi::OmiCredentialUpdate,
) {
    if let Some(value) = update.developer_api_key.as_ref() {
        credentials.omi_developer_api_key = Some(value.clone());
    }
    if let Some(value) = update.native_ingest_token.as_ref() {
        credentials.omi_ingest_token = Some(value.clone());
    }
}

/// The init wizard owns these public keys. Everything else in freedom.yaml is
/// retained value-semantically through a YAML merge, including future
/// top-level additions that this binary does not yet know about.
const WIZARD_OWNED_CONFIG_KEYS: &[&str] = &[
    "secrets_backend",
    "operator_id",
    "language_primary",
    "language_code",
    "role",
    "role_custom",
    "provider_kind",
    "provider_binary",
    "provider_key",
    "provider_endpoint",
    "provider_model",
    "provider_region",
    "provider_api_version",
    "telegram_token",
    "telegram_user_id",
    "autonomy",
    "custom_autonomy",
    "inference",
    "auto_update",
    "plugins",
    "supervisor",
    "companion",
    "omi",
    "audit_rpc",
    "import_memory",
    "onboarding_complete",
    "chat_onboarding_completed",
    "obsidian_vault",
    "obsidian_subdir",
];

fn merge_yaml_value(target: &mut serde_yaml::Value, source: &serde_yaml::Value) {
    match (target, source) {
        (serde_yaml::Value::Mapping(target), serde_yaml::Value::Mapping(source)) => {
            for (key, value) in source {
                if let Some(current) = target.get_mut(key) {
                    merge_yaml_value(current, value);
                } else {
                    target.insert(key.clone(), value.clone());
                }
            }
        }
        (target, source) => *target = source.clone(),
    }
}

fn merge_wizard_owned_config(
    existing: Option<serde_yaml::Value>,
    wizard: &serde_yaml::Value,
) -> Result<serde_yaml::Value> {
    let wizard = wizard
        .as_mapping()
        .context("serialized WizardState must be a YAML mapping")?;
    let mut output =
        existing.unwrap_or_else(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    {
        let output = output
            .as_mapping_mut()
            .context("existing freedom.yaml root must be a YAML mapping")?;

        for &name in WIZARD_OWNED_CONFIG_KEYS {
            let key = serde_yaml::Value::String(name.to_string());
            let Some(incoming) = wizard.get(&key) else {
                continue;
            };
            if let Some(current) = output.get_mut(&key) {
                merge_yaml_value(current, incoming);
            } else {
                output.insert(key, incoming.clone());
            }
        }
    }
    Ok(output)
}

pub(crate) async fn write_config(neoth_dir: &std::path::Path, state: &WizardState) -> Result<()> {
    ensure_dir_secure(neoth_dir)?;
    ensure_dir_secure(&neoth_dir.join("credentials"))?;

    // Phase 33+ secret split (Codex audit #7): serialise freedom.yaml
    // WITHOUT the secret fields, write the secrets to credentials.yaml
    // alongside. Loading merges both back together — see
    // `FreedomConfig::load_from_path`.
    let mut public_state = state.clone();
    let provider_key = public_state.provider_key.take();
    let telegram_token = public_state.telegram_token.take();
    let omi_developer_api_key = public_state.omi_developer_api_key.take();
    let omi_ingest_token = public_state.omi_ingest_token.take();
    let inference_left_key = public_state.inference.left.key.take();
    let inference_right_key = public_state.inference.right.key.take();
    let inference_cerebellum_key = public_state.inference.cerebellum.key.take();
    let inference_default_slot_key = public_state.inference.default_slot.key.take();
    // Legacy direct-seed/Pear wizard fields are deliberately discarded. The
    // companion credentials belong in credentials.yaml and are written by
    // `neoth channel add keet`; the wizard must not revive the guessed
    // direct-transport format.
    public_state.keet_seed_phrase = None;
    public_state.keet_bridge_bearer_token = None;

    // GOLD-ADAPT-OH-03: mark onboarding complete iff ≥1 channel configured.
    // `configured_channels` checks the Telegram wizard path.
    // Discord/Slack/WhatsApp/Signal configured via step6g go straight to
    // credentials.yaml — the secondary boot-time probe catches those correctly.
    public_state.onboarding_complete =
        public_state.onboarding_complete || !configured_channels(state).is_empty();

    // GOLD-ADAPT-OH-11: wizard always resets chat_onboarding_completed = false
    // so the first-chat hint fires on the next `neoth chat` after (re-)init.
    // This correctly re-arms the hint on `neoth init --force` runs too.
    public_state.chat_onboarding_completed = false;

    let mut wizard_value =
        serde_yaml::to_value(&public_state).context("serialize WizardState as YAML value")?;
    if public_state.bootstrap_vault
        && let Some(vault_path) = public_state.vault_path.as_ref()
        && let serde_yaml::Value::Mapping(map) = &mut wizard_value
    {
        map.insert(
            serde_yaml::Value::String("obsidian_vault".to_string()),
            serde_yaml::Value::String(vault_path.display().to_string()),
        );
        let subdir_key = serde_yaml::Value::String("obsidian_subdir".to_string());
        if !map.contains_key(&subdir_key) {
            map.insert(
                subdir_key,
                serde_yaml::Value::String("NEOTH-sessions".to_string()),
            );
        }
    }

    let freedom_yaml = neoth_dir.join("freedom.yaml");
    let cred_path = neoth_dir.join("credentials.yaml");
    let omi_update = crate::cli::omi::OmiCredentialUpdate {
        developer_api_key: omi_developer_api_key,
        native_ingest_token: omi_ingest_token,
    };
    if omi_update.developer_api_key.is_some() || omi_update.native_ingest_token.is_some() {
        omi_update.validate()?;
    }

    let credentials_updated = provider_key.is_some()
        || telegram_token.is_some()
        || inference_left_key.is_some()
        || inference_right_key.is_some()
        || inference_cerebellum_key.is_some()
        || inference_default_slot_key.is_some()
        || omi_update.developer_api_key.is_some()
        || omi_update.native_ingest_token.is_some();

    // A3-tail mutation-site wiring: when freedom.yaml ALREADY exists
    // (reconfigure flow, not first-run), capture its prior bytes
    // before overwriting so `neoth rollback list --kind config_write`
    // surfaces this rewrite. First-run wizard has no prior bytes →
    // skip (would produce a useless empty-restore snapshot).
    let rollback_snapshot = if freedom_yaml.exists() {
        match snapshot_existing_config(&freedom_yaml).await {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    path = %freedom_yaml.display(),
                    "could not capture pre-overwrite snapshot for freedom.yaml — proceeding without rollback coverage for this write"
                );
                None
            }
        }
    } else {
        None
    };

    // Open the configured store before the transaction. New OMI values are
    // first committed as file overrides in the config/credential journal; only
    // after that durable pair exists are they copied to the keychain and the
    // overrides cleared. A crash at every boundary therefore leaves the new
    // secret reachable through the active generation.
    let keychain_store = if public_state.secrets_backend == crate::config::SecretsBackend::Keychain
    {
        Some(
            crate::config::keychain::open_store()
                .context("open configured OS keychain during init")?,
        )
    } else {
        None
    };
    let transaction =
        crate::config::credentials::Credentials::update_raw_freedom_with_credentials_at(
            &freedom_yaml,
            &cred_path,
            |source, credentials| {
                if let Some(snapshot) = rollback_snapshot.as_deref() {
                    ensure_snapshot_matches_source(source, snapshot)?;
                }
                let existing = source
                    .map(|body| {
                        serde_yaml::from_str(body).with_context(|| {
                            format!("parse existing {} for merge", freedom_yaml.display())
                        })
                    })
                    .transpose()?;
                let public_value = merge_wizard_owned_config(existing, &wizard_value)?;
                let serialized = serde_yaml::to_string(&public_value)
                    .context("serialize losslessly merged init config for freedom.yaml")?;

                let apply_common = |target: &mut crate::config::credentials::Credentials| {
                    if let Some(value) = provider_key.as_ref() {
                        target.provider_key = Some(value.clone());
                    }
                    if let Some(value) = telegram_token.as_ref() {
                        target.telegram_token = Some(value.clone());
                    }
                    if let Some(value) = inference_left_key.as_ref() {
                        target.inference_left_key = Some(value.clone());
                    }
                    if let Some(value) = inference_right_key.as_ref() {
                        target.inference_right_key = Some(value.clone());
                    }
                    if let Some(value) = inference_cerebellum_key.as_ref() {
                        target.inference_cerebellum_key = Some(value.clone());
                    }
                    if let Some(value) = inference_default_slot_key.as_ref() {
                        target.inference_default_slot_key = Some(value.clone());
                    }
                };
                apply_common(credentials);

                // File values override keychain values, so this is also the safe
                // staging location when the target backend is Keychain.
                stage_omi_file_override(credentials, &omi_update);

                let mut candidate = credentials.clone();
                if let Some(store) = keychain_store.as_deref() {
                    crate::config::keychain::supplement_from_store(&mut candidate, store)
                        .context("supplement init candidate from configured OS keychain")?;
                }
                apply_common(&mut candidate);
                if let Some(value) = omi_update.developer_api_key.as_ref() {
                    candidate.omi_developer_api_key = Some(value.clone());
                }
                if let Some(value) = omi_update.native_ingest_token.as_ref() {
                    candidate.omi_ingest_token = Some(value.clone());
                }
                if public_state.omi.enabled
                    || omi_update.developer_api_key.is_some()
                    || omi_update.native_ingest_token.is_some()
                {
                    public_state
                        .omi
                        .validate_with_credentials(&candidate)
                        .map_err(anyhow::Error::msg)
                        .context("validate OMI config and credentials before init commit")?;
                } else {
                    public_state
                        .omi
                        .validate()
                        .map_err(anyhow::Error::msg)
                        .context("validate disabled OMI config before init commit")?;
                }

                Ok((Some(serialized), ()))
            },
        );
    transaction.context("commit init freedom/credential transaction")?;

    if let Some(store) = keychain_store.as_deref()
        && (omi_update.developer_api_key.is_some() || omi_update.native_ingest_token.is_some())
    {
        crate::cli::omi::finalize_staged_omi_keychain_update(&cred_path, store, &omi_update).context(
            "init config committed with safe OMI file overrides, but keychain finalization failed; the file overrides remain authoritative",
        )?;
    }

    if credentials_updated {
        info!(path = %cred_path.display(), "credential store updated without replacing unrelated fields");
    }
    info!(path = %freedom_yaml.display(), "freedom.yaml and credentials committed atomically");
    Ok(())
}

pub(crate) fn write_initialized_marker(
    neoth_dir: &std::path::Path,
    state: &WizardState,
) -> Result<()> {
    // ARCH-07b: now_unix_secs() = same semantics (.map(|d| d.as_secs()).unwrap_or(0))
    let now = crate::time::now_unix_secs();

    let marker = InitializedMarker {
        wizard_version: 2, // F-22: bumped to 2 after extending the schema
        neoth_version: env!("CARGO_PKG_VERSION").to_string(),
        operator_id: state.operator_id.clone().unwrap_or_default(),
        steps_completed: {
            let mut seen = std::collections::HashSet::new();
            state
                .steps_completed
                .iter()
                .copied()
                .filter(|step| seen.insert(*step))
                .collect()
        },
        init_time_unix: now,
        init_time_iso8601: format_iso8601(now),
        provider_kind: state.provider_kind,
        channels: configured_channels(state),
        gui_transaction_id: None,
        config_sha256: None,
    };

    write_initialized_marker_value(neoth_dir, &marker).map(|_| ())
}

fn write_initialized_marker_value(
    neoth_dir: &std::path::Path,
    marker: &InitializedMarker,
) -> Result<std::path::PathBuf> {
    ensure_dir_secure(neoth_dir)?;
    let path = neoth_dir.join(".initialized");
    let json =
        serde_json::to_string_pretty(&marker).context("serialize InitializedMarker as JSON")?;
    with_gui_init_lock(neoth_dir, || {
        publish_private_replace_commit(&path, json.as_bytes())?;
        cleanup_gui_init_pending_best_effort(neoth_dir);
        Ok(())
    })?;
    info!(path = %path.display(), "init marker written (mode 0600 on unix)");
    Ok(path)
}

/// Create or resume the one authoritative GUI initialization transaction for
/// this home. The token exists only in this private record and the JSON ack.
pub(crate) fn begin_initialized_home_from_gui(
    neoth_dir: &std::path::Path,
) -> Result<GuiInitBeginAcknowledgement> {
    ensure_dir_secure(neoth_dir)?;
    let canonical_home = std::fs::canonicalize(neoth_dir).with_context(|| {
        format!(
            "canonicalize GUI initialization home {}",
            neoth_dir.display()
        )
    })?;
    with_gui_init_lock(&canonical_home, || {
        if let Some(pending) = read_gui_init_pending(&canonical_home)? {
            return Ok(gui_begin_ack(&pending));
        }

        let base_marker_sha256 = read_initialized_marker(&canonical_home)?.map(|file| file.sha256);
        let pending_dir = gui_init_pending_dir(&canonical_home);
        ensure_dir_secure(&pending_dir)?;

        let now = crate::time::now_unix_secs();
        if now == 0 {
            anyhow::bail!("system clock cannot produce a valid GUI transaction timestamp");
        }
        let mut transaction_id = [0u8; 32];
        let mut token = [0u8; 32];
        getrandom::getrandom(&mut transaction_id).map_err(|error| {
            anyhow::anyhow!("OS RNG unavailable for GUI transaction id: {error}")
        })?;
        getrandom::getrandom(&mut token).map_err(|error| {
            anyhow::anyhow!("OS RNG unavailable for GUI completion token: {error}")
        })?;
        let pending = GuiInitPending {
            schema_version: GUI_INIT_SCHEMA_VERSION,
            transaction_id: hex::encode(transaction_id),
            token: hex::encode(token),
            home: canonical_home.clone(),
            config_path: canonical_home.join("freedom.yaml"),
            base_marker_sha256,
            created_unix: now,
        };
        let bytes = serde_json::to_vec(&pending).context("serialize GUI Pending-State")?;
        if bytes.len() as u64 > MAX_GUI_INIT_PENDING_BYTES {
            anyhow::bail!("serialized GUI Pending-State exceeds its bounded record contract");
        }
        let pending_path = gui_init_pending_path(&canonical_home);
        if publish_private_create_new(&pending_path, &bytes)? {
            return Ok(gui_begin_ack(&pending));
        }

        let winner = read_gui_init_pending(&canonical_home)?.ok_or_else(|| {
            anyhow::anyhow!(
                "GUI Pending-State publication raced but no authoritative record remained"
            )
        })?;
        Ok(gui_begin_ack(&winner))
    })
}

/// Finish GUI onboarding through the daemon-owned marker contract. The GUI is
/// allowed to prepare freedom/credentials only; it cannot claim completion.
pub(crate) fn complete_initialized_home_from_gui(
    neoth_dir: &std::path::Path,
    provided_token: &str,
) -> Result<GuiInitCompletionAcknowledgement> {
    require_lower_hex_64(provided_token, "GUI completion token")?;
    ensure_dir_secure(neoth_dir)?;
    let canonical_home = std::fs::canonicalize(neoth_dir).with_context(|| {
        format!(
            "canonicalize GUI initialization home {}",
            neoth_dir.display()
        )
    })?;
    with_gui_init_lock(&canonical_home, || {
        let pending = read_gui_init_pending(&canonical_home)?.ok_or_else(|| {
            anyhow::anyhow!(
                "no GUI Pending-State exists for {}; run `neoth init --begin-from-gui` first",
                canonical_home.display()
            )
        })?;
        if !crate::n8n_api::constant_time_token_eq(provided_token, &pending.token) {
            anyhow::bail!("GUI completion token does not authorize the active transaction");
        }

        let freedom_path = pending.config_path.clone();
        let config = read_initialization_config(&freedom_path)?.ok_or_else(|| {
            anyhow::anyhow!("GUI configuration {} is missing", freedom_path.display())
        })?;
        // The exact public bytes above own the transaction hash. Load the
        // effective view as well so split credentials contribute truthful
        // non-secret marker metadata (currently the Telegram channel bit).
        let effective_config = crate::config::FreedomConfig::load_from_path(&freedom_path)
            .with_context(|| format!("load effective GUI config {}", freedom_path.display()))?;
        let operator_id = config
            .config
            .operator_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("GUI configuration has no operator_id"))?;
        super::validate_operator_id(operator_id).context("validate GUI operator_id")?;

        let now = crate::time::now_unix_secs();
        if now == 0 {
            anyhow::bail!("system clock cannot produce a valid initialization timestamp");
        }
        let mut channels = Vec::new();
        if effective_config.telegram_token.is_some() {
            channels.push("telegram".to_string());
        }
        let marker = InitializedMarker {
            wizard_version: 2,
            neoth_version: env!("CARGO_PKG_VERSION").to_string(),
            operator_id: operator_id.to_string(),
            steps_completed: [
                WizardStep::License,
                WizardStep::OperatorId,
                WizardStep::Provider,
                WizardStep::Channel,
                WizardStep::Autonomy,
                WizardStep::Summary,
            ]
            .map(u8::from)
            .to_vec(),
            init_time_unix: now,
            init_time_iso8601: format_iso8601(now),
            provider_kind: config.config.provider_kind,
            channels,
            gui_transaction_id: Some(pending.transaction_id.clone()),
            config_sha256: Some(config.sha256.clone()),
        };
        let marker_path = canonical_home.join(".initialized");
        validate_initialized_marker(&marker, &marker_path)?;

        if let Some(existing) = read_initialized_marker(&canonical_home)?
            && existing.marker.gui_transaction_id.as_deref()
                == Some(pending.transaction_id.as_str())
        {
            validate_marker_config_pair(&existing.marker, &config, &canonical_home, &freedom_path)?;
            cleanup_gui_init_pending_best_effort(&canonical_home);
            return Ok(GuiInitCompletionAcknowledgement {
                schema_version: GUI_INIT_SCHEMA_VERSION,
                completed: true,
                ready: true,
                transaction_id: pending.transaction_id,
                home: canonical_home.clone(),
                marker_path,
            });
        }

        let marker_bytes =
            serde_json::to_vec_pretty(&marker).context("serialize GUI initialization marker")?;
        publish_private_replace_commit(&marker_path, &marker_bytes)?;

        // Marker visibility is the irreversible commit point. Cleanup is
        // deliberately warning-only and no readiness postcheck is permitted.
        cleanup_gui_init_pending_best_effort(&canonical_home);
        Ok(GuiInitCompletionAcknowledgement {
            schema_version: GUI_INIT_SCHEMA_VERSION,
            completed: true,
            ready: true,
            transaction_id: pending.transaction_id,
            home: canonical_home.clone(),
            marker_path,
        })
    })
}

/// Format a UTC epoch-seconds value as ISO-8601 / RFC 3339 with `Z`
/// suffix. Naive month-day arithmetic so we don't pull a date crate
/// just for this — the marker is human-info only, not parsed back.
pub(crate) fn format_iso8601(unix_secs: u64) -> String {
    // chrono is already in the dependency tree (used by profile pipeline);
    // reuse it for accuracy + leap-year handling.
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix_secs as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| format!("{unix_secs}-epoch"))
}

/// Sorted, stable list of channel ids the wizard configured. Operators
/// reading the marker via `neoth doctor` see exactly which inbound
/// surfaces are live without parsing freedom.yaml. Extend this when a
/// future channel (whatsapp, slack) lands.
pub(crate) fn configured_channels(state: &WizardState) -> Vec<String> {
    let mut out = Vec::new();
    if state.telegram_token.is_some() {
        out.push("telegram".to_string());
    }
    out
}
