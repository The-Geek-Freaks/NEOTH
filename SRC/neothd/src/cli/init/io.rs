//! Write-side I/O for the `neoth init` wizard (GOLD-ARCH-05): secure dir/file
//! creation, atomic writes, config + .initialized marker persistence, summary
//! and post-write steps. Split out of `cli/init.rs`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use tracing::{debug, info};

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
}

pub(crate) fn ensure_dir_secure(dir: &std::path::Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create_dir_all {}", dir.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms)
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    Ok(())
}

/// Open a file for exclusive create with mode 0600 (unix).
/// Windows: parent DACL inherited; warning emitted at daemon startup.
pub(crate) fn open_for_create_secure(path: &std::path::Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("open_for_create {}", path.display()))
}

/// Atomic write: `target.tmp` → fsync → rename → parent dir fsync (unix).
/// On `--force` paths, the caller is responsible for removing existing `target`
/// before invoking (we accept a target that already exists by removing it).
pub(crate) fn write_atomically(target: &std::path::Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    let tmp = target.with_extension("tmp");
    if tmp.exists() {
        std::fs::remove_file(&tmp).ok();
    }

    {
        let mut f = open_for_create_secure(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }

    if target.exists() {
        std::fs::remove_file(target).with_context(|| {
            format!("remove existing target {} before rename", target.display())
        })?;
    }
    std::fs::rename(&tmp, target)
        .with_context(|| format!("rename {} -> {}", tmp.display(), target.display()))?;

    // Durable rename on unix: fsync the parent directory.
    // Windows: rename is durable via NTFS metadata journal; no portable
    // equivalent of dir-fsync, so we skip.
    #[cfg(unix)]
    {
        if let Some(parent) = target.parent() {
            if parent.exists() {
                let dir = std::fs::File::open(parent)?;
                dir.sync_all().ok();
            }
        }
    }

    // Windows: restrict DACL to current user. Logs warning on failure, never
    // fails the write (degrades to "file inherits parent DACL").
    #[cfg(windows)]
    {
        let _ = crate::wal::win_acl::restrict_to_owner(target);
    }

    Ok(())
}

/// A3-tail: emit a `ConfigWrite` PRE_MUTATION_SNAPSHOT for the prior
/// freedom.yaml bytes before the reconfigure-flow rewrite. Honours the
/// operator's existing RollbackConfig when freedom.yaml is parseable;
/// falls back to defaults if the prior file is corrupt (still snapshot
/// it — corrupt bytes are exactly what an operator might want to roll
/// forward FROM during recovery).
pub(crate) async fn snapshot_existing_config(freedom_yaml: &std::path::Path) -> Result<()> {
    let prior_bytes = std::fs::read(freedom_yaml)
        .with_context(|| format!("read prior {} for snapshot", freedom_yaml.display()))?;
    let rollback_policy = match crate::config::FreedomConfig::load_from_path(freedom_yaml) {
        Ok(cfg) => cfg.rollback,
        Err(_) => crate::config::RollbackConfig::default(),
    };
    let now_unix = crate::time::now_unix_i64();
    let wal_dir = crate::config::FreedomConfig::default_wal_dir();
    std::fs::create_dir_all(&wal_dir).context("create WAL dir for init snapshot")?;
    let segment = wal_dir.join(format!("init-snapshot-{now_unix}.wal"));
    let (writer, join) = crate::wal::writer::spawn(segment).context("spawn WAL snapshot writer")?;
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
    Ok(())
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
    // Legacy Keet/Pear fields are deliberately discarded. There is no
    // supported public Keet chat API, so onboarding must never mint or persist
    // credentials for the removed guessed transport.
    public_state.keet_seed_phrase = None;
    public_state.pears_bearer_token = None;

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
    if public_state.bootstrap_vault {
        if let Some(vault_path) = public_state.vault_path.as_ref() {
            if let serde_yaml::Value::Mapping(map) = &mut wizard_value {
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
        }
    }

    let freedom_yaml = neoth_dir.join("freedom.yaml");
    // Parse and merge before touching credentials. A malformed existing file
    // must fail closed without leaving a half-applied cross-file update.
    let existing_value = if freedom_yaml.exists() {
        let raw = std::fs::read(&freedom_yaml)
            .with_context(|| format!("read existing {} for merge", freedom_yaml.display()))?;
        Some(
            serde_yaml::from_slice(&raw)
                .with_context(|| format!("parse existing {} for merge", freedom_yaml.display()))?,
        )
    } else {
        None
    };
    let public_value = merge_wizard_owned_config(existing_value, &wizard_value)?;
    let serialized = serde_yaml::to_string(&public_value)
        .context("serialize losslessly merged init config for freedom.yaml")?;

    let cred_path = neoth_dir.join("credentials.yaml");
    let omi_update = crate::cli::omi::OmiCredentialUpdate {
        developer_api_key: omi_developer_api_key,
        native_ingest_token: omi_ingest_token,
    };
    if omi_update.developer_api_key.is_some() || omi_update.native_ingest_token.is_some() {
        omi_update.validate()?;
    }

    // Validate the exact effective cross-file state before either file changes.
    // This prevents an enabled OMI config from ever being published without
    // the dedicated credential for every active network surface.
    if public_state.omi.enabled
        || omi_update.developer_api_key.is_some()
        || omi_update.native_ingest_token.is_some()
    {
        let mut candidate = crate::config::credentials::Credentials::load_effective(
            &cred_path,
            public_state.secrets_backend,
        )
        .with_context(|| format!("load effective credentials from {}", cred_path.display()))?;
        if let Some(value) = omi_update.developer_api_key.as_ref() {
            candidate.omi_developer_api_key = Some(value.clone());
        }
        if let Some(value) = omi_update.native_ingest_token.as_ref() {
            candidate.omi_ingest_token = Some(value.clone());
        }
        public_state
            .omi
            .validate_with_credentials(&candidate)
            .map_err(anyhow::Error::msg)
            .context("validate OMI config and credentials before init write")?;
    } else {
        public_state
            .omi
            .validate()
            .map_err(anyhow::Error::msg)
            .context("validate disabled OMI config before init write")?;
    }

    // Credentials land first. A later config-write failure leaves only dormant
    // secrets; the inverse ordering briefly exposed an enabled but unauthenticated
    // OMI surface. Locked read-modify-write preserves imported and unrelated
    // credentials instead of rebuilding credentials.yaml from two fields.
    let mut credentials_updated = false;
    if provider_key.is_some()
        || telegram_token.is_some()
        || inference_left_key.is_some()
        || inference_right_key.is_some()
        || inference_cerebellum_key.is_some()
        || inference_default_slot_key.is_some()
    {
        crate::config::credentials::Credentials::update_at(&cred_path, |credentials| {
            if let Some(value) = provider_key.as_ref() {
                credentials.provider_key = Some(value.clone());
            }
            if let Some(value) = telegram_token.as_ref() {
                credentials.telegram_token = Some(value.clone());
            }
            if let Some(value) = inference_left_key.as_ref() {
                credentials.inference_left_key = Some(value.clone());
            }
            if let Some(value) = inference_right_key.as_ref() {
                credentials.inference_right_key = Some(value.clone());
            }
            if let Some(value) = inference_cerebellum_key.as_ref() {
                credentials.inference_cerebellum_key = Some(value.clone());
            }
            if let Some(value) = inference_default_slot_key.as_ref() {
                credentials.inference_default_slot_key = Some(value.clone());
            }
            Ok(())
        })
        .context("merge provider/channel credentials during init")?;
        credentials_updated = true;
    }
    if omi_update.developer_api_key.is_some() || omi_update.native_ingest_token.is_some() {
        crate::cli::omi::persist_omi_credential_update(
            neoth_dir,
            public_state.secrets_backend,
            &omi_update,
        )
        .context("persist OMI credentials during init")?;
        credentials_updated = true;
    }
    if credentials_updated {
        info!(path = %cred_path.display(), "credential store updated without replacing unrelated fields");
    }

    // A3-tail mutation-site wiring: when freedom.yaml ALREADY exists
    // (reconfigure flow, not first-run), capture its prior bytes
    // before overwriting so `neoth rollback list --kind config_write`
    // surfaces this rewrite. First-run wizard has no prior bytes →
    // skip (would produce a useless empty-restore snapshot).
    if freedom_yaml.exists() {
        if let Err(e) = snapshot_existing_config(&freedom_yaml).await {
            tracing::warn!(
                error = %e,
                path = %freedom_yaml.display(),
                "could not capture pre-overwrite snapshot for freedom.yaml — proceeding without rollback coverage for this write"
            );
        }
    }

    write_atomically(&freedom_yaml, serialized.as_bytes())?;
    info!(path = %freedom_yaml.display(), "freedom.yaml written (mode 0600 on unix)");
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
        steps_completed: state.steps_completed.clone(),
        init_time_unix: now,
        init_time_iso8601: format_iso8601(now),
        provider_kind: state.provider_kind,
        channels: configured_channels(state),
    };

    let path = neoth_dir.join(".initialized");
    let json =
        serde_json::to_string_pretty(&marker).context("serialize InitializedMarker as JSON")?;
    write_atomically(&path, json.as_bytes())?;
    info!(path = %path.display(), "init marker written (mode 0600 on unix)");
    Ok(())
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
