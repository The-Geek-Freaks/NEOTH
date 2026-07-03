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
    // K-4 (Session 21, 2026-05-23): primary/secondary channel display.
    // Keet wins if paired (operator-private + e2e by default); Telegram
    // is the fallback. Both paired → "Keet (primary) / Telegram
    // (secondary)" — encodes the recommended-default flip the agent
    // panel called for in K-4.
    let channels = configured_channels(state);
    let channel_line = match channels.as_slice() {
        [] => "none".to_string(),
        [one] => match one.as_str() {
            "keet" => "Keet".to_string(),
            "telegram" => "Telegram".to_string(),
            other => other.to_string(),
        },
        [primary, secondary] => {
            fn pretty(s: &str) -> &str {
                match s {
                    "keet" => "Keet",
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
    println!("  neoth provider add        # change LLM provider");
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
///     onboarding (`["telegram"]`, `["telegram", "keet"]`, etc).
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
    // K-3.5 (Session 21): keet seed + pears bearer never touch freedom.yaml.
    let keet_seed_phrase = public_state.keet_seed_phrase.take();
    let pears_bearer_token = public_state.pears_bearer_token.take();

    // GOLD-ADAPT-OH-03: mark onboarding complete iff ≥1 channel configured.
    // `configured_channels` checks keet + telegram (the two wizard-path channels).
    // Discord/Slack/WhatsApp/Signal configured via step6g go straight to
    // credentials.yaml — the secondary boot-time probe catches those correctly.
    public_state.onboarding_complete = !configured_channels(state).is_empty();

    // GOLD-ADAPT-OH-11: wizard always resets chat_onboarding_completed = false
    // so the first-chat hint fires on the next `neoth chat` after (re-)init.
    // This correctly re-arms the hint on `neoth init --force` runs too.
    public_state.chat_onboarding_completed = false;

    let freedom_yaml = neoth_dir.join("freedom.yaml");
    let serialized = serde_yaml::to_string(&public_state)
        .context("serialize WizardState as YAML for freedom.yaml")?;

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

    let creds = crate::config::credentials::Credentials {
        provider_key,
        telegram_token,
        keet_seed_phrase,
        pears_bearer_token,
        ..Default::default()
    };
    let cred_path = neoth_dir.join("credentials.yaml");
    creds.write(&cred_path).context("write credentials.yaml")?;
    if creds.has_any() {
        info!(path = %cred_path.display(), "credentials.yaml written (mode 0600 on unix)");
    }
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
/// future channel (keet, whatsapp, slack) lands.
pub(crate) fn configured_channels(state: &WizardState) -> Vec<String> {
    // K-4 (Session 21, 2026-05-23): primary-channel ordering. Once
    // Keet pairing succeeded, surface Keet FIRST in the configured
    // list — `.initialized` marker + post-init wizard summary both
    // read this as "first entry = primary". Telegram still listed
    // but becomes the fallback channel. This is the minimal-first
    // K-4 verdict: change the recommended-primary signal without
    // restructuring step6_channel's dispatch (full default flip
    // gated on cluster live-test against `pear`).
    let mut out = Vec::new();
    if state.keet_seed_phrase.is_some() {
        out.push("keet".to_string());
    }
    if state.telegram_token.is_some() {
        out.push("telegram".to_string());
    }
    // No .sort() — K-4 ordering is intentional. The Vec is the
    // primary-first list operators see in `neoth status` output.
    out
}
