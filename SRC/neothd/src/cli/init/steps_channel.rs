//! Wizard channel + integration steps (GOLD-ARCH-05): step6 channel,
//! step6b legacy Keet migration marker, step6c/6d obsidian, step6e n8n, step6f memory
//! import, step6g credential import, step6h recommended installs.
//! Split out of `cli/init.rs`.

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::{
    InitArgs, WizardState, WizardStep, k4b_telegram_prompt_text, validate_telegram_token,
    write_credential_import_sidecar,
};

pub(crate) async fn step6_channel(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    debug!("wizard step 6: channel");

    // Resolve token from args or interactive prompt.
    let token = if let Some(t) = args.telegram_token.clone() {
        Some(t)
    } else if !interactive {
        None
    } else {
        #[cfg(feature = "wizard")]
        {
            let set_up =
                dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(k4b_telegram_prompt_text(false))
                    .default(false)
                    .interact()
                    .context("telegram channel prompt")?;
            if !set_up {
                None
            } else {
                let t: String =
                    dialoguer::Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
                        .with_prompt("Telegram bot token (from @BotFather)")
                        .interact()
                        .context("telegram token input")?;
                Some(t)
            }
        }
        #[cfg(not(feature = "wizard"))]
        {
            None
        }
    };

    if let Some(t) = token {
        validate_telegram_token(&t)?;
        state.telegram_token = Some(crate::secret::SecretString::from(t.as_str()));
        state.telegram_user_id = args.telegram_user_id;
    } else if interactive {
        println!(
            "  [6/9] Telegram skipped. Add any channel later: `neoth channel add \
             telegram|slack|whatsapp|discord|signal|line|irc|imessage|mattermost|gchat`"
        );
    }

    state.steps_completed.push(WizardStep::Channel as u8);
    Ok(())
}

/// Legacy wizard-step marker retained so interrupted wizard state remains
/// readable. Keet does not expose a supported public room/message API and Pear
/// Runtime communicates with embedded apps over IPC, so NEOTH must not solicit
/// or persist Keet credentials. The old guessed HTTP/DHT adapters were removed.
pub(crate) async fn step6b_keet_pairing(
    _args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    debug!("wizard step 6b: unsupported Keet migration marker");
    state.keet_seed_phrase = None;
    state.pears_bearer_token = None;
    if interactive {
        println!(
            "[6b/9] Keet integration unavailable: Keet has no supported public chat API; no credentials were requested or stored."
        );
    }
    state.steps_completed.push(WizardStep::KeetPairing as u8);
    Ok(())
}

/// Step 6c — O-1 (Workstream B): Obsidian install.
///
/// Surfaces the OS-appropriate `winget` / `brew` / AppImage URL.
/// Never auto-spawns the installer — operators paste the command
/// (per "operator GO per command" rule). The wizard records the
/// opt-in so subsequent boots know whether to nudge the vault step.
pub(crate) async fn step6c_obsidian_install(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::installers::obsidian;

    debug!("wizard step 6c: obsidian install");

    let already = obsidian::detect_obsidian_install();
    if already {
        info!("obsidian already installed; skipping install step");
        state.install_obsidian = true;
        state.steps_completed.push(WizardStep::Obsidian as u8);
        return Ok(());
    }

    if !interactive {
        if !args.install_obsidian {
            state.steps_completed.push(WizardStep::Obsidian as u8);
            return Ok(());
        }
        state.install_obsidian = true;
        let path = obsidian::recommend_install_path(false);
        let cmd = obsidian::install_command(path);
        info!(
            path = path.as_str(),
            cmd = %cmd.join(" "),
            "operator opted into obsidian install"
        );
        state.steps_completed.push(WizardStep::Obsidian as u8);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        println!();
        println!("[6c/9] Obsidian (vault archive — see step 6d) is not installed.");
        let install = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Install Obsidian now? (recommended for the NEOTH-Vault archive)")
            .default(true)
            .interact()
            .context("obsidian install confirm")?;
        if !install {
            state.steps_completed.push(WizardStep::Obsidian as u8);
            return Ok(());
        }
        state.install_obsidian = true;
        let path = obsidian::recommend_install_path(false);
        let cmd = obsidian::install_command(path);
        println!();
        if cmd.is_empty() {
            println!("  Obsidian appears to be installed via a non-standard path. Skipping.");
        } else {
            println!("  Suggested install command for this platform:");
            println!("      $ {}", cmd.join(" "));
            println!("  Run it in a separate shell; the wizard does not auto-spawn installers.");
        }
    }

    state.steps_completed.push(WizardStep::Obsidian as u8);
    Ok(())
}

/// Step 6d — O-2 (Workstream B): NEOTH-Vault bootstrap.
///
/// When the operator opts in, the wizard creates the vault directory
/// + writes the curated `.obsidian/` config + templates from
/// `installers::obsidian_vault::bootstrap_files`. Idempotent — files
/// that already exist are left alone (operator's edits win).
pub(crate) fn step6d_obsidian_vault_bootstrap(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    step6d_obsidian_vault_bootstrap_with_home(args, interactive, state, None)
}

/// Session 24 env-mutation refactor: explicit `home_override` lets
/// tests pass a tempdir instead of mutating the global HOME /
/// USERPROFILE env vars. Production call site passes `None` and
/// reads the env as before.
pub(crate) fn step6d_obsidian_vault_bootstrap_with_home(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
    home_override: Option<&std::path::Path>,
) -> Result<()> {
    use crate::installers::obsidian_vault;

    debug!("wizard step 6d: obsidian vault bootstrap");

    let resolve_vault = || -> Option<std::path::PathBuf> {
        match home_override {
            Some(h) => Some(obsidian_vault::default_vault_path_at(h)),
            None => obsidian_vault::default_vault_path(),
        }
    };

    let mut bootstrap = false;
    let mut vault_path: Option<std::path::PathBuf> = None;

    if !interactive {
        if !args.bootstrap_vault {
            state.steps_completed.push(WizardStep::ObsidianVault as u8);
            return Ok(());
        }
        bootstrap = true;
        vault_path = resolve_vault();
    } else {
        #[cfg(feature = "wizard")]
        {
            let default_path = resolve_vault();
            let default_label = default_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<HOME unset>".to_string());
            println!();
            println!("[6d/9] Bootstrap a NEOTH-Vault at: {default_label}");
            let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("Create the vault now? (skip if you already have one)")
                .default(true)
                .interact()
                .context("vault bootstrap confirm")?;
            if want {
                bootstrap = true;
                vault_path = default_path;
            }
        }
    }

    if !bootstrap {
        state.steps_completed.push(WizardStep::ObsidianVault as u8);
        return Ok(());
    }

    let Some(path) = vault_path else {
        warn!("vault bootstrap requested but no default path resolvable (HOME unset); skipping");
        state.steps_completed.push(WizardStep::ObsidianVault as u8);
        return Ok(());
    };

    std::fs::create_dir_all(&path)
        .with_context(|| format!("create vault root at {}", path.display()))?;
    let mut wrote = 0usize;
    let mut skipped = 0usize;
    for file in obsidian_vault::bootstrap_files() {
        let target = path.join(file.relative_path);
        if target.exists() {
            skipped += 1;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create vault subdir {}", parent.display()))?;
        }
        std::fs::write(&target, file.content)
            .with_context(|| format!("write vault file {}", target.display()))?;
        wrote += 1;
    }
    info!(
        vault = %path.display(),
        wrote,
        skipped,
        "neoth vault bootstrapped"
    );

    state.bootstrap_vault = true;
    state.vault_path = Some(path);
    state.steps_completed.push(WizardStep::ObsidianVault as u8);
    Ok(())
}

/// Step 6e — N-1 (Workstream B): n8n install opt-in.
///
/// Probes Docker + npm asynchronously, picks the recommended path
/// via `InstallStrategy::recommend`. The actual install command is
/// surfaced — never auto-spawned — so the operator runs it with full
/// visibility.
pub(crate) async fn step6e_n8n_install(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::installers::n8n;

    debug!("wizard step 6e: n8n install");

    if !interactive {
        if !args.install_n8n {
            state.steps_completed.push(WizardStep::N8n as u8);
            return Ok(());
        }
        state.install_n8n = true;
        let docker = n8n::check_docker_available().await.is_some();
        let npm = n8n::check_npm_available().await.is_some();
        match n8n::InstallStrategy::recommend(docker, npm) {
            Some(strategy) => {
                let cmd = strategy.install_command(n8n::DEFAULT_N8N_PORT);
                info!(
                    strategy = strategy.as_str(),
                    cmd = %cmd.join(" "),
                    "operator opted into n8n install"
                );
            }
            None => {
                warn!(
                    "n8n install opted in but neither docker nor npm available; install one first"
                );
            }
        }
        state.steps_completed.push(WizardStep::N8n as u8);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        println!();
        // NOOB-UX gate: Beginner skips the n8n prompt entirely.
        // n8n is an optional workflow engine — non-developers don't
        // know what "workflow engine" means and the safe default is
        // "don't install" (matches `Recommendation::skip_optional_installers`
        // from wizard/recommend.rs). Intermediate + Advanced still
        // get the prompt.
        if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!("[6e/9] Skipped optional workflow-engine install (n8n).");
            state.steps_completed.push(WizardStep::N8n as u8);
            return Ok(());
        }
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[6e/9] Install n8n (workflow engine, optional)?")
            .default(false)
            .interact()
            .context("n8n install confirm")?;
        if !want {
            state.steps_completed.push(WizardStep::N8n as u8);
            return Ok(());
        }
        state.install_n8n = true;
        let docker = n8n::check_docker_available().await.is_some();
        let npm = n8n::check_npm_available().await.is_some();
        match n8n::InstallStrategy::recommend(docker, npm) {
            Some(strategy) => {
                let cmd = strategy.install_command(n8n::DEFAULT_N8N_PORT);
                println!();
                println!("  {}", strategy.description());
                println!("      $ {}", cmd.join(" "));
                println!(
                    "  Then open http://127.0.0.1:{} to finish n8n's first-run setup.",
                    n8n::DEFAULT_N8N_PORT
                );
            }
            None => {
                println!();
                println!(
                    "  Neither Docker nor npm is on PATH. Install one first, then re-run \
                     `neoth init --force` to get the n8n step."
                );
            }
        }
    }

    state.steps_completed.push(WizardStep::N8n as u8);
    Ok(())
}

/// Step 6f — E-16 (Workstream B): prior-AI memory import record.
///
/// The actual migration is the separate `neoth-migrate` binary; the
/// wizard records the operator's intent + surfaces the runbook so a
/// later `neoth-migrate apply --confirm` knows where to look. Never
/// auto-applies — importing prior memory is heavyweight + irreversible
/// once the WAL frames land.
pub(crate) fn step6f_import_memory(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    debug!("wizard step 6f: prior-ai memory import intent");

    let path = if !interactive {
        args.import_memory.clone()
    } else {
        #[cfg(feature = "wizard")]
        {
            let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("[6f/9] Import memory from a previous AI assistant?")
                .default(false)
                .interact()
                .context("legacy-ai import confirm")?;
            if !want {
                state.steps_completed.push(WizardStep::ImportMemory as u8);
                return Ok(());
            }
            let raw: String =
                dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(
                        "  Path to your import-manifest.yaml \
                         (schema: neoth-migrate/examples/import-manifest.example.yaml)",
                    )
                    .allow_empty(true)
                    .interact_text()
                    .context("legacy-ai path input")?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(trimmed))
            }
        }
        #[cfg(not(feature = "wizard"))]
        {
            None
        }
    };

    let Some(path) = path else {
        state.steps_completed.push(WizardStep::ImportMemory as u8);
        return Ok(());
    };

    if !path.exists() {
        warn!(
            path = %path.display(),
            "prior-ai import manifest does not exist; recording intent but operator must \
             repoint with `neoth-migrate dry-run --manifest <path>` before applying"
        );
    }

    state.import_memory = Some(path.clone());

    if interactive {
        #[cfg(feature = "wizard")]
        {
            println!();
            println!("  Intent recorded. Run the migration when ready:");
            println!(
                "      $ neoth-migrate dry-run --manifest {}",
                path.display()
            );
            println!(
                "      $ neoth-migrate apply  --manifest {} --confirm",
                path.display()
            );
            println!(
                "  The wizard never auto-applies — migration writes WAL frames you can't undo."
            );
        }
    } else {
        info!(
            path = %path.display(),
            "legacy-ai import intent recorded; operator runs `neoth-migrate apply --confirm` manually"
        );
    }

    state.steps_completed.push(WizardStep::ImportMemory as u8);
    Ok(())
}

/// C-05 (Session 25) — wizard step 6g: credential import.
///
/// Iterates the available [`crate::credentials::CredentialImporter`]
/// impls (Chrome / Firefox + optional Bitwarden JSON export) +
/// hands the operator-visible outcomes to `run_wizard_step`,
/// which delegates redaction to the SC-17 typed gate
/// (`security::credential_redact::redact_credential_import`).
///
/// What this step writes to disk:
///   - Operator-visible summary printed inline.
///   - `~/.neoth/credentials_import_<ts>.json` sidecar file
///     containing the [`RedactedCredentialImportPayload`]. The
///     daemon's next boot picks up the sidecar, emits the
///     `0xD6 CREDENTIAL_IMPORT` WAL frame, then deletes the
///     sidecar — same at-least-once semantics the cluster audit
///     ingester uses.
///
/// What this step does NOT do: it never writes the secrets
/// themselves to disk. The SC-17 typed wrapper makes leaking
/// secret material via the WAL emit path unrepresentable. Future
/// secret-store integration (C-06) is the path operators will
/// use to actually consume the imported credentials.
///
/// Non-interactive runs skip the step entirely — credential
/// import requires explicit operator intent.
pub(crate) async fn step6g_credential_import(
    args: &InitArgs,
    interactive: bool,
    neoth_dir: &std::path::Path,
) {
    debug!("wizard step 6g: credential import (C-05)");
    if !interactive || args.non_interactive {
        debug!("skipping credential import in non-interactive mode");
        return;
    }
    println!("\n[6g/9] Credential import (optional).");
    println!("Bitwarden JSON / Chrome / Firefox sources detected on this host can");
    println!("be discovered + their structure recorded in a redacted audit frame.");
    println!("**No secret material is ever written to disk by this step.**");
    println!();

    #[cfg(feature = "wizard")]
    let opted_in = {
        match dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Run credential discovery now?")
            .default(false)
            .interact()
        {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "credential-import opt-in prompt failed; skipping step");
                return;
            }
        }
    };
    #[cfg(not(feature = "wizard"))]
    let opted_in = false;

    if !opted_in {
        println!("Skipped — operator declined.");
        return;
    }

    // Optional Bitwarden export path — empty input = no Bitwarden source.
    #[cfg(feature = "wizard")]
    let bitwarden_path: Option<std::path::PathBuf> = {
        match dialoguer::Input::<String>::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Bitwarden JSON export path (blank to skip)")
            .allow_empty(true)
            .interact_text()
        {
            Ok(s) if s.trim().is_empty() => None,
            Ok(s) => Some(std::path::PathBuf::from(s.trim())),
            Err(e) => {
                warn!(error = %e, "bitwarden path prompt failed; skipping bitwarden source");
                None
            }
        }
    };
    #[cfg(not(feature = "wizard"))]
    let bitwarden_path: Option<std::path::PathBuf> = None;

    // C-02b: a password-protected Bitwarden export needs the export
    // password to decrypt. Peek the file; only prompt when it's the
    // encrypted variant (the common plaintext export needs no password).
    #[cfg(feature = "wizard")]
    let bitwarden_password: Option<crate::secret::SecretString> = match bitwarden_path.as_deref() {
        // Bounded peek (file_is_encrypted_export caps the read at
        // MAX_PEEK_BYTES) — no unbounded synchronous read on the wizard
        // thread. The importer re-reads + handles the file authoritatively.
        Some(path) if crate::credentials::bitwarden::file_is_encrypted_export(path) => {
            match dialoguer::Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("Bitwarden export is encrypted — export password")
                .interact()
            {
                Ok(pw) => Some(crate::secret::SecretString::new(pw)),
                Err(e) => {
                    warn!(error = %e, "bitwarden password prompt failed; encrypted export will be skipped with a clear error");
                    None
                }
            }
        }
        _ => None,
    };
    #[cfg(not(feature = "wizard"))]
    let bitwarden_password: Option<crate::secret::SecretString> = None;

    let ts_unix = crate::time::now_unix_i64();
    let importers = crate::credentials::wizard_step::build_wizard_importer_list(
        bitwarden_path.as_deref(),
        bitwarden_password,
    );
    let result =
        crate::credentials::wizard_step::run_wizard_step(importers, "primary", ts_unix).await;

    if result.summaries.is_empty() {
        println!("No credential sources were available on this host.");
        return;
    }

    println!("\nDiscovered credential sources:");
    for s in &result.summaries {
        if s.ok {
            println!(
                "  • {} — {} entries, {} warnings",
                s.importer_name, s.entry_count, s.warning_count,
            );
        } else {
            println!("  • {} — FAILED: {}", s.importer_name, s.error_summary);
        }
    }
    println!(
        "\nSC-17 redactor pass: services_redacted = {} (entry_count = {})",
        result.redacted_payload.services_redacted, result.redacted_payload.entry_count,
    );

    // Sidecar drop — daemon picks up + emits 0xD6 WAL frame on next
    // boot. Atomic `.tmp` + rename, Windows-safe.
    if let Err(e) = write_credential_import_sidecar(neoth_dir, ts_unix, &result.redacted_payload) {
        warn!(error = %e, "credential import sidecar write failed (non-fatal)");
    } else {
        println!("Saved redacted import record (operator-private).");
    }
}

/// W-05 (Session 25) — wizard step 6h: install-command preview.
///
/// Reads the detect cache produced by `step1b_detect_environment`
/// (W-04), identifies operator-visible missing dev tools (docker,
/// node) and renders the per-OS install argv via
/// `wizard::install_step::FallbackChain::for_host()` +
/// `dry_run_install_commands`. The operator copies + runs the
/// commands manually — the wizard NEVER executes privileged
/// installs on the operator's behalf. This keeps the wizard's
/// surface "informational" and matches AGENTER's hard rule about
/// not invoking package managers without explicit go.
///
/// Non-interactive runs skip entirely. Operators who want to
/// audit the chain without prompts use
/// `neoth wizard install --dry-run` (CLI surface in W-05b).
pub(crate) fn step6h_install_recommended(
    args: &InitArgs,
    interactive: bool,
    neoth_dir: &std::path::Path,
) {
    debug!("wizard step 6h: install-command preview (W-05)");
    if !interactive || args.non_interactive {
        debug!("skipping install-command preview in non-interactive mode");
        return;
    }
    let now_unix = crate::time::now_unix_secs();
    let Some(report) = crate::installers::detect::load_cache(neoth_dir, now_unix) else {
        debug!("no detect cache; W-05 step has nothing to recommend");
        return;
    };

    // Identify the missing tools operators most commonly need
    // (docker for n8n + paperless; node for n8n; ffmpeg for media
    // ingest). Each entry: (canonical pkg_id, friendly name,
    // currently-detected-version Option).
    let candidates: Vec<(&str, &str, &Option<String>)> = vec![
        ("Docker.Docker", "Docker", &report.docker_version),
        ("OpenJS.NodeJS.LTS", "Node.js", &report.node_version),
        ("Gyan.FFmpeg", "ffmpeg", &report.ffmpeg_version),
    ];
    let missing: Vec<(&str, &str)> = candidates
        .iter()
        .filter(|(_, _, v)| v.is_none())
        .map(|(pkg, name, _)| (*pkg, *name))
        .collect();
    if missing.is_empty() {
        debug!("W-05: detect cache reports every recommended tool is already present");
        return;
    }

    println!("\n[6h/9] Install-command preview (W-05).");
    println!("These tools were NOT detected by step 1b. Copy + run the commands");
    println!("for the package manager you prefer. NEOTH never runs them for you.");
    println!();

    #[cfg(feature = "wizard")]
    let opted_in = {
        match dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Show install commands?")
            .default(true)
            .interact()
        {
            Ok(b) => b,
            Err(_) => return,
        }
    };
    #[cfg(not(feature = "wizard"))]
    let opted_in = true;

    if !opted_in {
        println!("Skipped — operator declined.");
        return;
    }

    let chain = crate::wizard::install_step::FallbackChain::for_host();
    if chain.is_empty() {
        println!("(No package-manager chain known for this host — install manually.)");
        return;
    }
    for (pkg_id, friendly) in &missing {
        println!("• {friendly} ({pkg_id})");
        let cmds = crate::wizard::install_step::dry_run_install_commands(&chain, pkg_id);
        for (kind, argv) in cmds {
            println!("    [{}] {}", kind.as_str(), argv.join(" "));
        }
        println!();
    }
}
