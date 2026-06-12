//! `neoth init` -- interactive onboarding wizard.
//!
//! Normative reference: PLAN/SPEC_onboarding.md
//!
//! All 7 wizard steps are implemented. Interactive prompts (dialoguer) require
//! the `wizard` Cargo feature (enabled by default). Non-interactive operation
//! works without `wizard` and is driven entirely by CLI flags + env vars.

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

mod io;
mod types;
mod validation;

pub(crate) use io::*;
pub use types::*;
pub use validation::*;

/// Main entry point for `neoth init`.
pub async fn run_init(args: InitArgs) -> Result<()> {
    let interactive = is_interactive(&args);
    debug!(interactive, force = args.force, "neoth init starting");

    let neoth_dir = dirs_home().join(".neoth");
    let marker = neoth_dir.join(".initialized");

    if marker.exists() && !args.force {
        info!("Already initialized. Showing reconfigure menu.");
        return run_reconfigure_menu(&args);
    }

    // Non-interactive (pipe / CI / --non-interactive flag) requires explicit license accept.
    if !interactive && !args.accept_license {
        anyhow::bail!(
            "--accept-license is required when running non-interactively \
             (no TTY detected or --non-interactive set)"
        );
    }

    let mut state = WizardState::default();

    // R-04 (Session 24) — restore in-flight wizard state from
    // ~/.neoth/wizard_checkpoint.json when the operator confirms
    // resume. Secrets are never persisted (the checkpoint module
    // strips them); operator re-enters provider_key + telegram_token
    // on resume. Decline → clear the file + start fresh.
    maybe_resume_from_checkpoint(&neoth_dir, interactive, &mut state)?;

    // Step 0 — operator picks GUI or CLI mode before anything else.
    // Per the HARD RULE `neoth_gui_first_screen_and_settings_parity`:
    // NEOTH targets non-developer operators ("noobs") who land on a
    // mode-selection screen, not a tracing-style logspew. If the
    // operator picks GUI here we exit the CLI wizard cleanly with a
    // pointer to `neothd-gui` — the wizard runs in either surface
    // with parity guarantees on settings.
    if step0_mode_selection(&args, interactive)?.exit_for_gui() {
        return Ok(());
    }
    step1_license(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step1b_detect_environment(&args, interactive, &neoth_dir).await;
    step1c_experience_level(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    // GOLD-HON-10 — new-vs-migration question, before the identity step.
    step1d_onboarding_mode(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step2_operator_id(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step3_language(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step3b_hmac_backup(interactive, &neoth_dir, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step4_role(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step5_provider(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step5b_inference_topology(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step5b2_ollama_provision(interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step5c_qwen_weights(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step5d_profile_approval_gate(interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6_channel(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6b_keet_pairing(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6c_obsidian_install(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6d_obsidian_vault_bootstrap(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6e_n8n_install(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6f_import_memory(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6g_credential_import(&args, interactive, &neoth_dir).await;
    step6h_install_recommended(&args, interactive, &neoth_dir);
    step7_autonomy(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step7b_auto_update(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step7c_wasm_plugin_activation(&args, interactive, &neoth_dir, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step7d_supervisor(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step8_summary(&args, &mut state)?;

    if args.dry_run {
        println!("[dry-run] No files written.");
    } else {
        write_config(&neoth_dir, &state).await?;
        write_initialized_marker(&neoth_dir, &state)?;
        // R-04: wizard reached the `.initialized` marker — the
        // checkpoint is no longer needed. Clear it so the next
        // `neoth init` (e.g. via --force or reconfigure) starts
        // from scratch instead of offering resume.
        if let Err(e) = crate::cli::wizard_checkpoint::clear_checkpoint(&neoth_dir) {
            tracing::warn!(error = %e, "post-init checkpoint clear failed (cosmetic)");
        }
        println!("Configuration written to ~/.neoth/");
        // R-05 (Session 24) — offer to auto-start the daemon + greet
        // with the first-tour message. Runs on TTY only; CI / pipe
        // skip so the wizard remains scriptable.
        if interactive {
            if let Err(e) = step9_offer_start_daemon(&neoth_dir) {
                tracing::warn!(error = %e, "auto-start daemon offer failed (cosmetic)");
            }
        }
        // Phase 28c R-24 GT-4: optional Q&A ground-truth seed. Runs only on
        // a TTY; non-interactive flow points operator at `neoth groundtruth
        // ask` instead. Skippable in interactive mode too.
        if interactive {
            maybe_run_groundtruth_qa(&state)?;
        } else {
            println!(
                "Run `neoth groundtruth ask` to seed ground-truth facts \
                 (or skip and add later via `neoth groundtruth add ...`)."
            );
        }
    }
    Ok(())
}

/// Step 0 — pick GUI vs CLI surface as the very first thing the
/// operator sees. Closes the HARD RULE
/// `neoth_gui_first_screen_and_settings_parity` violation flagged
/// in Session 26's UX review: a fresh `neoth init` run on a TTY
/// landed straight in a license prompt with tracing INFO lines
/// interleaved, which fails the "non-technical user on Win11" sanity test.
///
/// Non-interactive runs (CI / scripted bring-up / `--non-interactive`)
/// always pick CLI silently — there's no operator to ask, and the
/// scripted flow IS the API surface they want. Operators who want
/// to script the GUI install pass `--gui` to skip the prompt.
fn step0_mode_selection(args: &InitArgs, interactive: bool) -> Result<WizardModeChoice> {
    debug!("wizard step 0: mode selection");
    if args.gui {
        print_gui_handoff_banner();
        return Ok(WizardModeChoice::Gui);
    }
    if args.cli {
        // Operator explicitly opted out of the mode picker.
        return Ok(WizardModeChoice::Cli);
    }
    if !interactive {
        return Ok(WizardModeChoice::Cli);
    }

    println!();
    println!("=================================================================");
    println!("  Welcome to Neoth.");
    println!("=================================================================");
    println!();
    println!("  How would you like to set up Neoth?");
    println!();
    println!("    [GUI]  Graphical wizard — clickable cards, no terminal");
    println!("           prompts. Recommended for first-time setup.");
    println!();
    println!("    [CLI]  Terminal wizard — keyboard-only, scriptable.");
    println!("           Recommended for developers, SSH sessions, and");
    println!("           anything you want to automate later.");
    println!();

    #[cfg(feature = "wizard")]
    {
        let options = ["GUI (recommended)", "CLI (terminal wizard)"];
        let picked = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Pick your setup surface")
            .items(&options)
            .default(0)
            .interact()
            .context("mode-selection prompt")?;
        match picked {
            0 => {
                print_gui_handoff_banner();
                Ok(WizardModeChoice::Gui)
            }
            _ => Ok(WizardModeChoice::Cli),
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        // No `dialoguer` available → silent CLI fallback. Operators
        // who want GUI on a wizard-less build pass `--gui` explicitly.
        let _ = args;
        Ok(WizardModeChoice::Cli)
    }
}

fn step1_license(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 1: license");

    println!("\n=================================================================");
    println!(
        "  Neoth v{} -- Personal AI Agent",
        env!("CARGO_PKG_VERSION")
    );
    println!("  neoth knows.");
    println!("=================================================================\n");
    println!("License: MIT OR Apache-2.0");
    println!("Telemetry: ZERO. Neoth never phones home.\n");

    if !interactive {
        if args.accept_license {
            state.steps_completed.push(step_markers::STEP_1_LICENSE);
            return Ok(());
        }
        anyhow::bail!("--accept-license required in non-interactive mode");
    }

    #[cfg(feature = "wizard")]
    {
        let accept = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[1/9] Do you accept the license?")
            .default(false)
            .interact()
            .context("license confirmation prompt")?;
        if !accept {
            // Spec: deliberate refusal is exit 0, not failure.
            println!("Aborted. Re-run `neoth init` when ready.");
            std::process::exit(0);
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        if !args.accept_license {
            anyhow::bail!(
                "[1/9] Interactive license prompt requires the `wizard` feature. \
                 Re-run with --accept-license or rebuild with `--features wizard`."
            );
        }
    }

    state.steps_completed.push(step_markers::STEP_1_LICENSE);
    Ok(())
}

/// W-04 (Session 25) — wizard environment-detect step. Runs the
/// installer probes in parallel via `tokio::join!`, hands the
/// results to [`crate::wizard::detect_step::run_detect_step`] which
/// handles the 24h cache + atomic save, and prints a one-line
/// summary so the operator sees what the wizard found.
///
/// Non-interactive runs skip the probe pass entirely — probes do
/// subprocess + filesystem work that adds 2-15s of wall time, and
/// CI / scripted bring-up paths shouldn't pay that cost (the cache
/// hit on the next interactive run will fill the snapshot).
///
/// Failures are best-effort: a probe that fails returns None for
/// that field; a cache save IO error logs warn but doesn't abort
/// the wizard. The whole step is observability + planning input
/// for downstream steps — losing it never makes the wizard
/// non-functional.
async fn step1b_detect_environment(
    args: &InitArgs,
    interactive: bool,
    neoth_dir: &std::path::Path,
) {
    debug!("wizard step 1b: detect environment (W-04)");
    if !interactive {
        debug!("skipping environment detection in non-interactive mode");
        return;
    }
    if args.non_interactive {
        return;
    }
    println!("\n[1b/9] Detecting installed tools...");
    // GOLD-ADOPT-28 — classify the runtime environment (desktop / server / CI)
    // so the operator sees it and a headless box knows GUI steps are optional.
    let env_class = crate::wizard::env_probe::probe_and_classify();
    println!("  environment: {env_class}");
    if env_class.is_headless() {
        println!("  (headless — GUI / browser-OAuth steps are optional here; `neoth init --cli` skips them)");
    }
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (docker, compose_v2, compose_v1, node_npm, ffmpeg) = tokio::join!(
        crate::installers::n8n::check_docker_available(),
        crate::installers::paperless::check_docker_compose_available(),
        crate::installers::paperless::check_docker_compose_legacy_available(),
        crate::installers::node::check_node_and_npm(),
        crate::installers::ffmpeg::check_ffmpeg_available(),
    );
    let (node_version, npm_version) = match node_npm {
        Some((n, m)) => (Some(n), Some(m)),
        None => (None, None),
    };
    let inputs = crate::wizard::detect_step::DetectStepInputs {
        docker_version: docker,
        docker_compose_version: compose_v2,
        docker_compose_legacy_version: compose_v1,
        npm_version,
        node_version,
        git_version: None, // No `installers::git` probe today; follow-up.
        ffmpeg_version: ffmpeg,
        gpu: None, // GPU probe needs subprocess + parser orchestration
        // (out of scope for the W-04 wiring; cached on
        // first daemon boot).
        disk_free_bytes: None,
    };
    match crate::wizard::detect_step::run_detect_step(neoth_dir, now_unix, &inputs) {
        Ok(outcome) => {
            let summary = outcome.report.render_summary();
            for line in summary.lines() {
                println!("  {line}");
            }
            if outcome.probed_now {
                println!("  (snapshot saved; daemon will read it on next boot)");
                // W-04 follow-up (Session 26): drop a 0xD5 sidecar so
                // the daemon's ingester emits the DETECT_COMPLETE
                // audit frame. The wizard has no WAL writer of its
                // own — at-least-once via sidecar matches the
                // installer_ran + credentials_import path.
                if let Some(payload) = outcome.frame_payload.as_ref() {
                    if let Err(e) = write_detect_complete_sidecar(neoth_dir, now_unix, payload) {
                        warn!(error = %e, "detect_complete sidecar write failed (non-fatal)");
                    }
                }
            } else {
                println!("  (using cached snapshot from earlier today)");
            }
        }
        Err(e) => {
            warn!(error = %e, "wizard detect step save failed (non-fatal)");
            println!("  (detection inconclusive — wizard continues without it)");
        }
    }
}

/// NOOB-UX (Session 26) step 1c — operator picks an experience
/// level so later steps know how much tech detail to surface.
///
/// Beginner is the default + safest pick: every tech-deep prompt
/// in later steps (accelerator manual pick, embedding provider,
/// council recursion depth, …) silently uses the detected /
/// recommended value. Intermediate surfaces those prompts with
/// reasonable defaults pre-selected. Advanced surfaces everything
/// with no pre-selection.
///
/// Non-interactive runs default to Beginner (CI / scripted bring-
/// up benefits from minimal surface). Operators who want a
/// specific level in non-interactive mode can pass
/// `--experience-level <beginner|intermediate|advanced>` (added
/// alongside this step).
fn step1c_experience_level(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::wizard::recommend::ExperienceLevel;
    debug!("wizard step 1c: experience level");

    if let Some(ref raw) = args.experience_level_override {
        let lvl = match raw.to_ascii_lowercase().as_str() {
            "beginner" => ExperienceLevel::Beginner,
            "intermediate" => ExperienceLevel::Intermediate,
            "advanced" => ExperienceLevel::Advanced,
            other => anyhow::bail!(
                "invalid --experience-level '{other}'. Expected: beginner | intermediate | advanced"
            ),
        };
        state.experience_level = lvl;
        return Ok(());
    }
    if !interactive {
        // Safest non-interactive default: hand-holding flow.
        state.experience_level = ExperienceLevel::Beginner;
        return Ok(());
    }

    println!("\n[1c/9] How comfortable are you with terminals + config files?\n");
    println!("    [B]eginner       Auto-pick every default for you. Hide tech toggles.");
    println!("    [I]ntermediate   Show toggles with reasonable defaults pre-selected.");
    println!("    [A]dvanced       Surface every advanced setting. No defaults applied.");
    println!();

    #[cfg(feature = "wizard")]
    {
        let options = [
            "Beginner (recommended for first-time setup)",
            "Intermediate (terminal-comfortable)",
            "Advanced (power user)",
        ];
        let picked = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[1c/9] Pick your experience level")
            .items(&options)
            .default(0)
            .interact()
            .context("experience-level prompt")?;
        state.experience_level = match picked {
            0 => ExperienceLevel::Beginner,
            1 => ExperienceLevel::Intermediate,
            _ => ExperienceLevel::Advanced,
        };
    }
    #[cfg(not(feature = "wizard"))]
    {
        state.experience_level = ExperienceLevel::Beginner;
    }

    println!(
        "  [1c/9] experience: {} — tech-deep prompts will {}.",
        state.experience_level.as_str(),
        match state.experience_level {
            ExperienceLevel::Beginner => "be silently defaulted",
            ExperienceLevel::Intermediate => "appear with pre-selected defaults",
            ExperienceLevel::Advanced => "appear without defaults",
        }
    );
    Ok(())
}

/// GOLD-HON-10 — step 1d: new-vs-migration onboarding mode. Asked **before**
/// the identity step (step 2) so a migrating operator is told up front that
/// NEOTH can import a prior assistant's memory. The actual manifest is
/// collected later (step 6f); this is only the early signpost. Honest about
/// scope: v1.0 ships the preview/dry-run import path — the apply/import is
/// post-v1.0 (see GOLD-HON-01 / `neoth-migrate`). Non-interactive runs infer
/// the mode from `--import-memory` (a declared manifest ⇒ Migration).
fn step1d_onboarding_mode(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    debug!("wizard step 1d: onboarding mode (new vs migration)");

    let mode = if !interactive {
        // A declared import manifest is an unambiguous migration signal.
        if args.import_memory.is_some() {
            OnboardingMode::Migration
        } else {
            OnboardingMode::New
        }
    } else {
        #[cfg(feature = "wizard")]
        {
            println!("\n[1d/9] Is this a fresh start, or are you moving in from another assistant?\n");
            let options = [
                "Fresh install — start with an empty memory",
                "Migrate — import memory from a previous AI assistant",
            ];
            let picked =
                dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("[1d/9] Onboarding mode")
                    .items(&options)
                    .default(usize::from(args.import_memory.is_some()))
                    .interact()
                    .context("onboarding-mode prompt")?;
            if picked == 1 {
                OnboardingMode::Migration
            } else {
                OnboardingMode::New
            }
        }
        #[cfg(not(feature = "wizard"))]
        {
            if args.import_memory.is_some() {
                OnboardingMode::Migration
            } else {
                OnboardingMode::New
            }
        }
    };

    state.onboarding_mode = mode;
    state
        .steps_completed
        .push(step_markers::STEP_1D_ONBOARDING_MODE);

    match (mode, interactive) {
        (OnboardingMode::Migration, true) => {
            println!(
                "  [1d/9] Migration mode — the wizard collects your prior-assistant import \
                 manifest later (step 6f). Preview it any time with `neoth-migrate dry-run \
                 --manifest <path>`. Note: v1.0 ships the preview/dry-run path only; the \
                 apply/import step is post-v1.0, so the wizard records your intent and never \
                 auto-applies."
            );
        }
        (OnboardingMode::Migration, false) => {
            info!("onboarding mode: migration (import manifest declared via --import-memory)");
        }
        (OnboardingMode::New, true) => {
            println!("  [1d/9] Fresh install — starting with an empty memory.");
        }
        (OnboardingMode::New, false) => {}
    }
    Ok(())
}

fn step2_operator_id(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 2: operator_id");
    let default_id = get_os_username();

    let id = if let Some(ref id) = args.operator_id {
        validate_operator_id(id)?;
        id.clone()
    } else if !interactive {
        // Non-interactive without --operator-id: take OS username, fall back
        // to "operator" if it contains chars our validator rejects (Unicode,
        // spaces, etc. — common on Windows).
        if validate_operator_id(&default_id).is_ok() {
            default_id
        } else {
            "operator".to_string()
        }
    } else {
        #[cfg(feature = "wizard")]
        {
            loop {
                let input: String =
                    dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                        .with_prompt("[2/9] Operator identity (2-32 chars, [a-zA-Z0-9_-])")
                        .default(default_id.clone())
                        .interact_text()
                        .context("operator-id input")?;
                match validate_operator_id(&input) {
                    Ok(()) => break input,
                    Err(e) => {
                        eprintln!("  ✗ {e}");
                        continue;
                    }
                }
            }
        }
        #[cfg(not(feature = "wizard"))]
        {
            default_id
        }
    };
    state.operator_id = Some(id);
    state.steps_completed.push(step_markers::STEP_2_OPERATOR_ID);
    Ok(())
}

fn step3_language(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 3: language");
    validate_bcp47(&args.language)?;
    let default_code = args
        .code_language
        .clone()
        .unwrap_or_else(|| args.language.clone());

    let (primary, code) = if !interactive {
        validate_bcp47(&default_code)?;
        (args.language.clone(), default_code)
    } else {
        #[cfg(feature = "wizard")]
        {
            let primary: String =
                dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("[3/9] Primary language (BCP-47, e.g. en, de, zh-CN)")
                    .default(args.language.clone())
                    .validate_with(|input: &String| {
                        validate_bcp47(input).map_err(|e| e.to_string())
                    })
                    .interact_text()
                    .context("language input")?;
            let code: String =
                dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("[3/9] Code-comment language (BCP-47)")
                    .default(primary.clone())
                    .validate_with(|input: &String| {
                        validate_bcp47(input).map_err(|e| e.to_string())
                    })
                    .interact_text()
                    .context("code-language input")?;
            (primary, code)
        }
        #[cfg(not(feature = "wizard"))]
        {
            validate_bcp47(&default_code)?;
            (args.language.clone(), default_code)
        }
    };

    state.language_primary = Some(primary);
    state.language_code = Some(code);
    state.steps_completed.push(step_markers::STEP_3_LANGUAGE);
    Ok(())
}

/// SC-09 step 3b — optionally back up the WAL integrity (HMAC) key. The key is
/// bound to this machine/user (DPAPI on Windows, mode-0600 on Unix); a plaintext
/// backup is the ONLY way to recover the audit-chain history after a machine
/// change or Windows reinstall (see `PLAN/RUNBOOK_dpapi_hmac_recovery.md`).
/// Default NO — opt-in, since it writes a plaintext copy of a secret. Skipped
/// entirely in non-interactive runs (the operator can run
/// `neoth security backup-hmac-key` later).
fn step3b_hmac_backup(
    interactive: bool,
    neoth_dir: &std::path::Path,
    state: &mut WizardState,
) -> Result<()> {
    debug!("wizard step 3b: hmac key backup");
    if !interactive {
        return Ok(());
    }
    #[cfg(feature = "wizard")]
    {
        let do_backup = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(
                "[3b/9] Back up your WAL integrity key now? (lets you recover your \
                 tamper-evident audit history after a machine change — writes a plaintext copy)",
            )
            .default(false)
            .interact()
            .context("hmac backup prompt")?;
        state.hmac_backup_offered = true;
        if do_backup {
            let output = neoth_dir.join("wal").join("hmac_backup.bin");
            let bargs = crate::cli::security::BackupHmacKeyArgs {
                output: output.clone(),
                force: true,
                home: Some(neoth_dir.to_path_buf()),
            };
            // Best-effort: a backup failure must NOT abort onboarding.
            match crate::cli::security::run_backup_hmac_key(&bargs) {
                Ok(()) => eprintln!("[neoth init] WAL integrity key backed up to {}", output.display()),
                Err(e) => eprintln!("[neoth init] HMAC key backup failed (non-fatal): {e}"),
            }
        }
    }
    // `neoth_dir` + `state` are only consumed under the `wizard` feature.
    #[cfg(not(feature = "wizard"))]
    let _ = (neoth_dir, state);
    Ok(())
}

fn step4_role(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 4: role");
    let role = if let Some(r) = args.role {
        r
    } else if !interactive {
        OperatorRole::None
    } else {
        #[cfg(feature = "wizard")]
        {
            const CHOICES: &[(OperatorRole, &str)] = &[
                (OperatorRole::Developer, "developer"),
                (OperatorRole::SecurityResearcher, "security-researcher"),
                (OperatorRole::Founder, "founder"),
                (OperatorRole::DataScientist, "data-scientist"),
                (OperatorRole::Writer, "writer"),
                (OperatorRole::None, "none (skip role inference)"),
            ];
            let labels: Vec<&str> = CHOICES.iter().map(|(_, l)| *l).collect();
            let idx = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("[4/9] Operator role (shapes profile inference defaults)")
                .items(&labels)
                .default(0)
                .interact()
                .context("role selection")?;
            CHOICES[idx].0
        }
        #[cfg(not(feature = "wizard"))]
        {
            OperatorRole::None
        }
    };
    state.role = Some(role);
    state.steps_completed.push(step_markers::STEP_4_ROLE);
    Ok(())
}

async fn step5_provider(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 5: provider");

    // Detect the three first-class CLIs and offer to install any that are
    // missing. Memory note: [[neoth-cli-installers]] — operator never
    // opens npm or curl manually. Google's Antigravity CLI (`agy`)
    // replaces the retired gemini-cli per 2026-05-19 transition; legacy
    // `gemini` binaries still on PATH surface as a doctor warning.
    let mut claude_path = which_binary("claude");
    let mut codex_path = which_binary("codex");
    let mut antigravity_path = which_binary("agy");
    let legacy_gemini_path = which_binary("gemini");

    if interactive {
        println!("\n[5/9] LLM Provider — detected CLIs:");
        println!(
            "  claude: {}",
            claude_path.as_deref().unwrap_or("NOT FOUND")
        );
        println!("  codex:  {}", codex_path.as_deref().unwrap_or("NOT FOUND"));
        println!(
            "  agy:    {}",
            antigravity_path.as_deref().unwrap_or("NOT FOUND")
        );
        if let Some(legacy) = legacy_gemini_path.as_deref() {
            println!(
                "  ! legacy `gemini` ({legacy}) detected. Google retires gemini-cli \
                 API on 2026-06-18 — install `agy` to migrate."
            );
        }

        if claude_path.is_none() || codex_path.is_none() || antigravity_path.is_none() {
            offer_cli_installs(&mut claude_path, &mut codex_path, &mut antigravity_path).await?;
        }
    }

    let default_kind = if claude_path.is_some() {
        ProviderKind::ClaudeCli
    } else if codex_path.is_some() {
        ProviderKind::OpenaiApi
    } else {
        ProviderKind::Skip
    };

    let kind = if let Some(k) = args.provider {
        k
    } else if !interactive {
        // Pick #34 (Session 14, operator-flow audit-fix Flow#1): in
        // non-interactive mode (CI / cloud-init / scripted install)
        // a `Skip` default means no CLI was detected AND the operator
        // didn't pass `--provider`. The wizard would happily write a
        // Skip config; `neoth chat` then fails cryptically on
        // provider construction with no actionable signal. Surface
        // the gap loudly here — operator chose CI-mode + omitted a
        // mandatory choice, so we error with a remedy instead of
        // silently shipping a broken install.
        if matches!(default_kind, ProviderKind::Skip) {
            anyhow::bail!(
                "neoth init: non-interactive mode + no `--provider <kind>` + no claude/codex/agy \
                 binary detected on PATH. The wizard would silently configure provider=`skip` and \
                 `neoth chat` would fail. Pick one:\n  \
                   --provider claude_cli   (install claude CLI first)\n  \
                   --provider openai_api   (provide --provider-key sk-...)\n  \
                   --provider gemini_api   (provide --provider-key ...)\n  \
                   --provider local_qwen   (no key needed, ~3 GB local model)\n  \
                   --provider openai_compat --provider-endpoint <URL>   (OpenRouter / vLLM / etc.)"
            );
        }
        default_kind
    } else {
        #[cfg(feature = "wizard")]
        {
            const CHOICES: &[(ProviderKind, &str)] = &[
                (ProviderKind::ClaudeCli, "claude_cli (Claude CLI binary)"),
                (ProviderKind::OpenaiApi, "openai_api (api.openai.com)"),
                (
                    ProviderKind::AnthropicApi,
                    "anthropic_api (api.anthropic.com — Claude via API key) — ⚠ BILLED PER-TOKEN; \
                     pick claude_cli for OAuth/subscription (no metering)",
                ),
                (ProviderKind::GeminiApi, "gemini_api (Google Gemini REST)"),
                (
                    ProviderKind::Cohere,
                    "cohere_api (api.cohere.com — Cohere v2 Chat, ⚠ BILLED per-token)",
                ),
                (
                    ProviderKind::OpenaiCompat,
                    "openai_compat (OpenRouter / Together / Groq / LM Studio / vLLM / Ollama / custom)",
                ),
                (
                    ProviderKind::LocalQwen,
                    "local_qwen — Qwen2/Qwen3 dense on your hardware (~3 GB cached, CPU + GPU). No GPU? Pick openai_compat + OpenRouter instead.",
                ),
                (ProviderKind::Skip, "skip (configure later)"),
            ];
            let labels: Vec<&str> = CHOICES.iter().map(|(_, l)| *l).collect();
            let default_idx = CHOICES
                .iter()
                .position(|(k, _)| *k == default_kind)
                .unwrap_or(0);
            let idx = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("[5/9] LLM provider kind")
                .items(&labels)
                .default(default_idx)
                .interact()
                .context("provider selection")?;
            CHOICES[idx].0
        }
        #[cfg(not(feature = "wizard"))]
        {
            default_kind
        }
    };

    state.provider_kind = Some(kind);

    match kind {
        ProviderKind::LocalQwen => {
            // No endpoint / key — model + tokenizer come from Hugging Face.
            // `provider_model` here is the HF repo identifier; default in the
            // adapter applies if unset.
            state.provider_model = args.provider_model.clone();
            if interactive {
                println!(
                    "  local_qwen runs Qwen2/Qwen3 dense models locally via candle. \
                     First-run downloads ~3 GB of weights into ~/.neoth/models/ \
                     and may take a few minutes; later runs reuse the cache. \
                     CPU-only by default — pick CUDA/Metal in step 5b if you \
                     have a GPU. `neoth chat --temperature 0.7 --top-p 0.9` \
                     enables nucleus sampling; the default is greedy/argmax."
                );
            }
        }
        ProviderKind::LocalOuro => {
            // Ouro O-3: same hf-hub flow as LocalQwen. Default checkpoint
            // (when provider_model is None) is `ByteDance/Ouro-1.4B-Thinking`
            // — operator overrides with `--provider-model
            // ByteDance/Ouro-2.6B-Thinking` for the larger variant.
            state.provider_model = args.provider_model.clone();
            if interactive {
                println!(
                    "  local_ouro runs ByteDance Ouro LoopLM thinking-models \
                     locally via candle. First-run downloads ~3 GB of weights \
                     into ~/.neoth/models/. Looped-transformer architecture \
                     applies 24 layers 4× per token (~4× compute vs Qwen) but \
                     emits explicit reasoning prose in the -Thinking variants. \
                     Default checkpoint: ByteDance/Ouro-1.4B-Thinking. \
                     Apache-2.0; CPU-only by default — pick CUDA/Metal in step \
                     5b if you have a GPU."
                );
            }
        }
        ProviderKind::ClaudeCli => {
            let bin = args
                .provider_binary
                .clone()
                .or(claude_path)
                .unwrap_or_else(|| "claude".to_string());
            state.provider_binary = Some(bin);
            // MV-01c — catalog-first default so a newly-discovered Claude
            // model (Opus 4.8 / 4.9, Sonnet 4.8, codenames) becomes the
            // wizard default WITHOUT a code patch. Mirrors the OpenAI/Gemini
            // arm below; `ClaudeCli` maps to the `anthropic_api` catalog
            // key. Falls back to the bundled baseline when no fresh
            // anthropic_api entry exists (fresh install, pre-`catalog
            // refresh`).
            // GOLD-WIRE-03: the bundled fallback comes from the same SSOT as
            // `providers::from_config` (`model_roles::default_table`), so the
            // wizard + the runtime can't drift.
            let resolved_default = catalog_recommended_for_provider_kind(kind).unwrap_or_else(|| {
                crate::providers::default_model(
                    "claude_cli",
                    crate::providers::model_roles::ModelRole::Flagship,
                    "claude-opus-4-7",
                )
            });
            state.provider_model = Some(args.provider_model.clone().unwrap_or(resolved_default));
        }
        ProviderKind::OpenaiApi
        | ProviderKind::AnthropicApi
        | ProviderKind::GeminiApi
        | ProviderKind::Cohere
        | ProviderKind::OpenaiCompat => {
            // Cost guard (operator directive 2026-05-31): anthropic_api BILLS
            // per-token; claude_cli via tmux is the OAuth/subscription path
            // with NO metering. Make the distinction loud so a noob doesn't
            // accidentally bill themselves by picking the API over the CLI.
            if interactive && kind == ProviderKind::AnthropicApi {
                println!(
                    "  ⚠ anthropic_api BILLS PER-TOKEN via the Anthropic API. If you have a \
                     Claude subscription (Claude Pro/Max or Claude Code OAuth), go back and \
                     pick `claude_cli` instead — it routes through the `claude` CLI (tmux) \
                     with NO per-token metering. Only use anthropic_api if you specifically \
                     want API-key billing (e.g. no subscription, just an API key)."
                );
            }
            if interactive && kind == ProviderKind::Cohere {
                println!(
                    "  ⚠ cohere_api BILLS PER-TOKEN via the Cohere API (no subscription \
                     path). For a free local option pick `local_qwen`; for a Claude \
                     subscription pick `claude_cli`."
                );
            }
            // Endpoint resolution: for OpenaiCompat we prompt explicitly because
            // there is no upstream default. For OpenaiApi we default to api.openai.com.
            // For GeminiApi the endpoint lives in code (URL has model in path), no field needed.
            if matches!(kind, ProviderKind::OpenaiApi | ProviderKind::OpenaiCompat) {
                let mut default_endpoint = match kind {
                    ProviderKind::OpenaiApi => "https://api.openai.com/v1".to_string(),
                    _ => String::new(),
                };
                // For OpenaiCompat: auto-probe the local Claude bridge so the
                // operator does not have to type the URL when it is the common
                // path on this machine. Probe runs at wizard time only.
                if kind == ProviderKind::OpenaiCompat && default_endpoint.is_empty() {
                    if let Some(probed) = probe_local_bridge_sync() {
                        default_endpoint = probed;
                    }
                }
                let endpoint = if let Some(e) = args.provider_endpoint.clone() {
                    e
                } else if !interactive {
                    default_endpoint
                } else {
                    #[cfg(feature = "wizard")]
                    {
                        dialoguer::Input::<String>::with_theme(
                            &dialoguer::theme::ColorfulTheme::default(),
                        )
                        .with_prompt(format!(
                            "[5/9] {} endpoint (full URL incl. /v1)",
                            match kind {
                                ProviderKind::OpenaiApi => "OpenAI API",
                                _ => "OpenAI-compat (local bridge / vLLM / LM Studio)",
                            }
                        ))
                        .default(default_endpoint)
                        .interact_text()
                        .context("endpoint input")?
                    }
                    #[cfg(not(feature = "wizard"))]
                    {
                        default_endpoint
                    }
                };
                state.provider_endpoint = Some(endpoint);
            }

            // Key resolution: OpenaiCompat may accept empty (unauthenticated local server)
            // or a local bridge token (NOT an Anthropic key).
            let key = prompt_provider_key(args, interactive, kind)?;
            if let Some(k) = key {
                state.provider_key = Some(crate::secret::SecretString::from(k));
            }

            // Default model per provider. K-Models-Discovery (Session 14)
            // consults the cached catalog at `~/.neoth/models_catalog.json`
            // when present; falls back to the bundled hardcoded baseline
            // when the catalog is empty / stale / has no entry for the
            // chosen provider.
            // GOLD-WIRE-03: bundled fallbacks come from the same SSOT as
            // `providers::from_config` (`model_roles::default_table`) so the
            // wizard's freedom.yaml write can't drift from the runtime default.
            // anthropic_api uses BALANCED (sonnet) to match from_config's
            // metered-API cost choice. `openai_compat` requires an operator
            // model anyway (no table row) so it keeps its literal placeholder.
            use crate::providers::model_roles::ModelRole;
            let bundled_default = match kind {
                ProviderKind::OpenaiApi => {
                    crate::providers::default_model("openai_api", ModelRole::Flagship, "gpt-5.5")
                }
                ProviderKind::AnthropicApi => crate::providers::default_model(
                    "anthropic_api",
                    ModelRole::Balanced,
                    "claude-sonnet-4-6",
                ),
                ProviderKind::GeminiApi => crate::providers::default_model(
                    "gemini_api",
                    ModelRole::Flagship,
                    "gemini-3.1-pro-preview",
                ),
                ProviderKind::Cohere => crate::providers::default_model(
                    "cohere_api",
                    ModelRole::Flagship,
                    "command-a-plus-05-2026",
                ),
                ProviderKind::OpenaiCompat => "opus-4.7".to_string(),
                _ => String::new(),
            };
            let resolved_default =
                catalog_recommended_for_provider_kind(kind).unwrap_or(bundled_default);
            state.provider_model = Some(args.provider_model.clone().unwrap_or(resolved_default));
        }
        ProviderKind::AwsBedrock => {
            // C-3 (Session 13) Phase 1 — scaffold variant. Operator
            // sees it in the wizard select but the actual SigV4
            // adapter lands in Phase 2. Region + IAM credential
            // chain config schema also Phase 2.
            if interactive {
                println!(
                    "  aws_bedrock is C-3 Phase 1 scaffold — the variant is selectable \
                     for forward-compat but the SigV4 adapter ships in Phase 2. \
                     Use `openai_compat` against a Bedrock-on-OpenAI proxy in the interim."
                );
            }
        }
        ProviderKind::AzureOpenAi => {
            // C-4 (Session 13) Phase 1 — scaffold variant. Operator
            // sees it in the wizard select; actual adapter ships in
            // Phase 2 with the `api-version` + deployment-name-as-
            // model schema.
            if interactive {
                println!(
                    "  azure_openai is C-4 Phase 1 scaffold — the variant is selectable \
                     for forward-compat but the adapter (api-version query param + \
                     deployment-name-as-model schema) ships in Phase 2."
                );
            }
        }
        ProviderKind::Skip => {
            if interactive {
                println!("  Skipped. Configure later: `neoth provider add`");
            }
        }
    }

    state.steps_completed.push(step_markers::STEP_5_PROVIDER);
    Ok(())
}

/// Resolve a provider API key from (in order): --provider-key, env, interactive
/// password prompt. Returns None if user skips.
fn prompt_provider_key(
    args: &InitArgs,
    interactive: bool,
    kind: ProviderKind,
) -> Result<Option<String>> {
    if let Some(k) = &args.provider_key {
        return Ok(Some(k.clone()));
    }
    if !interactive {
        return Ok(::std::option::Option::None);
    }
    #[cfg(feature = "wizard")]
    {
        let label = match kind {
            ProviderKind::OpenaiApi => "OpenAI API key (sk-...)",
            ProviderKind::GeminiApi => "Gemini API key",
            ProviderKind::OpenaiCompat => "API key (or blank if endpoint is unauthenticated)",
            _ => "API key",
        };
        let key: String =
            dialoguer::Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(format!("[5/9] {label}"))
                .allow_empty_password(matches!(kind, ProviderKind::OpenaiCompat))
                .interact()
                .context("provider key input")?;
        if key.is_empty() {
            Ok(::std::option::Option::None)
        } else {
            Ok(Some(key))
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        let _ = kind;
        Ok(::std::option::Option::None)
    }
}

/// Step 5b — inference topology (D14b).
///
/// Operator picks:
///   1. **Mode** — single (one provider for all), triplet (same provider
///      on all three hemispheres but separate keys/models), or custom
///      (per-hemisphere provider).
///   2. **Accelerator** — auto-detected default, override allowed.
///   3. **Embedding provider** — local Qwen (uses the chosen accelerator)
///      or a cloud LLM with embedding endpoint.
///
/// Persists into `state.inference`. Non-interactive uses the
/// `--inference-mode` / `--accelerator-override` / `--embedding-provider`
/// flags and falls back to safe defaults (single mode, auto accelerator,
/// no embedding provider).
fn step5b_inference_topology(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::config::inference::{HemisphereSlot, InferenceProvider, TopologyMode};
    use crate::daemon::accelerator;

    debug!("wizard step 5b: inference topology");

    // Auto-detect runs in both interactive and non-interactive paths so we
    // log what we found. Cheap (<500ms total) — see daemon::accelerator.
    let probe = accelerator::probe();
    info!(
        picked = probe.picked.as_str(),
        cuda = probe.cuda,
        metal = probe.metal,
        openvino = probe.openvino,
        "accelerator probe complete"
    );

    // Mirror the operator's step-5 provider choice into default_slot so the
    // common single-mode case round-trips without re-asking the operator.
    state.inference.default_slot = HemisphereSlot {
        provider: state.provider_kind.map(|k| k.to_inference()),
        model: state.provider_model.clone(),
        key: state.provider_key.clone(),
        endpoint: state.provider_endpoint.clone(),
        region: None,
        api_version: None,
        // GOLD-WIRE-04: the single-mode default slot carries no council voice.
        voice: None,
    };

    // Non-interactive: honour CLI overrides, otherwise stay in single mode.
    if !interactive {
        let mode = parse_topology_mode_arg(args.inference_mode.as_deref())?;
        state.inference.mode = mode;
        if let Some(o) = args.accelerator_override.as_deref() {
            accelerator::Accelerator::from_str(o).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --accelerator-override '{o}'. Expected: cuda | metal | openvino | cpu"
                )
            })?;
            state.inference.accelerator_override = Some(o.to_string());
        }
        if let Some(e) = args.embedding_provider.as_deref() {
            let parsed = InferenceProvider::from_str(e).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --embedding-provider '{e}'. Expected: local_qwen | openai_api | anthropic_api | gemini_api"
                )
            })?;
            state.inference.embedding_provider = Some(parsed);
        }
        // E-2 Phase 4 (Session 14 Pick #23) — non-interactive depth
        // override. Clamp + stderr warning instead of the interactive
        // confirm screen (no TTY to draw it on).
        if let Some(raw) = args.council_depth {
            let (depth, clamped) =
                crate::config::inference::HemisphereCouncilDepth::new_clamped(raw);
            state.inference.hemisphere_council_depth = depth;
            if depth.get() > 1 {
                eprintln!(
                    "[neoth init] {}",
                    render_council_depth_cost_warning(depth.get()),
                );
            }
            if clamped {
                eprintln!(
                    "[neoth init] --council-depth={} exceeds MAX_HEMISPHERE_COUNCIL_DEPTH={}; clamped",
                    raw,
                    crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
                );
            }
        }
        state.steps_completed.push(step_markers::STEP_5B_TOPOLOGY); // marker for step 5b (kept separate)
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        // ─── 1. Topology mode ──────────────────────────────────────────
        // Finding 6 (Session 13) — Topology preset table with a new
        // `local-only` privacy-positive option that hard-binds all
        // three hemispheres to LocalQwen on operator hardware. Default
        // moves to `local-only` when an accelerator (CUDA / Metal /
        // OpenVino) is detected; on CPU-only systems the default stays
        // at `single` because CPU Qwen is too slow for daily-use Council
        // mode.
        let gpu_detected = probe.picked != accelerator::Accelerator::Cpu;
        let local_only_hint = if gpu_detected {
            "all 3 hemispheres = LocalQwen on operator hardware (RECOMMENDED — zero cloud exposure)"
        } else {
            "all 3 hemispheres = LocalQwen (CPU — slower; prefer `single` without a GPU)"
        };
        let single_hint = if gpu_detected {
            "one provider for everything (cloud or local)"
        } else {
            "one provider for everything (recommended)"
        };
        // GOLD-ADOPT-12 — multi-local preset: run up to 3 QUANTIZED abliterated
        // GGUFs (one per hemisphere) on the operator's own hardware via Ollama.
        let local_multi_hint = if gpu_detected {
            // GR-098 — the preset uses curated_or_nearest (verified repos sized to
            // VRAM), NOT a live "newest/best" lookup; say what it actually does.
            "1–3 local abliterated Q4/Q8 models across the hemispheres (Ollama — curated repos, VRAM-sized)"
        } else {
            "1–3 small local abliterated models (CPU — slow; prefer cloud without a GPU)"
        };
        // Topology preset table. `local-only` is a virtual preset — the
        // wizard expands it to Triplet mode + LocalQwen slots below so
        // freedom.yaml round-trips through the existing TopologyMode
        // enum without a new wire-format variant.
        let modes: [(TopologyMode, &str, String); 5] = [
            (TopologyMode::Single, "single", single_hint.to_string()),
            (
                TopologyMode::Triplet,
                "triplet",
                "same provider on all 3 hemispheres, separate keys/models allowed".to_string(),
            ),
            (
                TopologyMode::Custom,
                "custom",
                "fully custom — different provider per hemisphere".to_string(),
            ),
            (
                // local-only expands to Triplet mode at apply time.
                TopologyMode::Triplet,
                "local-only",
                local_only_hint.to_string(),
            ),
            (
                // local-multi expands to Triplet (all-local) or Custom (mixed)
                // at apply time; the real slots are set by the preset below.
                TopologyMode::Triplet,
                "local-multi",
                local_multi_hint.to_string(),
            ),
        ];
        let labels: Vec<String> = modes
            .iter()
            .map(|(_, n, hint)| format!("{n:<10}  {hint}"))
            .collect();
        let default_idx = topology_default_idx_for_probe(&probe);
        let pick = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[5b/9] Hemisphere LLM topology")
            .items(&labels)
            .default(default_idx)
            .interact()
            .context("topology mode select")?;
        state.inference.mode = modes[pick].0;
        let is_local_only_preset = matches!(modes[pick].1, "local-only");
        println!("  [5b/9] mode: {}", modes[pick].1);
        // GOLD-HON-11 — explicit single-provider confirmation. `Single`
        // means ONE provider answers every turn: no council cross-check,
        // no hemisphere diversity, and that provider sees every prompt.
        // Surface the trade-off so it's a deliberate choice, not a silent
        // default. (The same label + note is shown by `neoth hemispheres
        // show`.)
        if matches!(state.inference.mode, TopologyMode::Single) {
            println!(
                "      → single-provider setup confirmed: one provider handles every \
                 turn — no council cross-check or hemisphere diversity, and that provider \
                 sees all prompts. Switch later with `neoth init` or `neoth hemispheres set`."
            );
        }
        // Apply the local-only preset BEFORE the per-hemisphere loop —
        // the loop's gate on `Triplet|Custom` would otherwise overwrite
        // these with the per-role prompts.
        if is_local_only_preset {
            apply_local_only_preset(&mut state.inference);
            println!("  [5b/9] hemispheres (local-only preset):");
            println!("      left        provider=local_qwen  model=(adapter default)");
            println!("      right       provider=local_qwen  model=(adapter default)");
            println!("      cerebellum  provider=local_qwen  model=(adapter default)");
        }
        // GOLD-ADOPT-12 — multi-local abliterated preset: VRAM-size the local
        // model(s), let the operator choose how many hemispheres run local, bind
        // them to Ollama, and print the `ollama pull` commands. Same early-apply
        // ordering as local-only (before the per-role loop's Triplet|Custom gate).
        let is_local_multi_preset = matches!(modes[pick].1, "local-multi");
        if is_local_multi_preset {
            apply_local_multi_preset_interactive(&mut state.inference)?;
        }

        // ─── 2. Accelerator (only matters when local_qwen is in play) ──
        let accel_options = [
            accelerator::Accelerator::Cpu,
            accelerator::Accelerator::Cuda,
            accelerator::Accelerator::Metal,
            accelerator::Accelerator::OpenVino,
        ];
        // Build a "(detected: X)" hint so the operator sees what auto-detect
        // picked and which alternatives compile.
        let accel_labels: Vec<String> = accel_options
            .iter()
            .map(|a| {
                let marker = if *a == probe.picked {
                    " (detected)"
                } else {
                    ""
                };
                format!("{:<9}{marker}  {}", a.as_str(), a.description())
            })
            .collect();
        let default_idx = accel_options
            .iter()
            .position(|a| *a == probe.picked)
            .unwrap_or(0);
        // NOOB-UX gate: Beginner-level operators don't see the
        // manual accelerator pick — auto-detection is almost always
        // right, and surfacing the choice scares non-developers
        // (see Session 26 UX review for the screenshot that flagged this).
        // Intermediate + Advanced still get the prompt with the
        // detected pick pre-selected as default.
        let chosen_accel = if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!(
                "  [5b/9] accelerator: {} (auto-detected, hidden in beginner mode)",
                probe.picked.as_str()
            );
            probe.picked
        } else {
            let accel_pick =
                dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("    accelerator (used by local_qwen forward pass)")
                    .items(&accel_labels)
                    .default(default_idx)
                    .interact()
                    .context("accelerator select")?;
            accel_options[accel_pick]
        };
        // Only record an override when the operator picked something OTHER
        // than the detected default — auto-detection is preferred so portable
        // freedom.yaml files survive moving between hosts.
        state.inference.accelerator_override = if chosen_accel == probe.picked {
            None
        } else {
            Some(chosen_accel.as_str().to_string())
        };
        // Beginner-mode already printed the "auto-detected" line above;
        // re-print only for Intermediate/Advanced who actually picked.
        if !matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!("  [5b/9] accelerator: {}", chosen_accel.as_str());
        }

        // ─── 3. Per-hemisphere providers (only Triplet + Custom) ───────
        // SPEC_hemisphere_provider_selection.md §3: surface a recommended
        // provider per role (claude_cli/gemini/local_qwen) without
        // enforcing it. Custom mode additionally asks for a per-role
        // model so left=opus-4-7 + right=gemini-3.1-pro + cerebellum=Qwen3
        // can coexist without further CLI edits.
        if !is_local_only_preset
            && !is_local_multi_preset
            && matches!(
                state.inference.mode,
                TopologyMode::Triplet | TopologyMode::Custom
            )
        {
            let is_custom = matches!(state.inference.mode, TopologyMode::Custom);
            for role in ["left", "right", "cerebellum"] {
                let recommended = recommended_provider_for_role(role);
                let chosen = prompt_inference_provider(
                    &format!(
                        "    {role} hemisphere provider (recommended: {})",
                        recommended.as_str()
                    ),
                    Some(recommended),
                )?;
                // In Triplet mode model/key/endpoint inherit from default so
                // the operator isn't asked 3× for the same value. In Custom
                // mode prompt for the model — the most common reason to
                // pick per-role providers in the first place.
                let model = if is_custom {
                    prompt_hemisphere_model(role, chosen, &state.inference.default_slot.model)?
                } else {
                    state.inference.default_slot.model.clone()
                };
                let slot = HemisphereSlot {
                    provider: Some(chosen),
                    model,
                    key: state.inference.default_slot.key.clone(),
                    endpoint: state.inference.default_slot.endpoint.clone(),
                    region: state.inference.default_slot.region.clone(),
                    api_version: state.inference.default_slot.api_version.clone(),
                    // GOLD-WIRE-04: mirror the default slot's voice onto each
                    // per-role slot so a wizard-set voice survives role split.
                    voice: state.inference.default_slot.voice,
                };
                match role {
                    "left" => state.inference.left = slot,
                    "right" => state.inference.right = slot,
                    "cerebellum" => state.inference.cerebellum = slot,
                    _ => {}
                }
            }
            // Render summary so the operator confirms what they just
            // bound. Matches `neoth hemispheres show` table format.
            println!("  [5b/9] hemispheres:");
            for (label, slot) in [
                ("left      ", &state.inference.left),
                ("right     ", &state.inference.right),
                ("cerebellum", &state.inference.cerebellum),
            ] {
                let prov = slot
                    .provider
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| "(default)".into());
                let model = slot.model.as_deref().unwrap_or("(default)");
                println!("      {label}  provider={prov}  model={model}");
            }
        }

        // ─── 4. Embedding provider (independent of chat) ───────────────
        // NOOB-UX gate: Beginner skips. Embedding provider is an
        // optional speed-up for the skill router + ctx-mode re-rank;
        // operators who don't know what either of those is get a
        // sensible no-op default.
        if !matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            let want_emb = dialoguer::Confirm::with_theme(
                &dialoguer::theme::ColorfulTheme::default(),
            )
            .with_prompt(
                "    configure an embedding provider (used by skill router + ctx-mode re-rank)?",
            )
            .default(false)
            .interact()
            .context("embedding-yes/no confirm")?;
            if want_emb {
                let emb = prompt_inference_provider(
                    "    embedding provider",
                    Some(InferenceProvider::LocalQwen),
                )?;
                state.inference.embedding_provider = Some(emb);
                println!("  [5b/9] embeddings via {}", emb.as_str());
            }
        }

        // ─── E-2 Phase 4 (Session 14 Pick #23) — Council recursion depth
        //     + one-screen cost warning. Wizard never asked about this
        //     before; operators only saw depth>1 if they hand-edited
        //     freedom.yaml, which silently produced 3^depth leaf calls
        //     per message. Now they pick it explicitly with the math
        //     spelled out + a confirm that defaults to "no".
        let depth_choice = if let Some(raw) = args.council_depth {
            // Operator passed --council-depth on the CLI even though
            // we're in the interactive path. Honour it without re-asking.
            let (d, _) = crate::config::inference::HemisphereCouncilDepth::new_clamped(raw);
            d.get()
        } else if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            // NOOB-UX gate: Beginner gets the safe flat default
            // silently. Depth>1 is a 3^N cost multiplier — surfacing
            // it to non-developers risks accidental 81-leaf-call
            // councils that burn provider quota.
            1u8
        } else {
            let raw: u8 = dialoguer::Input::with_theme(
                &dialoguer::theme::ColorfulTheme::default(),
            )
            .with_prompt(
                "[5b/9] Council recursion depth (1=flat default, 2..=4 enables fractal sub-councils)",
            )
            .default(1u8)
            .validate_with(|v: &u8| {
                if *v <= crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH {
                    Ok(())
                } else {
                    Err(format!(
                        "must be 0..={}",
                        crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
                    ))
                }
            })
            .interact_text()
            .context("council depth input")?;
            raw
        };
        let depth_choice = if depth_choice > 1 {
            // One-screen cost warning + confirm — default no, so a
            // distracted Enter-spammer doesn't accidentally opt in to
            // 81 leaf calls per message.
            println!("{}", render_council_depth_cost_warning(depth_choice));
            let proceed =
                dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(format!(
                        "[5b/9] Proceed with hemisphere_council_depth={depth_choice}?"
                    ))
                    .default(false)
                    .interact()
                    .context("council depth confirm")?;
            if proceed {
                depth_choice
            } else {
                println!("  [5b/9] reverted to depth=1 (flat council)");
                1
            }
        } else {
            depth_choice
        };
        let (clamped_depth, was_clamped) =
            crate::config::inference::HemisphereCouncilDepth::new_clamped(depth_choice);
        state.inference.hemisphere_council_depth = clamped_depth;
        if was_clamped {
            println!(
                "  [5b/9] depth clamped to MAX_HEMISPHERE_COUNCIL_DEPTH={}",
                crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
            );
        }
        println!("  [5b/9] hemisphere_council_depth: {}", clamped_depth.get(),);
    }
    #[cfg(not(feature = "wizard"))]
    {
        // No dialoguer build → leave defaults from non-interactive path.
    }

    state.steps_completed.push(step_markers::STEP_5B_TOPOLOGY);
    Ok(())
}

/// E-2 Phase 4 (Session 14 Pick #23) — operator-readable cost warning
/// for council recursion. Spells out the leaf-call multiplication so a
/// hand-edited `freedom.yaml::hemisphere_council_depth: 4` (or a wizard
/// raise above 1) gets matched with the actual token-burn math BEFORE
/// the operator commits.
///
/// Returns the multi-line warning text ready to `println!` — pure-fn so
/// the same string lands in the wizard's interactive screen, in the
/// non-interactive `eprintln!` warning, and in the unit tests pinning
/// the math.
pub fn render_council_depth_cost_warning(depth: u8) -> String {
    // 3 hemispheres per recursion level → 3^depth leaf calls in the
    // worst case. Clamp the exponent to u32 so a malicious depth=255
    // can't overflow at the call site (the type-system clamps to 4
    // before this fn is invoked, but we stay defensive).
    let safe_depth: u32 = (depth as u32).min(u32::from(
        crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
    ));
    let leaf_calls = 3u64.saturating_pow(safe_depth);
    let default_cap: u32 = crate::config::inference::DEFAULT_MAX_CALLS_PER_USER_MESSAGE;
    let cap_note = if (leaf_calls as u32) > default_cap {
        format!(
            "exceeds council.max_calls_per_user_message default cap of {default_cap}\n     \
             → late hemispheres will surface `budget-exhausted` (Pick #19 BudgetToken). \
             Raise the cap in freedom.yaml if you want all leaves to run."
        )
    } else {
        format!("fits within the council.max_calls_per_user_message default cap of {default_cap}")
    };
    format!(
        "\
    ┌──────────────────────────────────────────────────────────────────┐\n  \
    │  COUNCIL DEPTH COST WARNING (E-2 Phase 4)                        │\n  \
    └──────────────────────────────────────────────────────────────────┘\n  \
      depth={depth} → up to {leaf_calls} leaf LLM calls per user message\n  \
      ({cap_note})\n  \
      Cloud-token cost at typical pricing: roughly €0.02-€0.50 per message at depth 2,\n  \
      scaling linearly with the leaf count.\n  \
      Operator-recommended defaults:\n  \
        depth=1: flat 3-hemisphere council (default)\n  \
        depth=2: fractal sub-councils — useful for high-stakes prompts only\n  \
        depth=3+: research / debugging — manual budget tuning required"
    )
}

/// Helper: prompt the operator to pick one `InferenceProvider`. Used in
/// per-hemisphere + embedding choices. Default lands on the operator's
/// already-chosen step-5 provider, so a single-key flow stays one click.
#[cfg(feature = "wizard")]
fn prompt_inference_provider(
    prompt: &str,
    default: Option<crate::config::inference::InferenceProvider>,
) -> Result<crate::config::inference::InferenceProvider> {
    use crate::config::inference::InferenceProvider;

    let options = [
        InferenceProvider::ClaudeCli,
        InferenceProvider::AnthropicApi,
        InferenceProvider::OpenAi,
        InferenceProvider::OpenAiCompat,
        InferenceProvider::Gemini,
        InferenceProvider::LocalQwen,
        InferenceProvider::AwsBedrock,
        InferenceProvider::AzureOpenAi,
    ];
    let labels: Vec<String> = options
        .iter()
        .map(|p| {
            let stub = if p.is_implemented() { "" } else { " [stub]" };
            format!("{:<15}{stub}  {}", p.as_str(), p.description())
        })
        .collect();
    let default_idx = default
        .and_then(|d| options.iter().position(|p| *p == d))
        .unwrap_or(0);
    let pick = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(prompt)
        .items(&labels)
        .default(default_idx)
        .interact()
        .context("provider select")?;
    Ok(options[pick])
}

#[cfg(not(feature = "wizard"))]
fn prompt_inference_provider(
    _prompt: &str,
    default: Option<crate::config::inference::InferenceProvider>,
) -> Result<crate::config::inference::InferenceProvider> {
    Ok(default.unwrap_or(crate::config::inference::InferenceProvider::ClaudeCli))
}

/// Per-role recommendation from SPEC_hemisphere_provider_selection.md §2.
/// Surfaced as a *suggestion* in the wizard — never enforced. Returning
/// `InferenceProvider` (not `Option`) lets the prompt always pre-select
/// a sane default for a one-keystroke confirm.
/// Finding 6 (Session 13) — apply the wizard's `local-only` topology
/// preset. All three hemispheres + the single-mode default slot are
/// bound to `LocalQwen`, mode is set to `Triplet` (so per-hemisphere
/// lookup honours the explicit slots rather than collapsing to a
/// single-mode fallback). Pure function — tested directly without
/// running the interactive wizard.
pub(crate) fn apply_local_only_preset(topology: &mut crate::config::inference::InferenceTopology) {
    use crate::config::inference::{HemisphereSlot, InferenceProvider, TopologyMode};
    let local_slot = HemisphereSlot {
        provider: Some(InferenceProvider::LocalQwen),
        model: None,
        key: None,
        endpoint: None,
        region: None,
        api_version: None,
        // GOLD-WIRE-04: local-only preset leaves voices unset.
        voice: None,
    };
    topology.mode = TopologyMode::Triplet;
    topology.default_slot = local_slot.clone();
    topology.left = local_slot.clone();
    topology.right = local_slot.clone();
    topology.cerebellum = local_slot;
}

/// GOLD-ADOPT-12 — apply a multi-local hemisphere preset: each local slot
/// becomes an `OpenAiCompat` provider pointing at Ollama's `/v1` with the
/// planned quantized GGUF as its model. All-local → Triplet; a local+cloud mix
/// → Custom (roles past `preset.locals` keep their existing — typically cloud —
/// slot). Ollama needs no key, so `key` stays `None`.
pub(crate) fn apply_local_abliterated_preset(
    topology: &mut crate::config::inference::InferenceTopology,
    preset: &crate::models::hemisphere_preset::HemispherePreset,
) {
    use crate::config::inference::{HemisphereSlot, InferenceProvider, TopologyMode};
    let make_slot = |model_ref: &str| HemisphereSlot {
        provider: Some(InferenceProvider::OpenAiCompat),
        model: Some(model_ref.to_string()),
        key: None,
        endpoint: Some(preset.endpoint.clone()),
        region: None,
        api_version: None,
        voice: None,
    };
    topology.mode = if preset.is_all_local() {
        TopologyMode::Triplet
    } else {
        TopologyMode::Custom
    };
    for local in &preset.locals {
        let slot = make_slot(&local.ollama_model_ref);
        match local.role {
            "left" => topology.left = slot,
            "right" => topology.right = slot,
            "cerebellum" => topology.cerebellum = slot,
            _ => {}
        }
    }
    // Mirror the first local onto default_slot only when every hemisphere is
    // local (matches apply_local_only_preset); a mixed setup keeps the cloud
    // default so unspecified surfaces still reach a capable provider.
    if preset.is_all_local() {
        if let Some(first) = preset.locals.first() {
            topology.default_slot = make_slot(&first.ollama_model_ref);
        }
    }
}

/// GOLD-ADOPT-12 — interactive multi-local preset: VRAM-size the local model(s),
/// let the operator choose how many hemispheres run local (1..=max the hardware
/// supports), bind them to Ollama, and print the `ollama pull` commands. Falls
/// back to single-provider when no GPU/VRAM holds a usable local model.
#[cfg(feature = "wizard")]
fn apply_local_multi_preset_interactive(
    topology: &mut crate::config::inference::InferenceTopology,
) -> Result<()> {
    use crate::installers::ollama::DEFAULT_OLLAMA_PORT;
    use crate::models::gguf_variants::VariantClass;
    use crate::models::hemisphere_preset::{build_local_preset, ROLES};
    use crate::models::selector::recommended_local_count;

    let vram_mib = crate::installers::gpu::probe_gpu().vram_mib;
    let n_max = recommended_local_count(vram_mib);
    if n_max == 0 {
        println!(
            "  [5b/9] local-multi: no GPU/VRAM holds a usable (≥3B) local model — \
             staying single-provider. Add a GPU and re-run, or pick a cloud provider."
        );
        topology.mode = crate::config::inference::TopologyMode::Single;
        return Ok(());
    }
    // Operator chooses 1..=n_max local hemispheres (default = the max the
    // hardware supports): one local + cloud rest, or fully local.
    let count_labels: Vec<String> = (1..=n_max)
        .map(|n| {
            if n == 1 {
                "1 local hemisphere (biggest model; other 2 stay cloud)".to_string()
            } else if (n as usize) == ROLES.len() {
                format!("{n} local hemispheres (fully local, zero cloud)")
            } else {
                format!("{n} local hemispheres (rest stay cloud)")
            }
        })
        .collect();
    let pick = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("    how many hemispheres run a LOCAL abliterated model?")
        .items(&count_labels)
        .default((n_max - 1) as usize)
        .interact()
        .context("local count select")?;
    let n_local = (pick as u8) + 1;

    let preset = build_local_preset(
        vram_mib,
        n_local,
        VariantClass::Abliterated,
        DEFAULT_OLLAMA_PORT,
    );
    apply_local_abliterated_preset(topology, &preset);

    println!("  [5b/9] hemispheres (local-multi — abliterated Q4/Q8 via Ollama):");
    for l in &preset.locals {
        println!(
            "      {:<10}  {:>4.1}B {:<7} {}",
            l.role, l.param_b, l.quant_tag, l.repo
        );
    }
    if !preset.is_all_local() {
        println!("      (remaining hemispheres keep your cloud provider)");
    }
    if !preset.locals.is_empty() {
        println!(
            "      Each local hemisphere is wired to {} (no API key).",
            preset.endpoint
        );
        println!("      The next step offers to install Ollama + pull these models.");
    }
    Ok(())
}

/// GOLD-ADOPT-13 — collect the distinct Ollama-served local model refs the
/// applied topology points at (OpenAiCompat slots on the Ollama `/v1` endpoint
/// with an `hf.co/...` model). Pure + order-preserving + deduplicated, so the
/// provision step pulls each model exactly once.
fn collect_ollama_model_refs(
    topo: &crate::config::inference::InferenceTopology,
) -> Vec<String> {
    use crate::config::inference::InferenceProvider;
    let endpoint = crate::installers::ollama::openai_compat_endpoint(
        crate::installers::ollama::DEFAULT_OLLAMA_PORT,
    );
    let mut refs: Vec<String> = Vec::new();
    for slot in [&topo.left, &topo.right, &topo.cerebellum] {
        if slot.provider == Some(InferenceProvider::OpenAiCompat)
            && slot.endpoint.as_deref() == Some(endpoint.as_str())
        {
            if let Some(m) = slot.model.as_deref() {
                if m.starts_with("hf.co/") && !refs.iter().any(|r| r == m) {
                    refs.push(m.to_string());
                }
            }
        }
    }
    refs
}

/// GOLD-ADOPT-13 — wizard step 5b₂: provision the Ollama runtime for any
/// local-multi hemispheres. Offers to install Ollama (if absent) and pull each
/// model. Non-interactive just prints the commands (no surprise multi-GB network
/// pulls in CI / scripted installs). No-op when no Ollama models are configured.
async fn step5b2_ollama_provision(interactive: bool, state: &mut WizardState) -> Result<()> {
    let refs = collect_ollama_model_refs(&state.inference);
    if refs.is_empty() {
        return Ok(());
    }

    if !interactive {
        for r in &refs {
            println!(
                "[neoth init] local model configured — run: {}",
                crate::installers::ollama::pull_command(r).join(" ")
            );
        }
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        use crate::installers::ollama;
        println!("\n[5b/9] Ollama runtime — serves your local abliterated model(s).");

        // Install Ollama if it isn't already on PATH.
        if ollama::check_ollama_available().await.is_none() {
            let install = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(format!(
                    // GR-086 — show the ACTUAL command (e.g. `curl … | sh`), not
                    // the terse `upstream_script` tag, so consent is informed.
                    "Ollama not found. Install it now? This runs:  {}",
                    ollama::InstallPath::for_host().display_command()
                ))
                .default(true)
                .interact()
                .context("ollama install confirm")?;
            if install {
                match ollama::install_for_host().await {
                    Ok(()) => println!("  ✓ Ollama installed"),
                    Err(e) => println!(
                        "  ! Ollama install failed: {e}\n    Install manually from {} then re-run the pulls below.",
                        ollama::OLLAMA_DOWNLOAD_URL
                    ),
                }
            } else {
                println!("  → skipped Ollama install. Pull commands are printed below.");
            }
        } else {
            println!("  ✓ Ollama already installed");
        }

        // Offer to pull each configured model.
        let pull = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(format!(
                "Pull the {} local model(s) now (multi-GB download)?",
                refs.len()
            ))
            .default(true)
            .interact()
            .context("ollama pull confirm")?;
        for r in &refs {
            let cmd = ollama::pull_command(r);
            if pull {
                println!("  ⏬ {}", cmd.join(" "));
                if let Err(e) = ollama::run_command(&cmd).await {
                    println!("  ! pull failed: {e} (re-run `{}` later)", cmd.join(" "));
                }
            } else {
                println!("  later: $ {}", cmd.join(" "));
            }
        }
    }
    Ok(())
}

/// Finding 6 (Session 13) — pick the default topology-select index for
/// the wizard's mode list (single=0, triplet=1, custom=2, local-only=3).
/// When the accelerator probe found anything other than CPU, the
/// privacy-positive `local-only` preset wins; otherwise `single`
/// remains the default because CPU Qwen is too slow for daily Council
/// mode.
pub(crate) fn topology_default_idx_for_probe(probe: &crate::daemon::accelerator::Probe) -> usize {
    if probe.picked != crate::daemon::accelerator::Accelerator::Cpu {
        3
    } else {
        0
    }
}

fn recommended_provider_for_role(role: &str) -> crate::config::inference::InferenceProvider {
    use crate::config::inference::InferenceProvider as I;
    match role {
        "left" => I::ClaudeCli,       // analytic / structured reasoning
        "right" => I::Gemini,         // creative / freeform
        "cerebellum" => I::LocalQwen, // fast pattern matching / routing
        _ => I::ClaudeCli,
    }
}

/// GOLD-ADOPT-12 — the LOCAL mirror of [`recommended_provider_for_role`]: which
/// LOCAL provider to recommend per hemisphere role for a fully-local brain. The
/// analytic LEFT role gets **`LocalOuro`** (ByteDance's looped LoopLM — explicit
/// multi-step reasoning, the local analog of the cloud default's `ClaudeCli`
/// on left); the creative RIGHT and fast CEREBELLUM roles get `LocalQwen`.
///
/// NOTE: a `left=Ouro` + `right/cerebellum=Qwen` split loads TWO local model
/// families, so the VRAM-shared [`apply_local_only_preset`] deliberately keeps a
/// single shared Qwen by default (noob-VRAM-safe). This Ouro-on-left
/// recommendation is applied only by the explicit `neoth hemispheres preset
/// local-reasoning`, where the operator opts into the extra VRAM cost knowingly.
pub(crate) fn recommended_local_provider_for_role(
    role: &str,
) -> crate::config::inference::InferenceProvider {
    use crate::config::inference::InferenceProvider as I;
    match role {
        "left" => I::LocalOuro,       // explicit-reasoning LoopLM for the analytic role
        "right" => I::LocalQwen,      // creative / freeform
        "cerebellum" => I::LocalQwen, // fast routing
        _ => I::LocalQwen,
    }
}

/// Suggest a sensible default model per provider × role pair. Operators
/// editing in Custom mode want a starting point; they can override.
///
/// Bundled (hardcoded) defaults — kept as a safe baseline for fresh
/// installs / air-gapped setups / when the model catalog hasn't been
/// populated yet. The K-Models-Discovery catalog
/// (`~/.neoth/models_catalog.json`) overrides these when present —
/// see [`catalog_or_bundled_default_model_for`].
fn default_model_for(
    role: &str,
    provider: crate::config::inference::InferenceProvider,
) -> Option<&'static str> {
    use crate::config::inference::InferenceProvider as I;
    match (role, provider) {
        ("left", I::ClaudeCli) => Some("claude-opus-4-7"),
        ("left", I::AnthropicApi) => Some("claude-opus-4-7"),
        ("left", I::OpenAi) => Some("gpt-5.5"),
        ("right", I::Gemini) => Some("gemini-3.1-pro-preview"),
        ("right", I::ClaudeCli) => Some("claude-sonnet-4-6"),
        ("right", I::AnthropicApi) => Some("claude-sonnet-4-6"),
        ("cerebellum", I::LocalQwen) => Some("Qwen/Qwen2.5-3B-Instruct"),
        ("cerebellum", I::OpenAi) => Some("gpt-5.4-mini"),
        ("cerebellum", I::OpenAiCompat) => Some("qwen2.5-3b-instruct"),
        _ => None,
    }
}

/// Catalog-first default model lookup keyed by the wizard's
/// `ProviderKind` against an explicit catalog path. Production caller
/// uses [`catalog_recommended_for_provider_kind`] which resolves to
/// `~/.neoth/models_catalog.json`. Returns the provider's
/// `recommended_default()` when present, `None` otherwise.
pub(crate) fn catalog_recommended_for_provider_kind_at(
    catalog_path: &std::path::Path,
    kind: ProviderKind,
) -> Option<String> {
    use crate::models::catalog::ModelsCatalog;

    let key = kind.catalog_key()?;
    let catalog = ModelsCatalog::load_from(catalog_path);
    catalog
        .provider(key)
        .and_then(|pc| pc.recommended_default())
        .map(|m| m.id.clone())
}

/// Production wrapper for [`catalog_recommended_for_provider_kind_at`]
/// against the operator's actual `~/.neoth/models_catalog.json`.
pub(crate) fn catalog_recommended_for_provider_kind(kind: ProviderKind) -> Option<String> {
    use crate::config::FreedomConfig;
    use crate::models::catalog::ModelsCatalog;

    let home = FreedomConfig::default_neoth_home();
    let path = ModelsCatalog::default_path(&home);
    catalog_recommended_for_provider_kind_at(&path, kind)
}

/// Map an `InferenceProvider` to the catalog key used by
/// `crate::models::catalog`. Catalog keys mirror NEOTH's snake_case
/// `ProviderKind` strings (`anthropic_api`, `openai_api`, etc.).
fn catalog_key_for_provider(
    provider: crate::config::inference::InferenceProvider,
) -> Option<&'static str> {
    use crate::config::inference::InferenceProvider as I;
    Some(match provider {
        I::ClaudeCli | I::AnthropicApi => "anthropic_api",
        I::OpenAi => "openai_api",
        I::OpenAiCompat => "openai_compat",
        I::Gemini => "gemini_api",
        I::AwsBedrock => "aws_bedrock",
        // Local Qwen + AzureOpenAi + Cohere don't have a model-catalog
        // source today — fall through to bundled defaults.
        I::LocalQwen | I::LocalOuro | I::AzureOpenAi | I::Cohere => return None,
    })
}

/// Catalog-first default model resolution. Loads the discovery cache
/// at `~/.neoth/models_catalog.json` and returns the provider's
/// `recommended_default()` when present. Falls back to the
/// hardcoded bundled defaults from [`default_model_for`] when:
///   - the catalog file is missing (fresh install, no `neoth catalog
///     refresh` yet)
///   - the catalog has no entry for this provider (discovery skipped
///     it for cred reasons)
///   - the catalog has the entry but every model is deprecated
///
/// Pure helper — no network calls, no daemon dependencies. Wizard
/// runs this synchronously during step5 / step5b.
pub(crate) fn catalog_or_bundled_default_model_for(
    role: &str,
    provider: crate::config::inference::InferenceProvider,
) -> Option<String> {
    use crate::config::FreedomConfig;
    use crate::models::catalog::ModelsCatalog;

    if let Some(key) = catalog_key_for_provider(provider) {
        let home = FreedomConfig::default_neoth_home();
        let catalog_path = ModelsCatalog::default_path(&home);
        let catalog = ModelsCatalog::load_from(&catalog_path);
        if let Some(pc) = catalog.provider(key) {
            if let Some(recommended) = pc.recommended_default() {
                return Some(recommended.id.clone());
            }
        }
    }
    default_model_for(role, provider).map(String::from)
}

/// Custom-mode: prompt for the model identifier per hemisphere. Pre-fills
/// either the operator's step-5 default (if they want consistency) or the
/// `default_model_for(role, provider)` recommendation when the role-provider
/// pair has a known sensible default. Empty input → inherit from default_slot.
#[cfg(feature = "wizard")]
fn prompt_hemisphere_model(
    role: &str,
    provider: crate::config::inference::InferenceProvider,
    inherited_default: &Option<String>,
) -> Result<Option<String>> {
    // K-Models-Discovery (Session 14): try the cached catalog first;
    // fall back to the hardcoded bundled default. The catalog ALSO
    // surfaces a fuzzy-select option list when available so the
    // operator picks a real current model id with their up/down
    // arrows rather than typing one from memory.
    let suggestion: Option<String> =
        catalog_or_bundled_default_model_for(role, provider).or_else(|| inherited_default.clone());
    let catalog_choices = catalog_model_ids_for_provider(provider);

    let prompt = format!("      {role} model (empty → inherit default)");
    let theme = dialoguer::theme::ColorfulTheme::default();

    // Catalog has ≥2 entries → render a select with "type your own"
    // as the trailing option for full control.
    if catalog_choices.len() >= 2 {
        let mut items: Vec<String> = catalog_choices.to_vec();
        items.push("(type my own)".to_string());
        let default_idx = suggestion
            .as_ref()
            .and_then(|s| items.iter().position(|m| m == s))
            .unwrap_or(0);
        let selection = dialoguer::Select::with_theme(&theme)
            .with_prompt(&prompt)
            .items(&items)
            .default(default_idx)
            .interact()
            .context("hemisphere model select")?;
        if selection < items.len() - 1 {
            return Ok(Some(items[selection].clone()));
        }
        // "type my own" → fall through to free-text input below.
    }

    let mut input = dialoguer::Input::<String>::with_theme(&theme)
        .with_prompt(prompt)
        .allow_empty(true);
    if let Some(s) = suggestion.as_ref() {
        input = input.default(s.clone());
    }
    let raw = input.interact_text().context("hemisphere model input")?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(inherited_default.clone())
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

/// Catalog lookup: every non-deprecated model id the operator's
/// `~/.neoth/models_catalog.json` lists for `provider`. Empty `Vec`
/// when the catalog has no entry / no fresh entries. Pure helper —
/// no network calls.
pub(crate) fn catalog_model_ids_for_provider(
    provider: crate::config::inference::InferenceProvider,
) -> Vec<String> {
    use crate::config::FreedomConfig;
    use crate::models::catalog::ModelsCatalog;

    let Some(key) = catalog_key_for_provider(provider) else {
        return Vec::new();
    };
    let home = FreedomConfig::default_neoth_home();
    let catalog_path = ModelsCatalog::default_path(&home);
    let catalog = ModelsCatalog::load_from(&catalog_path);
    catalog
        .provider(key)
        .map(|pc| {
            pc.models
                .iter()
                .filter(|m| !m.deprecated)
                .map(|m| m.id.clone())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(not(feature = "wizard"))]
fn prompt_hemisphere_model(
    _role: &str,
    _provider: crate::config::inference::InferenceProvider,
    inherited_default: &Option<String>,
) -> Result<Option<String>> {
    Ok(inherited_default.clone())
}

/// Parse the `--inference-mode` flag. None → Single.
fn parse_topology_mode_arg(arg: Option<&str>) -> Result<crate::config::inference::TopologyMode> {
    use crate::config::inference::TopologyMode;
    match arg {
        None => Ok(TopologyMode::Single),
        Some(s) => TopologyMode::from_str(s).ok_or_else(|| {
            anyhow::anyhow!("invalid --inference-mode '{s}'. Expected: single | triplet | custom")
        }),
    }
}

/// K-4b (Session 21, 2026-05-23) — operator-facing Telegram prompt text.
/// Defaults depend on whether `pear` is on PATH: when present, Keet is
/// the recommended primary so Telegram is framed as the FALLBACK and
/// the wizard defaults to No more strongly; without pear, Telegram is
/// the only operator-private option so the prompt stays neutral.
///
/// Pure-fn so the K-4b restructure can be unit-tested without a TTY.
pub(crate) fn k4b_telegram_prompt_text(pear_present: bool) -> &'static str {
    if pear_present {
        "[6/9] Set up Telegram as a FALLBACK channel? (Keet is preferred primary; default: no)"
    } else {
        "[6/9] Set up a Telegram bot now? (optional, can add later)"
    }
}

/// Step 5c — NOOB-UX-6 (Workstream B): Qwen weights pre-download.
///
/// Only meaningful when the operator's inference topology pulls in
/// `LocalQwen` somewhere (default_slot or any hemisphere or the
/// embedding provider). The probe is sync + ~1ms (file_exists); when
/// weights are already cached the step is a no-op log line.
///
/// GOLD-ADOPT-10 — this step deliberately pre-downloads the FIXED
/// [`qwen_weights::DEFAULT_QWEN_MODEL_ID`] (Qwen2.5-3B), the single curated
/// candle weight + the always-available lightweight `LocalQwen` baseline. It is
/// VRAM-INDEPENDENT by design: VRAM-aware local-model sizing is a SEPARATE path
/// — the Ollama multi-local preset (`models::hemisphere_preset::build_local_preset`
/// → `selector::quantized_shortlist(vram)` → `gguf_variants::curated_or_nearest`),
/// which scales the GGUF size to the detected VRAM. `recommended_model_tier()`
/// feeds the operator-facing recommendation (`wizard::recommend`), not this
/// candle pre-download.
///
/// Non-interactive: honours `--download-qwen-weights`. With the flag
/// the step records the intent + surfaces the `huggingface-cli` line
/// the operator runs. Without the flag the step is a silent no-op
/// for hosts that don't touch LocalQwen.
async fn step5c_qwen_weights(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::installers::qwen_weights;

    debug!("wizard step 5c: qwen weights");

    if !inference_uses_local_qwen(&state.inference, &state.provider_kind) {
        // Operator picked cloud-only — no LocalQwen path = nothing to
        // pre-download. Mark step run + return.
        state.steps_completed.push(step_markers::STEP_5C_QWEN_WEIGHTS);
        return Ok(());
    }

    let cached = qwen_weights::check_weights_cached(qwen_weights::DEFAULT_QWEN_MODEL_ID);

    if !interactive {
        let opted_in = args.download_qwen_weights;
        let action = qwen_weights::recommend_action(cached, opted_in);
        match action {
            qwen_weights::WeightsAction::AlreadyCached => {
                info!(
                    model = qwen_weights::DEFAULT_QWEN_MODEL_ID,
                    "qwen weights cached"
                );
            }
            qwen_weights::WeightsAction::DownloadNeeded => {
                state.download_qwen_weights = true;
                let cmd =
                    qwen_weights::weights_download_command(qwen_weights::DEFAULT_QWEN_MODEL_ID);
                info!(
                    cmd = %cmd.join(" "),
                    gb = qwen_weights::DEFAULT_QWEN_DOWNLOAD_GB,
                    "operator opted into Qwen weights pre-download"
                );
            }
            qwen_weights::WeightsAction::OperatorSkipped => {
                warn!(
                    model = qwen_weights::DEFAULT_QWEN_MODEL_ID,
                    "LocalQwen configured but weights not cached + operator did not pass --download-qwen-weights; \
                     first chat will lazy-download"
                );
            }
        }
        state.steps_completed.push(step_markers::STEP_5C_QWEN_WEIGHTS);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        println!();
        if cached {
            println!("[5c/9] Qwen weights already cached (~/.cache/huggingface/hub/). Skipping.");
            state.steps_completed.push(step_markers::STEP_5C_QWEN_WEIGHTS);
            return Ok(());
        }
        // NOOB-UX gate: Beginner skips the pre-download prompt. The
        // jargon ("Pre-download", "lazy-download", `huggingface-cli`)
        // scares non-developers and the safe default (lazy-fetch on
        // first chat with operator-visible progress) is already the
        // right answer for the "non-technical operator" cliff. Intermediate and
        // Advanced still see the prompt + the download recipe.
        if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!(
                "[5c/9] Qwen weights will download automatically on your first chat (~{} GB, progress shown).",
                qwen_weights::DEFAULT_QWEN_DOWNLOAD_GB,
            );
            state.steps_completed.push(step_markers::STEP_5C_QWEN_WEIGHTS);
            return Ok(());
        }
        println!(
            "[5c/9] LocalQwen is wired but the {} weights aren't cached yet (~{} GB download).",
            qwen_weights::DEFAULT_QWEN_MODEL_ID,
            qwen_weights::DEFAULT_QWEN_DOWNLOAD_GB,
        );
        let opt_in = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Pre-download the Qwen weights now? (skip = lazy-download on first chat)")
            .default(false)
            .interact()
            .context("qwen weights opt-in")?;
        if !opt_in {
            println!(
                "  Skipped — weights will lazy-download on first chat (operator-visible progress)."
            );
            state.steps_completed.push(step_markers::STEP_5C_QWEN_WEIGHTS);
            return Ok(());
        }
        state.download_qwen_weights = true;
        let cmd = qwen_weights::weights_download_command(qwen_weights::DEFAULT_QWEN_MODEL_ID);
        println!();
        println!("  To download the weights, run:");
        println!("      $ {}", cmd.join(" "));
        println!(
            "  (`huggingface-cli` ships with the `huggingface_hub` pip package; \
             `pip install -U huggingface_hub` if missing.)"
        );
    }

    state.steps_completed.push(step_markers::STEP_5C_QWEN_WEIGHTS);
    Ok(())
}

/// True when the configured inference topology touches LocalQwen
/// anywhere — default slot, a hemisphere override, or the embedding
/// provider. Sole call site is `step5c_qwen_weights`'s skip-check.
fn inference_uses_local_qwen(
    topology: &crate::config::inference::InferenceTopology,
    provider_kind: &Option<ProviderKind>,
) -> bool {
    use crate::config::inference::InferenceProvider;

    if matches!(provider_kind, Some(ProviderKind::LocalQwen)) {
        return true;
    }
    if matches!(
        topology.default_slot.provider,
        Some(InferenceProvider::LocalQwen)
    ) {
        return true;
    }
    if matches!(
        topology.embedding_provider,
        Some(InferenceProvider::LocalQwen)
    ) {
        return true;
    }
    let hemis = [&topology.cerebellum, &topology.left, &topology.right];
    hemis
        .iter()
        .any(|slot| matches!(slot.provider, Some(InferenceProvider::LocalQwen)))
}

/// ADV-03 item 4 Phase 7 (Session 24): operator-awareness step for
/// the profile-claim approval gate. The actual persistence happens
/// via serde default on `ProfileConfig::require_approval` (true on
/// fresh installs + missing-field migrations) AND via the
/// `neoth profile migrate-require-approval [--disable]` CLI — this
/// step exists so fresh-install operators KNOW the gate is on
/// before their first chat triggers a profile extraction.
///
/// Non-interactive: silent no-op (the marker still records the step
/// completed for the audit trail).
///
/// Interactive: print a 3-line summary + the disable command, then
/// continue. No prompt — operator can opt out later via
/// `neoth profile migrate-require-approval --disable` if they
/// genuinely want auto-apply.
fn step5d_profile_approval_gate(interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 5d: profile approval gate awareness");
    if interactive {
        println!();
        // NOOB-UX gate: Beginner gets a 1-line plain-English summary.
        // The 6-line technical version ("prompt-injection attacks",
        // "multi-turn slow-poison chains", "daemon mode no tty",
        // `neoth profile pending`) is jargon dense — Intermediate +
        // Advanced still see it so they know the disable command.
        if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!(
                "[5d/9] NEOTH will ask before saving facts about you (e.g. 'you live in Berlin')."
            );
        } else {
            println!("[5d/9] Profile-claim approval gate is ON by default.");
            println!(
                "  When NEOTH extracts a profile claim ('you live in Berlin', \
                 'your editor is vim'),"
            );
            println!(
                "  it asks you to confirm before writing — protects against \
                 prompt-injection attacks"
            );
            println!("  via channel inbound + multi-turn slow-poison chains.");
            println!(
                "  Daemon mode (no tty) parks pending claims in \
                 `neoth profile pending` for review."
            );
            println!("  Opt out anytime with: `neoth profile migrate-require-approval --disable`");
        }
    }
    state.steps_completed.push(step_markers::STEP_5D_PROFILE_GATE);
    Ok(())
}

async fn step6_channel(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 6: channel");

    // K-4b (Session 21): probe `pear` once so the prompt copy reflects
    // whether Keet is reachable as the preferred primary. The probe is
    // cheap (single subprocess spawn with 5s timeout) and only runs in
    // interactive mode where the prompt actually surfaces.
    let pear_present = if interactive {
        crate::installers::pears::check_pears().await.is_some()
    } else {
        false
    };

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
                    .with_prompt(k4b_telegram_prompt_text(pear_present))
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
        println!("  [6/9] Telegram skipped. Add later: `neoth channel add telegram`");
    }

    state.steps_completed.push(step_markers::STEP_6_CHANNEL);
    Ok(())
}

/// K-3.5 (Session 21, 2026-05-23) — interactive Keet pairing prompt.
///
/// Runs AFTER step6_channel (Telegram) so an operator who set both
/// Telegram + Keet has both configured. Skipped silently in non-
/// interactive mode + when `pear` is not on PATH (the operator-facing
/// install command surfaces so they know what to install if they want
/// the K-2b outbound path).
///
/// Flow:
///   1. Probe `pear --version` via `installers::pears::check_pears`.
///   2. If missing → print install command + skip the rest of the step
///      (don't bail — Telegram already covers the operator's channel).
///   3. Ask "Set up Keet pairing now?"  default No.
///   4. If yes → prompt for 24-word seed (Password input — pasted seed
///      shouldn't end up in scrollback).
///   5. Call `channels::keet_pairing::prepare_pairing(seed, port)`.
///      Validation failure → print error + offer to re-try; capped
///      at 3 attempts so an operator who pasted the wrong thing 3x
///      doesn't get stuck.
///   6. Render the pairing-anchor hex + freedom.yaml snippet + the
///      PAIRING_INSTRUCTIONS list. Bearer token value is NOT printed
///      (Debug-redacted in the module); it lands in credentials.yaml.
///   7. Stash seed + bearer in WizardState so `write_config` persists
///      both into credentials.yaml on the next step.
async fn step6b_keet_pairing(
    _args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    debug!("wizard step 6b: keet pairing");

    if !interactive {
        // CI / cloud-init operators configure Keet by editing
        // ~/.neoth/credentials.yaml directly + running `neoth serve`.
        // No prompt available, no flag yet — K-3.5 deferred non-
        // interactive surface.
        state.steps_completed.push(step_markers::STEP_6B_KEET_PAIRING); // 6b marker
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        let pear_present = crate::installers::pears::check_pears().await.is_some();
        if !pear_present {
            // Operator can still skip Keet entirely (Telegram is
            // already wired in step 6). Surface the install path so
            // they know how to come back to this.
            println!();
            println!("[6b/9] Keet pairing skipped — `pear` runtime not on PATH.");
            let path = crate::installers::pears::recommend_install_path(false);
            let cmd = crate::installers::pears::install_command(path);
            if !cmd.is_empty() {
                println!("       To enable Keet later, install Pears + re-run `neoth init`:");
                println!("       $ {}", cmd.join(" "));
            }
            state.steps_completed.push(step_markers::STEP_6B_KEET_PAIRING);
            return Ok(());
        }

        let set_up = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[6b/9] `pear` runtime detected. Pair Keet now? (optional)")
            .default(false)
            .interact()
            .context("keet pairing confirm")?;
        if !set_up {
            state.steps_completed.push(step_markers::STEP_6B_KEET_PAIRING);
            return Ok(());
        }

        const MAX_ATTEMPTS: usize = 3;
        for attempt in 1..=MAX_ATTEMPTS {
            let seed: String = dialoguer::Password::with_theme(
                &dialoguer::theme::ColorfulTheme::default(),
            )
            .with_prompt(
                "  Paste the 24-word Keet seed phrase your phone showed (single-spaced, lowercase)",
            )
            .interact()
            .context("keet seed input")?;

            match crate::channels::keet_pairing::prepare_pairing(
                &seed,
                crate::channels::pears_bridge::DEFAULT_BRIDGE_PORT,
            ) {
                Ok(info) => {
                    println!();
                    println!("  ✔ Pairing prepared.");
                    println!("    Anchor (compare with phone): {}", info.pairing_anchor);
                    println!();
                    println!("    Operator steps:");
                    for line in crate::channels::keet_pairing::PAIRING_INSTRUCTIONS {
                        println!("      {line}");
                    }
                    println!();
                    println!("    freedom.yaml snippet (auto-written; shown for reference):");
                    for line in info.freedom_yaml_snippet.lines() {
                        println!("      {line}");
                    }
                    state.keet_seed_phrase =
                        Some(crate::secret::SecretString::from(seed.trim().to_string()));
                    state.pears_bearer_token = Some(crate::secret::SecretString::from(
                        info.bearer_token.expose().to_string(),
                    ));
                    break;
                }
                Err(e) => {
                    println!("  ✗ {e}");
                    if attempt == MAX_ATTEMPTS {
                        println!(
                            "  Maximum attempts reached. Skipping Keet pairing — re-run `neoth init` later."
                        );
                        break;
                    }
                    println!(
                        "  Re-paste the phrase (attempt {}/{}).",
                        attempt + 1,
                        MAX_ATTEMPTS
                    );
                }
            }
        }
    }

    state.steps_completed.push(step_markers::STEP_6B_KEET_PAIRING);
    Ok(())
}

/// Step 6c — O-1 (Workstream B): Obsidian install.
///
/// Surfaces the OS-appropriate `winget` / `brew` / AppImage URL.
/// Never auto-spawns the installer — operators paste the command
/// (per "operator GO per command" rule). The wizard records the
/// opt-in so subsequent boots know whether to nudge the vault step.
async fn step6c_obsidian_install(
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
        state.steps_completed.push(step_markers::STEP_6C_OBSIDIAN);
        return Ok(());
    }

    if !interactive {
        if !args.install_obsidian {
            state.steps_completed.push(step_markers::STEP_6C_OBSIDIAN);
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
        state.steps_completed.push(step_markers::STEP_6C_OBSIDIAN);
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
            state.steps_completed.push(step_markers::STEP_6C_OBSIDIAN);
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

    state.steps_completed.push(step_markers::STEP_6C_OBSIDIAN);
    Ok(())
}

/// Step 6d — O-2 (Workstream B): NEOTH-Vault bootstrap.
///
/// When the operator opts in, the wizard creates the vault directory
/// + writes the curated `.obsidian/` config + templates from
/// `installers::obsidian_vault::bootstrap_files`. Idempotent — files
/// that already exist are left alone (operator's edits win).
fn step6d_obsidian_vault_bootstrap(
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
fn step6d_obsidian_vault_bootstrap_with_home(
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
            state.steps_completed.push(step_markers::STEP_6D_OBSIDIAN_VAULT);
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
        state.steps_completed.push(step_markers::STEP_6D_OBSIDIAN_VAULT);
        return Ok(());
    }

    let Some(path) = vault_path else {
        warn!("vault bootstrap requested but no default path resolvable (HOME unset); skipping");
        state.steps_completed.push(step_markers::STEP_6D_OBSIDIAN_VAULT);
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
    state.steps_completed.push(step_markers::STEP_6D_OBSIDIAN_VAULT);
    Ok(())
}

/// Step 6e — N-1 (Workstream B): n8n install opt-in.
///
/// Probes Docker + npm asynchronously, picks the recommended path
/// via `InstallStrategy::recommend`. The actual install command is
/// surfaced — never auto-spawned — so the operator runs it with full
/// visibility.
async fn step6e_n8n_install(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::installers::n8n;

    debug!("wizard step 6e: n8n install");

    if !interactive {
        if !args.install_n8n {
            state.steps_completed.push(step_markers::STEP_6E_N8N);
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
        state.steps_completed.push(step_markers::STEP_6E_N8N);
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
            state.steps_completed.push(step_markers::STEP_6E_N8N);
            return Ok(());
        }
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[6e/9] Install n8n (workflow engine, optional)?")
            .default(false)
            .interact()
            .context("n8n install confirm")?;
        if !want {
            state.steps_completed.push(step_markers::STEP_6E_N8N);
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

    state.steps_completed.push(step_markers::STEP_6E_N8N);
    Ok(())
}

/// Step 6f — E-16 (Workstream B): prior-AI memory import record.
///
/// The actual migration is the separate `neoth-migrate` binary; the
/// wizard records the operator's intent + surfaces the runbook so a
/// later `neoth-migrate apply --confirm` knows where to look. Never
/// auto-applies — importing prior memory is heavyweight + irreversible
/// once the WAL frames land.
fn step6f_import_memory(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
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
                state.steps_completed.push(step_markers::STEP_6F_IMPORT_MEMORY);
                return Ok(());
            }
            let raw: String =
                dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(
                        "  Path to your import-manifest.yaml (see the neoth-migrate examples)",
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
        state.steps_completed.push(step_markers::STEP_6F_IMPORT_MEMORY);
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
            println!("      $ neoth-migrate dry-run");
            println!("      $ neoth-migrate apply --confirm");
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

    state.steps_completed.push(step_markers::STEP_6F_IMPORT_MEMORY);
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
async fn step6g_credential_import(args: &InitArgs, interactive: bool, neoth_dir: &std::path::Path) {
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

    let ts_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
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
fn step6h_install_recommended(args: &InitArgs, interactive: bool, neoth_dir: &std::path::Path) {
    debug!("wizard step 6h: install-command preview (W-05)");
    if !interactive || args.non_interactive {
        debug!("skipping install-command preview in non-interactive mode");
        return;
    }
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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

/// Step 7 — operator picks an autonomy level (Phase 28b R-23).
///
/// Five choices map to `permissions::AutonomyLevel`. Each one-line
/// consequence preview describes the *first* surprise the operator would
/// hit at that level so the choice stays concrete.
///
/// Non-interactive: honours `--autonomy <level>`. Falls back to `Standard`
/// if absent — least-surprise default per spec.
fn step7_autonomy(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    use crate::permissions::AutonomyLevel;

    debug!("wizard step 7: autonomy");

    // Non-interactive path: --autonomy flag wins, otherwise default.
    if !interactive {
        let level = match args.autonomy.as_deref() {
            Some(s) => AutonomyLevel::from_str(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --autonomy '{s}'. Expected: strict | standard | elevated | full | custom"
                )
            })?,
            None => AutonomyLevel::Standard,
        };
        state.autonomy = level;
        state.steps_completed.push(step_markers::STEP_7_AUTONOMY);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        // NOOB-UX gate: Beginner silently takes `Standard` — the
        // 5-option matrix ("paid calls > €0.50", "policy.yaml
        // dangerous_targets", "fine-grained matrix") is dense
        // jargon and Standard is the safe default the panel
        // already recommends. Intermediate + Advanced see the
        // full picker.
        if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            state.autonomy = AutonomyLevel::Standard;
            println!(
                "  [7/9] autonomy: {} (safe default — change anytime in settings)",
                state.autonomy.as_str(),
            );
            state.steps_completed.push(step_markers::STEP_7_AUTONOMY);
            return Ok(());
        }
        let options = [
            (
                "strict",
                AutonomyLevel::Strict,
                "every write/exec/send asks before running",
            ),
            (
                "standard",
                AutonomyLevel::Standard,
                "writes inside ~/.neoth/ allowed; shell exec confirms; paid calls > €0.50 confirm",
            ),
            (
                "elevated",
                AutonomyLevel::Elevated,
                "writes everywhere allowed; shell inside ~/.neoth/scripts/ runs; paid calls > €5 confirm",
            ),
            (
                "full",
                AutonomyLevel::Full,
                "FULL-AUTO gate: runs shell / sends / writes without asking (dangerous targets still prompt)",
            ),
            (
                "custom",
                AutonomyLevel::Custom,
                "fine-grained matrix (today behaves like standard until override file lands)",
            ),
        ];
        let labels: Vec<String> = options
            .iter()
            .map(|(name, _, hint)| format!("{name:<8}  {hint}"))
            .collect();

        let default_idx = options
            .iter()
            .position(|(_, l, _)| *l == AutonomyLevel::Standard)
            .unwrap_or(1);
        let choice = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[7/9] How autonomous should NEOTH be?")
            .items(&labels)
            .default(default_idx)
            .interact()
            .context("autonomy select")?;

        let picked = options[choice].1;
        if picked == AutonomyLevel::Full {
            // Spec calls for a hardware-2FA prompt the first time `full` is
            // enabled. Phase 28b ships a confirm step; the real 2FA hook
            // lands when `policy.yaml::dangerous_targets` is wired (Phase 33c).
            let confirmed =
                dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(
                        "  ⚠  `full` lets NEOTH run shell commands without asking. Continue?",
                    )
                    .default(false)
                    .interact()
                    .context("full-level confirm")?;
            if !confirmed {
                println!("  [7/9] Falling back to `standard`.");
                state.autonomy = AutonomyLevel::Standard;
            } else {
                state.autonomy = AutonomyLevel::Full;
                // The `full` level is the GATE half of full-auto. To ALSO route
                // the entire bundled skill library proactively (the other half),
                // point the operator at the one-word headline switch — it sets
                // skills.enable_all_bundled, which the wizard's flat picker does
                // not. Honest pointer, no silent skill-library expansion here.
                println!(
                    "  [7/9] Tip: run `neoth sudomode` (or `neoth autonomy full-auto`) to also"
                );
                println!(
                    "        route the WHOLE skill library proactively — that's the full-auto mode."
                );
            }
        } else {
            state.autonomy = picked;
        }
        println!("  [7/9] autonomy: {}", state.autonomy.as_str());
    }
    #[cfg(not(feature = "wizard"))]
    {
        state.autonomy = AutonomyLevel::Standard;
    }

    state.steps_completed.push(step_markers::STEP_7_AUTONOMY);
    Ok(())
}

/// V03-09 Phase 2a wizard step. Two questions, both default to
/// the conservative answer so a hammered-Enter operator leaves
/// the daemon in the safest mode (no background HTTP traffic to
/// GitHub, no auto-apply).
///
/// Non-interactive runs leave the default `AutoUpdateConfig`
/// (enabled=false, auto_apply=false). Operators in CI / cold-
/// start scripts who want different values edit freedom.yaml
/// directly OR add `--auto-update` / `--auto-update-apply`
/// flags later (not yet wired — would land alongside other
/// non-interactive wizard knobs).
fn step7b_auto_update(_args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 7b: auto-update");

    if !interactive {
        // Default = enabled:false, auto_apply:false. Already set
        // by WizardState::default(); just record the step.
        state.steps_completed.push(step_markers::STEP_7B_AUTO_UPDATE); // 7-and-a-half style marker
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        let check = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(
                "[7b/9] Allow NEOTH to check GitHub for newer releases? (no background traffic until you say yes)",
            )
            .default(false)
            .interact()
            .context("auto-update check confirm")?;

        if check {
            state.auto_update.enabled = true;
            let apply = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(
                    "  Also auto-apply updates (download + replace the daemon binary)? Recommend NO — most operators want check-only nag.",
                )
                .default(false)
                .interact()
                .context("auto-update apply confirm")?;
            state.auto_update.auto_apply = apply;
            println!(
                "  [7b/9] auto_update: enabled={} auto_apply={} channel={}",
                state.auto_update.enabled, state.auto_update.auto_apply, state.auto_update.channel,
            );
        } else {
            // Explicit "no" — make sure both flags are false even
            // if a prior wizard run had flipped them on.
            state.auto_update.enabled = false;
            state.auto_update.auto_apply = false;
            println!("  [7b/9] auto_update: disabled");
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        // Slim build: leave defaults.
    }

    state.steps_completed.push(step_markers::STEP_7B_AUTO_UPDATE);
    Ok(())
}

/// D-102 wizard step 7c (Session 21, 2026-05-23) — bulk-enable
/// multiselect for discovered WASM plugins.
///
/// Per the 6/6 senior-dev panel verdict on D-102 (default-inactive),
/// the daemon NEVER auto-instantiates a discovered `.wasm` plugin.
/// This step is where the operator picks which ones to opt into during
/// onboarding — the alternative is running `neoth plugin enable <id>`
/// once per plugin after first boot, which is the friction the agent
/// panel called out as the noob-UX gap.
///
/// Behaviour:
///   - Scans `<neoth_dir>/plugins/` via `wasm_plugin::discovery::discover`.
///   - Zero discovered → silent no-op (the common first-run state).
///   - Non-interactive → leaves activations empty (every plugin stays
///     Pending; operator must enable via `neoth plugin enable <id>`
///     after install).
///   - Interactive → MultiSelect with one row per discovered plugin.
///     Picked → `Active`; unpicked → `Disabled` (NOT `Pending`, because
///     the operator HAS reviewed it during the wizard).
///
/// Activations land on `state.plugins.wasm.activations`; `write_config`
/// serialises the whole `plugins:` block into freedom.yaml so the next
/// daemon boot's `bootstrap_plugin_invoker` reads the operator's
/// decisions directly.
fn step7c_wasm_plugin_activation(
    args: &InitArgs,
    interactive: bool,
    neoth_dir: &std::path::Path,
    state: &mut WizardState,
) -> Result<()> {
    debug!("wizard step 7c: wasm plugin activation");

    let plugins_root = neoth_dir.join("plugins");
    let report = crate::wasm_plugin::discovery::discover(&plugins_root);
    if report.loaded.is_empty() {
        // Common first-run case: no plugins discovered. Skip silently
        // so the wizard transcript stays tight. Operator passing
        // --enable-plugin without any plugins on disk gets a warn
        // so the typo'd id is at least surfaced.
        if !args.enable_plugin.is_empty() {
            warn!(
                ids = ?args.enable_plugin,
                "--enable-plugin given but no plugins discovered under {}",
                plugins_root.display()
            );
        }
        state.steps_completed.push(step_markers::STEP_7C_WASM_PLUGINS); // 7c marker (7-and-three-quarters)
        return Ok(());
    }

    if !interactive {
        // Non-interactive runs honour --enable-plugin <id> (repeatable).
        // Unknown ids surface a warn so CI operators see the typo but
        // the wizard doesn't bail — partial activation is better than
        // a failed init.
        let known: std::collections::HashSet<&str> = report
            .loaded
            .iter()
            .map(|p| p.manifest.id.as_str())
            .collect();
        let mut activated: Vec<String> = Vec::new();
        let disabled: Vec<String> = Vec::new();
        for id in &args.enable_plugin {
            if known.contains(id.as_str()) {
                state.plugins.wasm.activations.insert(
                    id.clone(),
                    crate::wasm_plugin::discovery::PluginActivation::Active,
                );
                activated.push(id.clone());
            } else {
                let discovered: Vec<&str> = known.iter().copied().collect();
                warn!(
                    id = %id,
                    discovered = ?discovered,
                    "--enable-plugin id not found among discovered plugins; ignored"
                );
            }
        }
        // Any plugin not explicitly enabled stays PENDING (no entry =
        // default). We do NOT auto-Disabled them — that matches the
        // operator's mental model: `--enable-plugin X` is positive,
        // silence is "decide later" not "actively refused".
        let ids: Vec<&str> = report
            .loaded
            .iter()
            .map(|p| p.manifest.id.as_str())
            .collect();
        info!(
            count = report.loaded.len(),
            ids = ?ids,
            activated = ?activated,
            disabled = ?disabled,
            "wasm plugins discovered; non-interactive activation applied"
        );
        state.steps_completed.push(step_markers::STEP_7C_WASM_PLUGINS);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        println!();
        println!(
            "[7c/9] {} WASM plugin(s) discovered under ~/.neoth/plugins/.",
            report.loaded.len()
        );
        println!("       Default is PENDING (skipped at daemon boot until you opt in).");
        println!("       Pick the ones you want active. Unpicked = Disabled.");

        let labels: Vec<String> = report
            .loaded
            .iter()
            .map(|p| format!("{}  ({})", p.manifest.id, p.manifest.name,))
            .collect();

        let picked =
            dialoguer::MultiSelect::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("[7c/9] Activate plugins (space to toggle, Enter to confirm)")
                .items(&labels)
                .interact()
                .context("wasm plugin multiselect")?;

        let picked_set: std::collections::HashSet<usize> = picked.into_iter().collect();
        let mut active_count = 0usize;
        let mut disabled_count = 0usize;
        for (idx, plugin) in report.loaded.iter().enumerate() {
            let state_val = if picked_set.contains(&idx) {
                active_count += 1;
                crate::wasm_plugin::discovery::PluginActivation::Active
            } else {
                disabled_count += 1;
                crate::wasm_plugin::discovery::PluginActivation::Disabled
            };
            state
                .plugins
                .wasm
                .activations
                .insert(plugin.manifest.id.clone(), state_val);
        }
        println!(
            "  [7c/9] {} plugin(s) Active, {} Disabled.",
            active_count, disabled_count,
        );
    }
    #[cfg(not(feature = "wizard"))]
    {
        // Slim build (no dialoguer): default Pending for every
        // discovered id — same as non-interactive.
    }

    state.steps_completed.push(step_markers::STEP_7C_WASM_PLUGINS);
    Ok(())
}

/// MV-01b prereq #3 wizard step 7d (Session 28c) — offer to install the
/// OS-native process supervisor so NEOTH keeps running + auto-restarts
/// (the prerequisite for self-update to actually activate a new binary
/// + for the daemon to survive logout/crash).
///
/// Off by default (opt-in): a background auto-restart service is a real
/// system change, so the operator says yes explicitly. Non-interactive
/// runs skip it. The install is user-scoped (no root/admin) + best-effort
/// — a failure warns + leaves `supervisor.enabled = false` rather than
/// aborting onboarding.
fn step7d_supervisor(_args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 7d: supervisor");

    if !interactive {
        // Default = disabled (WizardState::default). Just record the step.
        state.steps_completed.push(step_markers::STEP_7D_SUPERVISOR);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        let kind = crate::daemon::supervisor::recommended_kind();
        if matches!(kind, crate::config::SupervisorKind::None) {
            println!("  [7d/9] supervisor: no supported supervisor for this OS — skipping");
            state.steps_completed.push(step_markers::STEP_7D_SUPERVISOR);
            return Ok(());
        }
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(format!(
                "[7d/9] Keep NEOTH running in the background + auto-restart it ({})? \
                 Needed for auto-update to take effect; survives logout/crash. No root required.",
                kind.as_str()
            ))
            .default(false)
            .interact()
            .context("supervisor install confirm")?;
        if want {
            match install_supervisor_now() {
                Ok(installed) => {
                    state.supervisor.enabled = true;
                    state.supervisor.kind = installed;
                    println!("  [7d/9] supervisor installed: {}", installed.as_str());
                }
                Err(e) => {
                    warn!(error = %e, "supervisor install failed; leaving it disabled");
                    state.supervisor.enabled = false;
                    println!(
                        "  [7d/9] supervisor install failed ({e}); NEOTH will run only while \
                         `neoth serve` is open. You can retry later with `neoth supervisor install`."
                    );
                }
            }
        } else {
            state.supervisor.enabled = false;
            println!(
                "  [7d/9] supervisor: skipped. Run NEOTH with `neoth serve`; auto-update will \
                 stage updates but you'll restart manually to finish them."
            );
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        // Slim build: leave defaults (disabled).
    }

    state.steps_completed.push(step_markers::STEP_7D_SUPERVISOR);
    Ok(())
}

/// Resolve the current exe + config/home dirs and run the OS supervisor
/// install. Split out so the dialoguer branch stays readable + so the
/// path resolution is shared with a future `neoth supervisor` re-run.
#[cfg(feature = "wizard")]
fn install_supervisor_now() -> Result<crate::config::SupervisorKind> {
    let exe = std::env::current_exe().context("locate current executable")?;
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    crate::daemon::supervisor::install(&exe, &config_home, &home)
}

/// V03-08 — offer to grant cloud-egress consent inline at wizard end so
/// the operator's first `neoth chat` doesn't hit a cold consent-failure.
/// Returns `true` when consent was granted in-process (caller then skips
/// the printed pre-grant hint). Interactive-TTY + `wizard`-feature only;
/// every other path returns `false` (caller prints the hint).
#[cfg(feature = "wizard")]
fn try_inline_consent_grant(
    args: &InitArgs,
    provider_kind: Option<ProviderKind>,
    provider_display: &str,
) -> bool {
    use std::io::IsTerminal;
    let interactive = !args.non_interactive && std::io::stdin().is_terminal();
    if !interactive {
        return false;
    }
    let Some(pk) = provider_kind else {
        return false;
    };
    let grant_now = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(format!(
            "Grant cloud-egress consent for `{provider_display}` now? \
             (so your first `neoth chat` just works)"
        ))
        .default(true)
        .interact()
        .unwrap_or(false);
    if !grant_now {
        return false;
    }
    let home = crate::config::FreedomConfig::default_neoth_home();
    match crate::consent::grant(&home, pk) {
        Ok(()) => {
            println!("  ✓ cloud-egress consent granted for `{provider_display}`");
            true
        }
        Err(e) => {
            println!(
                "  ! consent grant failed: {e} — run \
                 `neoth consent grant {provider_display}` before chatting"
            );
            false
        }
    }
}

#[cfg(not(feature = "wizard"))]
fn try_inline_consent_grant(
    _args: &InitArgs,
    _provider_kind: Option<ProviderKind>,
    _provider_display: &str,
) -> bool {
    false
}

// ── Atomic, mode-0600 file write helpers ──────────────────────────────────────
//
// SECURITY P0 (from Security Engineer review, OPEN_DECISIONS.md D-003):
// freedom.yaml and .initialized MUST be created with mode 0600 on `OpenOptions`
// BEFORE `open()` — never chmod-after-create (TOCTOU race). Pattern below uses
// `create_new(true)` + `.mode(0o600)` for unix; Windows inherits parent DACL
// (see wal/writer.rs::open_segment for the parallel Windows TODO).

// ── Validation helpers ────────────────────────────────────────────────────────

// ── OS utilities ──────────────────────────────────────────────────────────────

// `probe_local_bridge_sync` moved to `providers::local_probe` so the
// telemetry-guard lint (Phase 33c BS-6) keeps the daemon's `cli/` tree
// clean of any HTTP-client construction. Loopback-only probes still
// belong in `providers/` architecturally — the wizard is just one caller.
use crate::providers::local_probe::probe_local_bridge_sync;

/// Offer to install the three CLIs that are missing on PATH. Dispatches
/// on each CLI's [`InstallStrategy`] — npm-strategy CLIs need npm
/// reachable, shell-script-strategy CLIs (Antigravity) only need
/// `sh`/PowerShell which we can rely on. Updates the passed-in path
/// Options in place so the wizard can re-probe after install. Quiet
/// no-op when all three are already present.
#[cfg(feature = "wizard")]
async fn offer_cli_installs(
    claude: &mut Option<String>,
    codex: &mut Option<String>,
    antigravity: &mut Option<String>,
) -> Result<()> {
    use crate::installers::{
        ALL, ANTIGRAVITY as INST_ANTIGRAVITY, CLAUDE as INST_CLAUDE, CODEX as INST_CODEX, CliKind,
        InstallStrategy,
    };

    // npm probe is per-strategy now — only required when at least one
    // missing CLI ships via npm.
    let npm_v = crate::installers::npm_version().await;
    let needs_npm = ALL.iter().any(|k| {
        matches!(k.install, InstallStrategy::Npm { .. })
            && match k.binary {
                "claude" => claude.is_none(),
                "codex" => codex.is_none(),
                _ => false,
            }
    });
    if needs_npm && npm_v.is_none() {
        println!();
        println!("  ! npm not found on PATH. To auto-install npm-managed CLIs, install Node.js:");
        println!("    https://nodejs.org/  (the LTS installer ships npm)");
        println!("  Shell-script CLIs (Antigravity) can still install — continuing.");
    } else if let Some(v) = npm_v.as_ref() {
        println!("\n  npm {v} detected — auto-install available for npm-managed CLIs.");
    }

    for kind in ALL {
        let current = match kind.binary {
            "claude" => claude.clone(),
            "codex" => codex.clone(),
            "agy" => antigravity.clone(),
            _ => None,
        };
        if current.is_some() {
            continue;
        }
        // Skip npm-strategy CLIs when npm is missing — the message
        // above already told the operator how to recover.
        if matches!(kind.install, InstallStrategy::Npm { .. }) && npm_v.is_none() {
            continue;
        }
        let source_hint = match kind.install {
            InstallStrategy::Npm { package } => format!("npm: {package}"),
            InstallStrategy::ShellScript { unix_url, .. } => format!("shell: {unix_url}"),
        };
        let install_it =
            dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(format!("Install {} ({source_hint})?", kind.display))
                .default(true)
                .interact()
                .context("install confirm prompt")?;
        if !install_it {
            continue;
        }
        if let Err(e) = crate::installers::install_kind(*kind).await {
            println!("  ✗ install of {} failed: {e}", kind.display);
            continue;
        }
        // Re-probe and trigger login if the binary now appears on PATH.
        let resolved = which_binary(kind.binary);
        if resolved.is_some() {
            println!("  ✓ {} installed", kind.display);
            // Update the caller's path slot for the picker downstream.
            match kind.binary {
                "claude" => *claude = resolved.clone(),
                "codex" => *codex = resolved.clone(),
                "agy" => *antigravity = resolved.clone(),
                _ => {}
            }
            let login_it =
                dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(format!(
                        "Run `{} {}` for OAuth login now?",
                        kind.binary,
                        kind.login_args.unwrap_or(&[]).join(" ")
                    ))
                    .default(true)
                    .interact()
                    .context("login confirm prompt")?;
            if login_it {
                if let Err(e) = crate::installers::login_kind(*kind).await {
                    println!(
                        "  ! {} login error: {e} (you can re-run later)",
                        kind.display
                    );
                }
            }
        } else {
            let hint = match kind.install {
                InstallStrategy::Npm { .. } => npm_path_hint(kind.binary),
                InstallStrategy::ShellScript { .. } => {
                    "Open a new shell or check the installer's reported install path.".to_string()
                }
            };
            println!(
                "  ! {} installed but `{}` is still not on PATH. {hint}",
                kind.display, kind.binary
            );
        }
        // Silence unused-import on cfg with no other use of these.
        let _ = (INST_CLAUDE, INST_CODEX, INST_ANTIGRAVITY);
        let _: CliKind = *kind;
    }
    Ok(())
}

/// No-op fallback when the `wizard` feature is off. Wizard-less builds skip
/// interactive install offers entirely.
#[cfg(not(feature = "wizard"))]
async fn offer_cli_installs(
    _claude: &mut Option<String>,
    _codex: &mut Option<String>,
    _antigravity: &mut Option<String>,
) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SC-09 step 3b: HMAC key backup prompt ─────────────────────────

    #[test]
    fn step3b_non_interactive_is_a_noop() {
        // Non-interactive runs must NOT prompt, NOT back up, and NOT create a
        // key — the operator can run `neoth security backup-hmac-key` later.
        let dir = tempfile::tempdir().unwrap();
        let mut state = WizardState::default();
        step3b_hmac_backup(false, dir.path(), &mut state).expect("noop ok");
        assert!(!state.hmac_backup_offered, "non-interactive must not offer");
        assert!(
            !dir.path().join("wal").join("hmac_backup.bin").exists(),
            "non-interactive must write no backup"
        );
        assert!(
            !dir.path().join("wal").join("hmac.key").exists(),
            "non-interactive must not create a key"
        );
    }

    #[test]
    fn hmac_backup_offered_defaults_false_and_round_trips() {
        let s = WizardState::default();
        assert!(!s.hmac_backup_offered);
        // Round-trips, and a checkpoint written BEFORE this field existed (the
        // key absent from an otherwise-complete JSON) still loads — proving the
        // `#[serde(default)]` on the new field keeps old checkpoints valid.
        let mut v: serde_json::Value = serde_json::to_value(&s).unwrap();
        v.as_object_mut().unwrap().remove("hmac_backup_offered");
        let legacy: WizardState = serde_json::from_value(v).unwrap();
        assert!(!legacy.hmac_backup_offered);
    }

    // ── R-04 (Session 24) wizard resume gate ──────────────────────────

    #[test]
    fn maybe_resume_no_checkpoint_leaves_state_default() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = WizardState::default();
        maybe_resume_from_checkpoint(dir.path(), false, &mut state).expect("noop ok");
        assert!(state.operator_id.is_none());
        assert!(state.steps_completed.is_empty());
    }

    #[test]
    fn maybe_resume_non_interactive_auto_hydrates_from_checkpoint() {
        // CI / pipe path: auto-resume without prompting. The checkpoint
        // payload is the source of truth for non-secret fields.
        let dir = tempfile::tempdir().unwrap();
        let mut saved = WizardState::default();
        saved.operator_id = Some("sam".into());
        saved.language_code = Some("de".into());
        saved.steps_completed = vec![1, 2, 3, 4];
        saved.bootstrap_vault = true;
        crate::cli::wizard_checkpoint::save_checkpoint(dir.path(), &saved).expect("save");

        let mut state = WizardState::default();
        maybe_resume_from_checkpoint(dir.path(), false, &mut state).expect("auto-resume");
        assert_eq!(state.operator_id.as_deref(), Some("sam"));
        assert_eq!(state.language_code.as_deref(), Some("de"));
        assert_eq!(state.steps_completed, vec![1, 2, 3, 4]);
        assert!(state.bootstrap_vault);
        // Checkpoint file must still exist after auto-resume — it gets
        // cleared at the very end of run_init or by an operator decline.
        assert!(
            crate::cli::wizard_checkpoint::checkpoint_path(dir.path()).exists(),
            "non-interactive auto-resume keeps the file in place for the next save",
        );
    }

    #[test]
    fn maybe_resume_with_corrupt_file_clears_it_and_proceeds() {
        // Garbage JSON in the checkpoint must NOT brick the wizard.
        // Operator sees a fresh wizard + the bad file goes away.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(
            crate::cli::wizard_checkpoint::checkpoint_path(dir.path()),
            b"<<<not real json>>>",
        )
        .unwrap();

        let mut state = WizardState::default();
        maybe_resume_from_checkpoint(dir.path(), false, &mut state).expect("survives corruption");
        assert!(state.operator_id.is_none());
        assert!(
            !crate::cli::wizard_checkpoint::checkpoint_path(dir.path()).exists(),
            "corrupt checkpoint must be cleared",
        );
    }

    #[test]
    fn format_checkpoint_age_handles_zero_and_negative() {
        // Defensive: an operator who hand-edits the file to ts=0 or
        // pre-epoch shouldn't crash the resume prompt.
        assert_eq!(format_checkpoint_age(0), "timestamp unavailable");
        assert_eq!(format_checkpoint_age(-1), "timestamp unavailable");
    }

    // ── R-05 (Session 24) auto-start + first-tour marker ─────────────

    #[test]
    fn write_first_tour_marker_creates_file_with_canonical_body() {
        let dir = tempfile::tempdir().unwrap();
        super::write_first_tour_marker(dir.path()).expect("write marker");
        let path = dir.path().join(super::FIRST_TOUR_MARKER);
        assert!(path.exists(), "marker file must exist after write");
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body, super::FIRST_TOUR_MESSAGE);
    }

    #[test]
    fn consume_first_tour_marker_returns_some_then_none() {
        let dir = tempfile::tempdir().unwrap();
        super::write_first_tour_marker(dir.path()).expect("write");
        let first = super::consume_first_tour_marker(dir.path());
        assert!(first.is_some());
        assert_eq!(first.as_deref(), Some(super::FIRST_TOUR_MESSAGE));

        // Second call: marker consumed → None.
        let second = super::consume_first_tour_marker(dir.path());
        assert!(
            second.is_none(),
            "marker is single-use; second consume must return None",
        );
        assert!(
            !dir.path().join(super::FIRST_TOUR_MARKER).exists(),
            "consume must delete the file",
        );
    }

    #[test]
    fn consume_first_tour_marker_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let out = super::consume_first_tour_marker(dir.path());
        assert!(
            out.is_none(),
            "fresh-install state (no wizard ran yet) → None, not Err",
        );
    }

    #[test]
    fn write_first_tour_marker_is_idempotent_on_rewrite() {
        // Operator re-runs `neoth init --force` → second write must
        // succeed + leave the file at the canonical message. Catches
        // a future regression that switches to "fail if exists" mode.
        let dir = tempfile::tempdir().unwrap();
        super::write_first_tour_marker(dir.path()).expect("first");
        // Tamper with the file as if a partial write happened.
        std::fs::write(dir.path().join(super::FIRST_TOUR_MARKER), b"stale-content").unwrap();
        super::write_first_tour_marker(dir.path()).expect("second");
        let body = std::fs::read_to_string(dir.path().join(super::FIRST_TOUR_MARKER)).unwrap();
        assert_eq!(body, super::FIRST_TOUR_MESSAGE);
    }

    #[test]
    fn first_tour_message_is_actionable_one_liner() {
        // Drift guard: the greeting must mention a runnable command so
        // a first-time operator has a clear next step. If a future
        // refactor reduces it to "Hello." this fails.
        assert!(
            super::FIRST_TOUR_MESSAGE.contains("neoth chat")
                || super::FIRST_TOUR_MESSAGE.contains("neoth recall"),
            "greeting must reference a runnable command: {}",
            super::FIRST_TOUR_MESSAGE,
        );
    }

    #[test]
    fn format_checkpoint_age_picks_human_units() {
        // The exact phrasing isn't a contract, but the unit boundary
        // selection is — a 2-hour-old checkpoint should not say
        // "7200 seconds ago" to an operator.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(format_checkpoint_age(now - 30).contains("minute"));
        assert!(format_checkpoint_age(now - 600).contains("minutes ago"));
        assert!(format_checkpoint_age(now - 7_200).contains("hours ago"));
        assert!(format_checkpoint_age(now - 172_800).contains("days ago"));
    }

    /// Process-level lock for tests that mutate the global `HOME` /
    /// `USERPROFILE` env vars. `std::env::set_var` is process-global,
    /// so two parallel tests in this lib that both set HOME race —
    /// one sees the other's tempdir and asserts wrong, surfacing as
    /// the intermittent failure of e.g. step6d_non_interactive_*.
    /// Every test that calls `set_var("HOME"/"USERPROFILE", ...)`
    /// MUST take this lock at function entry; release on drop
    /// happens after the restore-prev block.
    /// Delegates to the CRATE-WIDE env lock (crate::test_env) so init's
    /// HOME/USERPROFILE tests serialise against EVERY env test in the
    /// crate, not just each other. (Was a file-local HOME_ENV_LOCK,
    /// which only serialised within init.rs → a split-mechanism race
    /// vs pidfile/mode/code_map; the SC-11-era sweep unified it.)
    fn lock_home_env() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env::lock()
    }

    #[test]
    fn operator_id_valid() {
        assert!(validate_operator_id("sam").is_ok());
        assert!(validate_operator_id("my-dev_1").is_ok());
    }

    #[test]
    fn operator_id_reserved() {
        assert!(validate_operator_id("root").is_err());
        assert!(validate_operator_id("neoth").is_err());
    }

    #[test]
    fn operator_id_length() {
        assert!(validate_operator_id("a").is_err());
        assert!(validate_operator_id(&"a".repeat(33)).is_err());
    }

    #[test]
    fn operator_id_charset() {
        assert!(validate_operator_id("has space").is_err());
        assert!(validate_operator_id("has@sym").is_err());
    }

    /// NOOB-UX-4 drift guard — every interactive wizard prompt
    /// (`dialoguer::Confirm/Select/Input`) MUST have an operator-
    /// readable `(recommended)` / `recommended` marker explaining
    /// the default choice. The full editorial pass needs real
    /// fresh-OS install testing, but this test pins the coverage
    /// ratio so a future refactor that drops a marker surfaces.
    /// Failure mode: a wizard prompt without a `(recommended)`
    /// tag forces a non-developer operator to guess.
    #[test]
    fn noob_ux_4_wizard_prompts_keep_recommended_markers() {
        let src = include_str!("init.rs");
        let prompt_count = src.matches("dialoguer::Confirm").count()
            + src.matches("dialoguer::Select").count()
            + src.matches("dialoguer::Input").count();
        let recommended_count = src.matches("recommended").count();
        assert!(
            prompt_count >= 1,
            "wizard prompt count went to zero — surface check"
        );
        assert!(
            recommended_count >= prompt_count,
            "NOOB-UX-4 drift: {} wizard prompts, {} 'recommended' markers — \
             every interactive prompt needs at least one recommended-default \
             hint for non-developer operators",
            prompt_count,
            recommended_count
        );
    }

    #[test]
    fn recommended_provider_matches_spec_table() {
        use crate::config::inference::InferenceProvider as I;
        // SPEC_hemisphere_provider_selection.md §2 table — pinned so a
        // future refactor of the recommendation logic doesn't silently
        // drift away from the documented operator-facing defaults.
        assert_eq!(recommended_provider_for_role("left"), I::ClaudeCli);
        assert_eq!(recommended_provider_for_role("right"), I::Gemini);
        assert_eq!(recommended_provider_for_role("cerebellum"), I::LocalQwen);
    }

    #[test]
    fn recommended_local_provider_puts_ouro_on_analytic_left() {
        // GOLD-ADOPT-12: the local mirror — Ouro (reasoning LoopLM) takes the
        // analytic LEFT slot just as ClaudeCli does in the cloud default;
        // right + cerebellum stay on local Qwen.
        use crate::config::inference::InferenceProvider as I;
        assert_eq!(recommended_local_provider_for_role("left"), I::LocalOuro);
        assert_eq!(recommended_local_provider_for_role("right"), I::LocalQwen);
        assert_eq!(recommended_local_provider_for_role("cerebellum"), I::LocalQwen);
        assert_eq!(recommended_local_provider_for_role("hippocampus"), I::LocalQwen);
    }

    // ── Finding 6 (Session 13) wizard local-only preset ─────────────

    #[test]
    fn apply_local_only_preset_binds_every_slot_to_local_qwen() {
        use crate::config::inference::{InferenceProvider, InferenceTopology, TopologyMode};
        let mut topo = InferenceTopology::default();
        apply_local_only_preset(&mut topo);
        assert_eq!(topo.mode, TopologyMode::Triplet);
        assert_eq!(
            topo.default_slot.provider,
            Some(InferenceProvider::LocalQwen)
        );
        assert_eq!(topo.left.provider, Some(InferenceProvider::LocalQwen));
        assert_eq!(topo.right.provider, Some(InferenceProvider::LocalQwen));
        assert_eq!(topo.cerebellum.provider, Some(InferenceProvider::LocalQwen));
    }

    #[test]
    fn apply_local_only_preset_clears_keys_and_endpoints() {
        // Pre-fill the topology with cloud secrets, then assert the preset
        // wipes them — local-only must not retain stale cloud credentials
        // that confuse later wizard reconfigure passes.
        use crate::config::inference::{HemisphereSlot, InferenceProvider, InferenceTopology};
        let dirty = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            model: Some("gpt-4o".into()),
            key: Some(crate::secret::SecretString::from("sk-test")),
            endpoint: Some("https://api.openai.com/v1".into()),
            region: None,
            api_version: None,
            voice: None,
        };
        let mut topo = InferenceTopology {
            left: dirty.clone(),
            right: dirty.clone(),
            cerebellum: dirty.clone(),
            default_slot: dirty,
            ..InferenceTopology::default()
        };
        apply_local_only_preset(&mut topo);
        for slot in [
            &topo.left,
            &topo.right,
            &topo.cerebellum,
            &topo.default_slot,
        ] {
            assert_eq!(slot.provider, Some(InferenceProvider::LocalQwen));
            assert!(slot.model.is_none(), "model should be cleared");
            assert!(slot.key.is_none(), "key should be cleared");
            assert!(slot.endpoint.is_none(), "endpoint should be cleared");
        }
    }

    #[test]
    fn apply_local_abliterated_preset_all_local_is_triplet_ollama() {
        use crate::config::inference::{InferenceProvider, InferenceTopology, TopologyMode};
        use crate::installers::ollama::DEFAULT_OLLAMA_PORT;
        use crate::models::gguf_variants::VariantClass;
        use crate::models::hemisphere_preset::build_local_preset;
        // 24 GiB → 3 local abliterated hemispheres.
        let preset = build_local_preset(
            Some(24 * 1024),
            3,
            VariantClass::Abliterated,
            DEFAULT_OLLAMA_PORT,
        );
        let mut topo = InferenceTopology::default();
        apply_local_abliterated_preset(&mut topo, &preset);
        assert_eq!(topo.mode, TopologyMode::Triplet);
        for slot in [&topo.left, &topo.right, &topo.cerebellum, &topo.default_slot] {
            assert_eq!(slot.provider, Some(InferenceProvider::OpenAiCompat));
            assert_eq!(slot.endpoint.as_deref(), Some("http://127.0.0.1:11434/v1"));
            assert!(slot.key.is_none(), "Ollama needs no API key");
            let m = slot.model.as_deref().unwrap_or("");
            assert!(m.starts_with("hf.co/mradermacher/"), "got {m}");
            assert!(m.contains("abliterated-GGUF"));
        }
    }

    #[test]
    fn apply_local_abliterated_preset_mixed_is_custom_keeps_cloud() {
        use crate::config::inference::{
            HemisphereSlot, InferenceProvider, InferenceTopology, TopologyMode,
        };
        use crate::installers::ollama::DEFAULT_OLLAMA_PORT;
        use crate::models::gguf_variants::VariantClass;
        use crate::models::hemisphere_preset::build_local_preset;
        // Pre-seed cloud slots; a 1-local preset must leave right+cerebellum cloud.
        let cloud = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            model: Some("gemini-3.1-pro-preview".into()),
            key: Some(crate::secret::SecretString::from("k")),
            endpoint: None,
            region: None,
            api_version: None,
            voice: None,
        };
        let mut topo = InferenceTopology {
            left: cloud.clone(),
            right: cloud.clone(),
            cerebellum: cloud.clone(),
            default_slot: cloud,
            ..InferenceTopology::default()
        };
        let preset = build_local_preset(
            Some(24 * 1024),
            1,
            VariantClass::Abliterated,
            DEFAULT_OLLAMA_PORT,
        );
        apply_local_abliterated_preset(&mut topo, &preset);
        assert_eq!(topo.mode, TopologyMode::Custom);
        // Left went local…
        assert_eq!(topo.left.provider, Some(InferenceProvider::OpenAiCompat));
        // …right + cerebellum + default stayed cloud (Gemini).
        assert_eq!(topo.right.provider, Some(InferenceProvider::Gemini));
        assert_eq!(topo.cerebellum.provider, Some(InferenceProvider::Gemini));
        assert_eq!(topo.default_slot.provider, Some(InferenceProvider::Gemini));
    }

    #[test]
    fn collect_ollama_model_refs_dedups_local_hemispheres() {
        use crate::config::inference::{InferenceProvider, InferenceTopology, TopologyMode};
        use crate::installers::ollama::DEFAULT_OLLAMA_PORT;
        use crate::models::gguf_variants::VariantClass;
        use crate::models::hemisphere_preset::build_local_preset;
        // 3 local hemispheres at the same VRAM-share → identical model on all 3.
        let preset = build_local_preset(
            Some(24 * 1024),
            3,
            VariantClass::Abliterated,
            DEFAULT_OLLAMA_PORT,
        );
        let mut topo = InferenceTopology::default();
        apply_local_abliterated_preset(&mut topo, &preset);
        let refs = collect_ollama_model_refs(&topo);
        // Same model across all 3 slots → pulled once.
        assert_eq!(refs.len(), 1, "expected dedup, got {refs:?}");
        assert!(refs[0].starts_with("hf.co/mradermacher/"));

        // A non-Ollama (cloud) topology yields nothing to provision.
        let cloud = InferenceTopology {
            mode: TopologyMode::Single,
            ..InferenceTopology::default()
        };
        assert!(collect_ollama_model_refs(&cloud).is_empty());
        // A slot that's OpenAiCompat but NOT the Ollama endpoint is ignored.
        let mut other = InferenceTopology::default();
        other.left.provider = Some(InferenceProvider::OpenAiCompat);
        other.left.endpoint = Some("https://openrouter.ai/api/v1".into());
        other.left.model = Some("hf.co/x/y:Q4_K_M".into());
        assert!(collect_ollama_model_refs(&other).is_empty());
    }

    #[test]
    fn topology_default_idx_picks_local_only_when_gpu_detected() {
        use crate::daemon::accelerator::{Accelerator, Probe};
        for picked in [Accelerator::Cuda, Accelerator::Metal, Accelerator::OpenVino] {
            let probe = Probe {
                picked,
                cuda: matches!(picked, Accelerator::Cuda),
                metal: matches!(picked, Accelerator::Metal),
                openvino: matches!(picked, Accelerator::OpenVino),
            };
            assert_eq!(
                topology_default_idx_for_probe(&probe),
                3,
                "GPU-detected probe must default to local-only (idx 3), got otherwise for {picked:?}",
            );
        }
    }

    #[test]
    fn topology_default_idx_picks_single_when_cpu_only() {
        use crate::daemon::accelerator::{Accelerator, Probe};
        let probe = Probe {
            picked: Accelerator::Cpu,
            cuda: false,
            metal: false,
            openvino: false,
        };
        assert_eq!(topology_default_idx_for_probe(&probe), 0);
    }

    #[test]
    fn recommended_provider_unknown_role_falls_back_safely() {
        use crate::config::inference::InferenceProvider as I;
        // Defensive default — never crash if a renamed role is passed.
        assert_eq!(recommended_provider_for_role("hippocampus"), I::ClaudeCli);
        assert_eq!(recommended_provider_for_role(""), I::ClaudeCli);
    }

    #[test]
    fn default_model_for_known_pairs() {
        use crate::config::inference::InferenceProvider as I;
        assert_eq!(
            default_model_for("left", I::ClaudeCli),
            Some("claude-opus-4-7")
        );
        assert_eq!(
            default_model_for("right", I::Gemini),
            Some("gemini-3.1-pro-preview")
        );
        assert_eq!(
            default_model_for("cerebellum", I::LocalQwen),
            Some("Qwen/Qwen2.5-3B-Instruct"),
        );
    }

    #[test]
    fn default_model_for_unknown_role_provider_pair_returns_none() {
        use crate::config::inference::InferenceProvider as I;
        // Pick #11 Phase A (Session 14): the Hermes/OpenClaw stub
        // test was removed alongside the variants. This replacement
        // pins the broader "unknown role+provider pair → fall back
        // to free-text input" contract that the wizard depends on.
        assert_eq!(default_model_for("hippocampus", I::ClaudeCli), None);
        assert_eq!(default_model_for("left", I::LocalQwen), None);
        assert_eq!(default_model_for("cerebellum", I::Gemini), None);
    }

    // ── K-Models-Wizard-Integration (Session 14 Pick #4) ─────────────────

    #[test]
    fn catalog_key_for_provider_kind_maps_all_real_providers() {
        assert_eq!(ProviderKind::ClaudeCli.catalog_key(), Some("anthropic_api"));
        assert_eq!(ProviderKind::OpenaiApi.catalog_key(), Some("openai_api"));
        assert_eq!(ProviderKind::GeminiApi.catalog_key(), Some("gemini_api"));
        assert_eq!(ProviderKind::AwsBedrock.catalog_key(), Some("aws_bedrock"));
        assert_eq!(
            ProviderKind::OpenaiCompat.catalog_key(),
            Some("openai_compat")
        );
    }

    #[test]
    fn catalog_key_for_provider_kind_returns_none_for_kinds_without_catalog_source() {
        // No remote list-models endpoint for these — wizard falls back
        // to bundled defaults.
        assert_eq!(ProviderKind::LocalQwen.catalog_key(), None);
        assert_eq!(ProviderKind::AzureOpenAi.catalog_key(), None);
        assert_eq!(ProviderKind::Skip.catalog_key(), None);
    }

    #[test]
    fn provider_kind_as_str_matches_serde_wire_form_for_all_variants() {
        // COR-13: as_str() must equal the serde-serialised slug for every
        // variant (incl. the AzureOpenAi rename), so the manual stringifier
        // and the persisted config form can never drift.
        use clap::ValueEnum;
        for kind in ProviderKind::value_variants() {
            let serde_form = serde_json::to_string(kind)
                .unwrap()
                .trim_matches('"')
                .to_string();
            assert_eq!(
                kind.as_str(),
                serde_form,
                "as_str() must match serde for {kind:?}"
            );
        }
        // Pin the two surface differences as_provider_id() carries.
        assert_eq!(ProviderKind::Cohere.as_str(), "cohere");
        assert_eq!(ProviderKind::AzureOpenAi.as_str(), "azure_openai");
        assert_eq!(ProviderKind::Skip.as_str(), "skip");
    }

    #[test]
    fn provider_kind_as_provider_id_canonicalises_status_form() {
        // Cohere + Skip diverge from as_str(); everything else matches.
        assert_eq!(ProviderKind::Cohere.as_provider_id(), "cohere_api");
        assert_eq!(ProviderKind::Skip.as_provider_id(), "none");
        assert_eq!(ProviderKind::AzureOpenAi.as_provider_id(), "azure_openai");
        assert_eq!(ProviderKind::OpenaiApi.as_provider_id(), "openai_api");
        assert_eq!(ProviderKind::ClaudeCli.as_provider_id(), "claude_cli");
        // The drift token: Skip resolves to "none", and kind_from_slug
        // treats it as non-cloud (same as the old unconfigured/unknown).
        assert!(crate::consent::kind_from_slug(ProviderKind::Skip.as_provider_id()).is_none());
    }

    #[test]
    fn provider_kind_display_forwards_to_as_str() {
        assert_eq!(format!("{}", ProviderKind::LocalOuro), "local_ouro");
        assert_eq!(format!("{}", ProviderKind::AzureOpenAi), "azure_openai");
    }

    #[test]
    fn provider_kind_to_inference_maps_every_variant() {
        use crate::config::inference::InferenceProvider as I;
        assert_eq!(ProviderKind::ClaudeCli.to_inference(), I::ClaudeCli);
        assert_eq!(ProviderKind::OpenaiApi.to_inference(), I::OpenAi);
        assert_eq!(ProviderKind::AnthropicApi.to_inference(), I::AnthropicApi);
        assert_eq!(ProviderKind::OpenaiCompat.to_inference(), I::OpenAiCompat);
        assert_eq!(ProviderKind::GeminiApi.to_inference(), I::Gemini);
        assert_eq!(ProviderKind::Cohere.to_inference(), I::Cohere);
        assert_eq!(ProviderKind::LocalQwen.to_inference(), I::LocalQwen);
        assert_eq!(ProviderKind::LocalOuro.to_inference(), I::LocalOuro);
        assert_eq!(ProviderKind::AwsBedrock.to_inference(), I::AwsBedrock);
        assert_eq!(ProviderKind::AzureOpenAi.to_inference(), I::AzureOpenAi);
        assert_eq!(ProviderKind::Skip.to_inference(), I::ClaudeCli);
    }

    #[test]
    fn azure_openai_serde_uses_canonical_slug_with_legacy_alias() {
        // COR-13: AzureOpenAi must serialise to the canonical "azure_openai"
        // (not serde's default "azure_open_ai") so freedom.yaml round-trips
        // against consent/cost/InferenceProvider, and the learn_provider
        // error message that promises "azure_openai" actually parses.
        let json = serde_json::to_string(&ProviderKind::AzureOpenAi).unwrap();
        assert_eq!(json, "\"azure_openai\"");
        // Canonical form round-trips.
        let back: ProviderKind = serde_json::from_str("\"azure_openai\"").unwrap();
        assert_eq!(back, ProviderKind::AzureOpenAi);
        // Legacy form still loads via the alias (back-compat for any
        // existing on-disk config).
        let legacy: ProviderKind = serde_json::from_str("\"azure_open_ai\"").unwrap();
        assert_eq!(legacy, ProviderKind::AzureOpenAi);
    }

    #[test]
    fn catalog_recommended_returns_none_when_catalog_missing() {
        // Pointing at a non-existent catalog path → load returns empty
        // catalog → no provider entry → None. Confirms the wizard
        // bundled-fallback path fires on a fresh install.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never_existed.json");
        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::ClaudeCli);
        assert_eq!(result, None);
    }

    #[test]
    fn catalog_recommended_returns_id_when_catalog_has_provider_entry() {
        use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![
                ModelEntry::new("claude-opus-4-7"),
                ModelEntry::new("claude-sonnet-4-6"),
            ],
        );
        catalog.save().unwrap();

        // ClaudeCli → anthropic_api → recommended = first non-deprecated = opus-4-7
        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::ClaudeCli);
        assert_eq!(result, Some("claude-opus-4-7".to_string()));
    }

    #[test]
    fn catalog_recommended_skips_deprecated_first_entry() {
        use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.upsert(
            "openai_api",
            SourceOrigin::Api,
            vec![
                ModelEntry::new("gpt-4o").marked_deprecated(),
                ModelEntry::new("gpt-5.4"),
                ModelEntry::new("gpt-5.5"),
            ],
        );
        catalog.save().unwrap();

        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::OpenaiApi);
        assert_eq!(result, Some("gpt-5.4".to_string()));
    }

    #[test]
    fn catalog_recommended_returns_none_for_kinds_without_source() {
        // Even when catalog file exists, LocalQwen has no source entry
        // because catalog_key_for_provider_kind returns None.
        use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![ModelEntry::new("claude-opus-4-7")],
        );
        catalog.save().unwrap();

        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::LocalQwen);
        assert_eq!(result, None);
    }

    #[test]
    fn default_model_for_unknown_pair_returns_none() {
        use crate::config::inference::InferenceProvider as I;
        // Pairs the SPEC doesn't pin (e.g. ClaudeCli for cerebellum)
        // return None so the wizard inherits the operator's step-5 model.
        assert_eq!(default_model_for("cerebellum", I::ClaudeCli), None);
        assert_eq!(default_model_for("right", I::OpenAi), None);
    }

    #[test]
    fn bcp47_valid() {
        assert!(validate_bcp47("en").is_ok());
        assert!(validate_bcp47("zh-CN").is_ok());
        assert!(validate_bcp47("pt-BR").is_ok());
    }

    #[test]
    fn bcp47_invalid() {
        assert!(validate_bcp47("").is_err());
        assert!(validate_bcp47("x").is_err());
    }

    #[test]
    fn role_valid() {
        assert!(validate_role("developer").is_ok());
        assert!(validate_role("security-researcher").is_ok());
        assert!(validate_role("custom-role").is_ok());
    }

    #[test]
    fn role_invalid() {
        assert!(validate_role("has space").is_err());
        assert!(validate_role(&"a".repeat(33)).is_err());
    }

    #[test]
    fn telegram_token_valid() {
        let token = format!("12345678:{}", "A".repeat(35));
        assert!(validate_telegram_token(&token).is_ok());
    }

    #[test]
    fn telegram_token_invalid() {
        assert!(validate_telegram_token("notvalid").is_err());
        assert!(validate_telegram_token("123:short").is_err());
    }

    // ── write_config + write_initialized_marker (O-1 acceptance) ───────────────

    fn fixture_state() -> WizardState {
        WizardState {
            experience_level: crate::wizard::recommend::ExperienceLevel::Beginner,
            onboarding_mode: OnboardingMode::New,
            operator_id: Some("alice".to_string()),
            language_primary: Some("en".to_string()),
            language_code: Some("en".to_string()),
            role: Some(OperatorRole::Developer),
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("/usr/local/bin/claude".to_string()),
            provider_key: None,
            provider_endpoint: None,
            provider_model: Some("claude-opus-4-7".to_string()),
            telegram_token: Some(crate::secret::SecretString::from(
                "12345678:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )),
            telegram_user_id: Some(987654321),
            autonomy: crate::permissions::AutonomyLevel::Standard,
            inference: crate::config::inference::InferenceTopology::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            supervisor: crate::config::SupervisorConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            keet_seed_phrase: None,
            pears_bearer_token: None,
            download_qwen_weights: false,
            install_obsidian: false,
            bootstrap_vault: false,
            vault_path: None,
            install_n8n: false,
            import_memory: None,
            hmac_backup_offered: false,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    #[tokio::test]
    async fn write_config_creates_freedom_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let state = fixture_state();

        write_config(&neoth_dir, &state)
            .await
            .expect("write_config");

        let yaml = neoth_dir.join("freedom.yaml");
        assert!(
            yaml.exists(),
            "freedom.yaml should exist after write_config"
        );

        let body = std::fs::read_to_string(&yaml).unwrap();
        assert!(body.contains("operator_id: alice"));
        assert!(body.contains("provider_kind: claude_cli"));
        assert!(body.contains("role: developer"));
        // Phase 33+ split: secrets are NOT in freedom.yaml. They live in
        // the sibling credentials.yaml — verify the negative + check the
        // sibling file contains the token.
        assert!(
            !body.contains("12345678:AAAAAAAAA"),
            "telegram_token must NOT be embedded in freedom.yaml after the split",
        );
        let creds_body =
            std::fs::read_to_string(neoth_dir.join("credentials.yaml")).expect("credentials.yaml");
        assert!(
            creds_body.contains("12345678:AAAAAAAAA"),
            "telegram_token must be in credentials.yaml",
        );
        // V03-09 Phase 2a — freedom.yaml MUST carry the auto_update
        // block so operators see the field exists + can edit it
        // without a docs roundtrip.
        assert!(
            body.contains("auto_update:"),
            "freedom.yaml must serialize auto_update block: {body}"
        );
        assert!(
            body.contains("enabled: false"),
            "auto_update default must serialize enabled: false"
        );
    }

    #[tokio::test]
    async fn step7b_non_interactive_leaves_default_auto_update() {
        // The step writes the default AutoUpdateConfig when
        // interactive == false. Pin the contract so a future
        // refactor that flips the default doesn't silently
        // enable background HTTP traffic.
        let mut state = fixture_state();
        state.auto_update = crate::config::AutoUpdateConfig {
            // Pretend a prior wizard run had enabled it; the
            // non-interactive re-run MUST NOT clobber that.
            enabled: true,
            auto_apply: true,
            ..crate::config::AutoUpdateConfig::default()
        };

        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        step7b_auto_update(&args, false, &mut state).unwrap();

        // Non-interactive run preserves whatever the prior state
        // had — does NOT prompt, does NOT reset.
        assert!(state.auto_update.enabled);
        assert!(state.auto_update.auto_apply);
        // Step marker recorded.
        assert!(state.steps_completed.contains(&70));
    }

    #[test]
    fn step7d_non_interactive_leaves_supervisor_disabled() {
        // A background auto-restart service is a real system change —
        // non-interactive onboarding MUST NOT install one. Pin the
        // off-by-default contract + the step marker.
        let mut state = fixture_state();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        step7d_supervisor(&args, false, &mut state).unwrap();
        assert!(
            !state.supervisor.enabled,
            "non-interactive must not install a supervisor"
        );
        assert_eq!(state.supervisor.kind, crate::config::SupervisorKind::None);
        assert!(state.steps_completed.contains(&72));
    }

    #[tokio::test]
    async fn write_config_uses_atomic_temp_then_rename() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        write_config(&neoth_dir, &fixture_state())
            .await
            .expect("write_config");

        // After successful write, the .tmp sibling must be gone (rename consumed it).
        let tmp = neoth_dir.join("freedom.tmp");
        assert!(!tmp.exists(), "intermediate .tmp must be renamed away");
    }

    #[tokio::test]
    async fn write_config_overwrites_existing_on_force_path() {
        // Simulate a --force re-run: write twice with different states.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");

        let mut s1 = fixture_state();
        s1.operator_id = Some("first".to_string());
        write_config(&neoth_dir, &s1).await.expect("first write");

        let mut s2 = fixture_state();
        s2.operator_id = Some("second".to_string());
        write_config(&neoth_dir, &s2)
            .await
            .expect("second write replaces first");

        let yaml = neoth_dir.join("freedom.yaml");
        let body = std::fs::read_to_string(&yaml).unwrap();
        assert!(body.contains("operator_id: second"));
        assert!(!body.contains("operator_id: first"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_config_sets_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        write_config(&neoth_dir, &fixture_state())
            .await
            .expect("write_config");

        let yaml = neoth_dir.join("freedom.yaml");
        let mode = std::fs::metadata(&yaml).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "freedom.yaml must be 0600 on unix");

        let dir_mode = std::fs::metadata(&neoth_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "~/.neoth/ must be 0700 on unix");
    }

    #[test]
    fn write_initialized_marker_writes_json() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let state = fixture_state();

        write_initialized_marker(&neoth_dir, &state).expect("marker write");

        let path = neoth_dir.join(".initialized");
        assert!(path.exists());

        let body = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        // F-22: wizard_version bumped to 2 after schema extension.
        assert_eq!(parsed["wizard_version"], 2);
        assert_eq!(parsed["operator_id"], "alice");
        // 8 steps after Phase 28b inserted the autonomy step.
        assert_eq!(parsed["steps_completed"].as_array().unwrap().len(), 8);
        assert!(parsed["init_time_unix"].as_u64().unwrap() > 0);
        // F-22: new fields all populated.
        assert!(
            !parsed["neoth_version"].as_str().unwrap().is_empty(),
            "neoth_version must reflect the daemon binary version"
        );
        let iso = parsed["init_time_iso8601"].as_str().unwrap();
        assert!(
            iso.ends_with('Z') && iso.contains('T'),
            "iso8601 must be RFC 3339 UTC: {iso}"
        );
        // fixture_state sets provider_kind = ClaudeCli — should round-trip.
        assert_eq!(parsed["provider_kind"], "claude_cli");
        // fixture_state sets telegram_token, so channels lists telegram.
        let channels = parsed["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0], "telegram");
    }

    #[test]
    fn write_initialized_marker_records_telegram_channel() {
        // F-22: when the wizard configured Telegram, the marker should
        // list it under `channels`. Mirrors what `neoth doctor` will
        // surface to the operator.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let mut state = fixture_state();
        state.telegram_token = Some(crate::secret::SecretString::from("dummy-token"));

        write_initialized_marker(&neoth_dir, &state).expect("marker write");

        let body = std::fs::read_to_string(neoth_dir.join(".initialized")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let channels = parsed["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0], "telegram");
    }

    #[test]
    fn format_iso8601_rfc3339_round_trips_known_epoch() {
        // Bounds check: zero epoch maps to 1970.
        assert_eq!(format_iso8601(0), "1970-01-01T00:00:00Z");
        // RFC 3339 round-trip via chrono: write → parse → compare.
        let s = format_iso8601(1_700_000_000);
        let parsed = chrono::DateTime::parse_from_rfc3339(&s).expect("RFC3339 parse");
        assert_eq!(parsed.timestamp(), 1_700_000_000);
        // Format invariant — every output ends with Z + carries a T separator.
        assert!(s.ends_with('Z'));
        assert!(s.contains('T'));
    }

    #[test]
    fn configured_channels_lists_telegram_when_token_set() {
        let mut s = fixture_state();
        s.telegram_token = None;
        assert!(configured_channels(&s).is_empty());
        s.telegram_token = Some(crate::secret::SecretString::from("t"));
        assert_eq!(configured_channels(&s), vec!["telegram".to_string()]);
    }

    #[test]
    fn initialized_marker_deserialises_old_v1_format() {
        // F-22 invariant: a `.initialized` file written by the previous
        // wizard (without neoth_version / iso8601 / provider_kind /
        // channels) must still parse — `#[serde(default)]` makes the
        // new fields optional. Future code paths (status, doctor)
        // depend on being able to read old markers without operator
        // intervention.
        let old_marker_json = r#"{
            "wizard_version": 1,
            "operator_id": "legacy_op",
            "steps_completed": [1, 2, 3, 4, 5, 6, 7],
            "init_time_unix": 1700000000
        }"#;
        let parsed: InitializedMarker = serde_json::from_str(old_marker_json).unwrap();
        assert_eq!(parsed.wizard_version, 1);
        assert_eq!(parsed.operator_id, "legacy_op");
        assert!(parsed.neoth_version.is_empty(), "missing field defaults");
        assert!(parsed.init_time_iso8601.is_empty());
        assert!(parsed.provider_kind.is_none());
        assert!(parsed.channels.is_empty());
    }

    #[tokio::test]
    async fn freedom_yaml_roundtrip_via_serde() {
        // Phase 33+ split: freedom.yaml carries the public fields, secrets
        // live in credentials.yaml. Verify the WizardState round-trips by
        // reading BOTH files (the daemon's `FreedomConfig::load_from_path`
        // does the same merge automatically).
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let original = fixture_state();
        write_config(&neoth_dir, &original).await.expect("write");

        let body = std::fs::read_to_string(neoth_dir.join("freedom.yaml")).unwrap();
        let restored: WizardState = serde_yaml::from_str(&body).expect("deserialize");

        assert_eq!(restored.operator_id, original.operator_id);
        assert_eq!(restored.role, original.role);
        assert_eq!(restored.provider_kind, original.provider_kind);
        assert_eq!(restored.steps_completed, original.steps_completed);
        // Secrets MUST be absent from freedom.yaml.
        assert!(
            restored.telegram_token.is_none(),
            "telegram_token must NOT live in freedom.yaml after the split",
        );
        assert!(
            restored.provider_key.is_none(),
            "provider_key must NOT live in freedom.yaml after the split",
        );
        // But they DO live in the sibling credentials.yaml.
        let cred_path = neoth_dir.join("credentials.yaml");
        assert!(cred_path.exists(), "credentials.yaml must be created");
        let creds = crate::config::credentials::Credentials::load_or_default(&cred_path).unwrap();
        let restored_token = creds.telegram_token.unwrap();
        assert_eq!(
            restored_token.expose(),
            "12345678:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert!(format!("{restored_token:?}").contains("REDACTED"));
    }

    // ── Pick #23 (Session 14) — E-2 Phase 4 council-depth cost warning

    #[test]
    fn depth_warning_at_depth_1_is_not_invoked_in_production_but_still_pure_fn() {
        // The wizard never calls render_council_depth_cost_warning
        // when depth <= 1 — but the fn must stay pure-fn + total so a
        // future refactor that DOES call it with 0/1 still produces a
        // sensible string instead of panicking. At depth=1 the leaf
        // count is 3^1 = 3 (the three outer hemispheres, no recursion).
        let s = render_council_depth_cost_warning(1);
        assert!(s.contains("depth=1"));
        assert!(
            s.contains("3 leaf"),
            "depth=1 should report 3 leaf calls; got: {s}"
        );
    }

    #[test]
    fn depth_warning_at_2_shows_9_leaf_calls() {
        let s = render_council_depth_cost_warning(2);
        assert!(s.contains("depth=2"));
        assert!(s.contains("9 leaf"), "want 9 leaf calls; got: {s}");
        // Default cap is 15 — 9 ≤ 15, so the "fits within" branch
        // should fire.
        assert!(
            s.contains("fits within"),
            "depth-2 cost note must mention cap-fit; got: {s}"
        );
    }

    #[test]
    fn depth_warning_at_3_shows_27_leaf_calls_and_exceeds_cap() {
        let s = render_council_depth_cost_warning(3);
        assert!(s.contains("depth=3"));
        assert!(s.contains("27 leaf"), "want 27 leaf calls; got: {s}");
        // 27 > 15 default cap → must mention budget-exhausted.
        assert!(
            s.contains("exceeds"),
            "depth-3 cost note must mention exceeding cap; got: {s}"
        );
        assert!(
            s.contains("budget-exhausted"),
            "depth-3 must surface the Pick #19 BudgetToken interaction; got: {s}"
        );
    }

    #[test]
    fn depth_warning_at_4_shows_81_leaf_calls() {
        let s = render_council_depth_cost_warning(4);
        assert!(s.contains("depth=4"));
        assert!(s.contains("81 leaf"), "want 81 leaf calls; got: {s}");
    }

    #[test]
    fn depth_warning_clamps_above_max_to_max_leaf_count() {
        // Defensive: even if a caller bypasses the type system and
        // passes depth=255, the render fn must not over-compute.
        let s = render_council_depth_cost_warning(255);
        // Worst-case render still bounded to MAX_HEMISPHERE_COUNCIL_DEPTH
        // power = 3^4 = 81.
        assert!(
            s.contains("81 leaf"),
            "render must clamp internally to MAX depth; got: {s}"
        );
    }

    #[test]
    fn depth_warning_mentions_remedies_in_freedom_yaml() {
        // Operator-facing strings must point at the lever they can pull.
        let s = render_council_depth_cost_warning(3);
        assert!(s.contains("freedom.yaml"), "operator needs the remedy file");
        assert!(
            s.contains("max_calls_per_user_message"),
            "must name the actual config key"
        );
    }

    #[test]
    fn depth_warning_lists_recommended_defaults() {
        let s = render_council_depth_cost_warning(2);
        assert!(s.contains("depth=1"));
        assert!(s.contains("depth=2"));
        // The "depth=3+" hint should still be in the table even when
        // the operator picked depth=2 — they should see the next-step
        // implications too.
        assert!(s.contains("depth=3+"));
    }

    // ── D-102 wizard step 7c — bulk plugin activation tests ─────────

    #[test]
    fn step7c_missing_plugins_dir_silent_noop_records_marker() {
        // Common first-run state: ~/.neoth/plugins/ doesn't exist yet.
        // Step must not panic + must record its marker so a wizard
        // resume can tell the step ran.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth-empty");
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(
            state.plugins.wasm.activations.is_empty(),
            "no plugins discovered → no activations recorded"
        );
        assert!(state.steps_completed.contains(&71));
    }

    #[test]
    fn step7c_empty_plugins_dir_silent_noop() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(neoth_dir.join("plugins")).unwrap();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(state.plugins.wasm.activations.is_empty());
        assert!(state.steps_completed.contains(&71));
    }

    #[test]
    fn step7c_non_interactive_with_discovered_plugins_leaves_activations_empty() {
        // Per panel verdict on D-102 + non-interactive contract:
        // automatically opting plugins in without operator review
        // would defeat the default-inactive guarantee. Activations
        // must stay empty (= every id falls through to default
        // Pending at boot).
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let plugins_root = neoth_dir.join("plugins").join("indexer_v1");
        std::fs::create_dir_all(&plugins_root).unwrap();
        std::fs::write(
            plugins_root.join("plugin.toml"),
            "id = \"indexer_v1\"\nname = \"Indexer\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        // Minimal valid WASM module bytes (wasm magic + version).
        std::fs::write(
            plugins_root.join("plugin.wasm"),
            [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        )
        .unwrap();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(
            state.plugins.wasm.activations.is_empty(),
            "non-interactive run MUST NOT auto-activate; got {:?}",
            state.plugins.wasm.activations,
        );
        assert!(state.steps_completed.contains(&71));
    }

    #[test]
    fn step7c_non_interactive_with_enable_plugin_flag_activates_named_ids() {
        // E-21 non-interactive follow-up: `--enable-plugin indexer_v1`
        // during scripted bring-up MUST land indexer_v1 = Active in
        // freedom.yaml without prompting. Other discovered plugins
        // stay Pending (no entry = default at boot).
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        for id in ["indexer_v1", "recall_rerank"] {
            let pd = neoth_dir.join("plugins").join(id);
            std::fs::create_dir_all(&pd).unwrap();
            std::fs::write(
                pd.join("plugin.toml"),
                format!("id = \"{id}\"\nname = \"x\"\nversion = \"0.1.0\"\n"),
            )
            .unwrap();
            std::fs::write(
                pd.join("plugin.wasm"),
                [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            )
            .unwrap();
        }
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            enable_plugin: vec!["indexer_v1".to_string()],
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert_eq!(
            state.plugins.wasm.activations.get("indexer_v1").copied(),
            Some(crate::wasm_plugin::discovery::PluginActivation::Active),
            "indexer_v1 must be Active after --enable-plugin",
        );
        // recall_rerank stays absent from the map → default Pending
        // at daemon boot.
        assert!(
            !state.plugins.wasm.activations.contains_key("recall_rerank"),
            "unspecified plugins must stay PENDING (no map entry); got {:?}",
            state.plugins.wasm.activations,
        );
    }

    #[test]
    fn step7c_non_interactive_unknown_enable_plugin_id_is_warn_not_fail() {
        // Typo on the operator's CLI line MUST NOT fail the wizard.
        // Per the non-interactive contract: partial activation is
        // better than a failed init.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let pd = neoth_dir.join("plugins").join("indexer_v1");
        std::fs::create_dir_all(&pd).unwrap();
        std::fs::write(
            pd.join("plugin.toml"),
            "id = \"indexer_v1\"\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            pd.join("plugin.wasm"),
            [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        )
        .unwrap();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            enable_plugin: vec!["typoed_id".to_string(), "indexer_v1".to_string()],
            ..Default::default()
        };
        let mut state = fixture_state();
        // Should not panic / not bail; typoed_id is ignored, the valid
        // id still activates.
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(state.plugins.wasm.activations.contains_key("indexer_v1"));
        assert!(!state.plugins.wasm.activations.contains_key("typoed_id"));
    }

    #[tokio::test]
    async fn step6b_non_interactive_silent_noop_records_marker() {
        // K-3.5 contract: non-interactive runs skip the prompt
        // entirely (no flag yet). The step must record its marker
        // for resume tracking.
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step6b_keet_pairing(&args, false, &mut state).await.unwrap();
        assert!(state.keet_seed_phrase.is_none());
        assert!(state.pears_bearer_token.is_none());
        // GOLD-COR-07: 6b's marker is now distinct from 5d's (was both 60).
        assert!(
            state
                .steps_completed
                .contains(&step_markers::STEP_6B_KEET_PAIRING)
        );
    }

    #[test]
    fn step_markers_are_unique() {
        // GOLD-COR-07 / A-26: the regression guard. step 5d and step 6b both
        // used to push `60`, making the checkpoint record ambiguous. Every
        // marker in `step_markers::ALL` must be distinct — a future duplicate
        // (or a re-used value on a new sub-step) trips this test instead of
        // silently corrupting resume state.
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for &m in step_markers::ALL {
            assert!(
                seen.insert(m),
                "duplicate wizard step marker {m} in step_markers::ALL"
            );
        }
        assert_eq!(
            seen.len(),
            step_markers::ALL.len(),
            "step_markers::ALL must contain only distinct values"
        );
    }

    #[test]
    fn keet_credentials_round_trip_through_credentials_yaml() {
        // K-3.5 wire-format pin: WizardState.keet_seed_phrase +
        // pears_bearer_token MUST land in credentials.yaml, NOT
        // freedom.yaml. The Credentials struct now carries both
        // fields — verify they round-trip the YAML cleanly.
        let cred = crate::config::credentials::Credentials {
            keet_seed_phrase: Some(crate::secret::SecretString::from("alpha bravo charlie")),
            pears_bearer_token: Some(crate::secret::SecretString::from("deadbeef".repeat(8))),
            ..Default::default()
        };
        assert!(cred.has_any());
        let yaml = serde_yaml::to_string(&cred).expect("serialize");
        assert!(yaml.contains("keet_seed_phrase:"));
        assert!(yaml.contains("pears_bearer_token:"));
        let back: crate::config::credentials::Credentials =
            serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(
            back.keet_seed_phrase
                .as_ref()
                .map(|s| s.expose().to_string()),
            Some("alpha bravo charlie".to_string()),
        );
        assert_eq!(
            back.pears_bearer_token.as_ref().map(|s| s.expose().len()),
            Some(64),
        );
    }

    // ── K-4b telegram-prompt text tests (Session 21) ────────────────

    #[test]
    fn k4b_prompt_demotes_telegram_when_pear_present() {
        // K-4b: when `pear` is on PATH, Keet is the preferred primary.
        // The Telegram prompt must reframe Telegram as a FALLBACK so
        // operators don't accidentally pick it as primary out of habit.
        let s = k4b_telegram_prompt_text(true);
        assert!(s.contains("FALLBACK"), "msg: {s}");
        assert!(s.contains("Keet"), "msg: {s}");
        assert!(s.contains("preferred primary"), "msg: {s}");
        assert!(s.contains("default: no"), "msg: {s}");
    }

    #[test]
    fn k4b_prompt_neutral_when_pear_missing() {
        // Backward-compat pin: operators without `pear` see the
        // original neutral Telegram prompt — Keet is unreachable so
        // there's nothing to demote Telegram against.
        let s = k4b_telegram_prompt_text(false);
        assert!(!s.contains("FALLBACK"));
        assert!(!s.contains("Keet"));
        assert!(s.contains("Telegram"));
        assert!(s.contains("optional"));
    }

    #[test]
    fn k4b_prompt_keeps_step_label_consistent_across_modes() {
        // Both variants must carry the same `[6/9]` step label so the
        // wizard transcript stays parseable — operators (or automated
        // probes) grepping for "[6/9]" find it regardless of the pear
        // detection outcome.
        assert!(k4b_telegram_prompt_text(true).contains("[6/9]"));
        assert!(k4b_telegram_prompt_text(false).contains("[6/9]"));
    }

    // ── K-4 channel-ordering tests (Session 21) ─────────────────────

    #[test]
    fn k4_configured_channels_lists_keet_first_when_both_paired() {
        // K-4 contract pin: when operator paired BOTH Keet + Telegram
        // during the wizard, Keet appears FIRST in the configured list.
        // First entry = primary; downstream (status display, .initialized
        // marker, post-init summary) reads this ordering.
        let mut s = fixture_state();
        // fixture_state sets Telegram already; add Keet.
        s.keet_seed_phrase = Some(crate::secret::SecretString::from(
            "alpha bravo charlie delta echo foxtrot golf hotel india juliet \
             kilo lima mike november oscar papa quebec romeo sierra tango \
             uniform victor whiskey xray",
        ));
        let chans = configured_channels(&s);
        assert_eq!(chans, vec!["keet".to_string(), "telegram".to_string()]);
    }

    #[test]
    fn k4_configured_channels_keet_only_when_no_telegram() {
        let mut s = fixture_state();
        s.telegram_token = None;
        s.keet_seed_phrase = Some(crate::secret::SecretString::from("seed".to_string()));
        let chans = configured_channels(&s);
        assert_eq!(chans, vec!["keet".to_string()]);
    }

    #[test]
    fn k4_configured_channels_telegram_only_when_no_keet() {
        // Backward-compat pin: a wizard run that skipped Keet pairing
        // still lists Telegram as the configured channel — K-4 must
        // not regress the pre-Keet operators.
        let s = fixture_state(); // has Telegram, no Keet
        let chans = configured_channels(&s);
        assert_eq!(chans, vec!["telegram".to_string()]);
    }

    #[test]
    fn k4_configured_channels_empty_when_neither_paired() {
        let mut s = fixture_state();
        s.telegram_token = None;
        s.keet_seed_phrase = None;
        assert!(configured_channels(&s).is_empty());
    }

    #[test]
    fn wizard_state_keet_fields_excluded_from_freedom_yaml() {
        // K-3.5 split contract: state.keet_seed_phrase +
        // state.pears_bearer_token are #[serde(skip)] so they NEVER
        // surface in freedom.yaml. The serde wire pin: emitting a
        // WizardState carrying both fields produces YAML that does
        // NOT mention either key.
        let mut state = fixture_state();
        state.keet_seed_phrase = Some(crate::secret::SecretString::from("not_in_freedom_yaml"));
        state.pears_bearer_token = Some(crate::secret::SecretString::from(
            "token_not_in_freedom_yaml",
        ));
        let yaml = serde_yaml::to_string(&state).expect("serialize");
        assert!(
            !yaml.contains("keet_seed_phrase"),
            "keet_seed_phrase MUST be #[serde(skip)] — yaml: {yaml}"
        );
        assert!(
            !yaml.contains("pears_bearer_token"),
            "pears_bearer_token MUST be #[serde(skip)] — yaml: {yaml}"
        );
        assert!(!yaml.contains("not_in_freedom_yaml"));
        assert!(!yaml.contains("token_not_in_freedom_yaml"));
    }

    #[test]
    fn wizard_state_plugins_field_round_trips_through_yaml() {
        // D-102 wire-format pin: WizardState.plugins serialises into
        // the same `plugins:\n  wasm:\n    activations:\n      <id>: active`
        // shape FreedomConfig deserialises from. A drift here would
        // mean the operator's wizard picks don't reach the daemon.
        let mut state = fixture_state();
        state.plugins.wasm.activations.insert(
            "indexer_v1".to_string(),
            crate::wasm_plugin::discovery::PluginActivation::Active,
        );
        state.plugins.wasm.activations.insert(
            "recall_rerank".to_string(),
            crate::wasm_plugin::discovery::PluginActivation::Disabled,
        );
        let yaml = serde_yaml::to_string(&state).expect("serialize");
        assert!(yaml.contains("plugins:"));
        assert!(yaml.contains("wasm:"));
        assert!(yaml.contains("activations:"));
        assert!(yaml.contains("indexer_v1: active"));
        assert!(yaml.contains("recall_rerank: disabled"));
    }

    // ── Workstream B (Session 22) — 5 wizard step regressions ─────────────

    fn args_with_flag(set: impl FnOnce(&mut InitArgs)) -> InitArgs {
        let mut a = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        set(&mut a);
        a
    }

    #[tokio::test]
    async fn step5c_non_interactive_no_op_when_provider_not_local_qwen() {
        // Cloud-only operator — no LocalQwen path. Step must skip
        // silently without recording opt-in.
        let mut state = fixture_state();
        state.provider_kind = Some(ProviderKind::ClaudeCli);
        let args = args_with_flag(|a| a.download_qwen_weights = true);
        step5c_qwen_weights(&args, false, &mut state).await.unwrap();
        assert!(!state.download_qwen_weights);
        assert!(state.steps_completed.contains(&58));
    }

    // The std::Mutex env-lock is intentional here: tests in this module
    // mutate process-global $HOME / $USERPROFILE so they MUST serialise
    // against each other. An async-aware Mutex would defeat the purpose
    // (tokio's mutex doesn't poison on panic, so a panicking test could
    // leave the env corrupted for the next test). The await inside the
    // critical section is bounded (`step5c_qwen_weights` does no
    // operator-blocking IO under #[non_interactive=false]).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn step5c_non_interactive_records_when_flag_set_and_local_qwen() {
        let _env_lock = lock_home_env();
        // LocalQwen-using operator + --download-qwen-weights → opt-in
        // recorded. The probe lives under a synthetic HOME so the
        // "weights missing" branch is exercised.
        let temp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        let prev_userprofile = std::env::var_os("USERPROFILE");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("USERPROFILE", temp.path());
        }

        let mut state = fixture_state();
        state.provider_kind = Some(ProviderKind::LocalQwen);
        let args = args_with_flag(|a| a.download_qwen_weights = true);
        step5c_qwen_weights(&args, false, &mut state).await.unwrap();
        assert!(state.download_qwen_weights);
        assert!(state.steps_completed.contains(&58));

        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_userprofile {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
        }
    }

    #[tokio::test]
    async fn step6c_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {}); // no install_obsidian
        step6c_obsidian_install(&args, false, &mut state)
            .await
            .unwrap();
        // Whether install_obsidian was set depends on whether the host
        // happens to have Obsidian already installed (sets it true).
        // The flag-absent path either records "already present" or
        // does nothing — the marker MUST land either way.
        assert!(state.steps_completed.contains(&61));
    }

    #[tokio::test]
    async fn step6c_non_interactive_records_when_flag_set() {
        let mut state = fixture_state();
        let args = args_with_flag(|a| a.install_obsidian = true);
        step6c_obsidian_install(&args, false, &mut state)
            .await
            .unwrap();
        assert!(state.install_obsidian);
        assert!(state.steps_completed.contains(&61));
    }

    #[test]
    fn step6d_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {});
        step6d_obsidian_vault_bootstrap(&args, false, &mut state).unwrap();
        assert!(!state.bootstrap_vault);
        assert!(state.vault_path.is_none());
        assert!(state.steps_completed.contains(&62));
    }

    #[test]
    fn step6d_non_interactive_bootstraps_vault_when_flag_set() {
        // Session 24 env-mutation refactor: use the explicit
        // `home_override` parameter instead of mutating the global
        // HOME / USERPROFILE env vars. No lock needed; tempdir
        // is fully isolated per test.
        let temp = tempfile::tempdir().unwrap();
        let mut state = fixture_state();
        let args = args_with_flag(|a| a.bootstrap_vault = true);
        step6d_obsidian_vault_bootstrap_with_home(&args, false, &mut state, Some(temp.path()))
            .unwrap();

        assert!(state.bootstrap_vault);
        let path = state.vault_path.as_ref().expect("vault_path recorded");
        assert!(path.exists());
        assert!(path.join("README.md").exists());
        assert!(path.join(".obsidian").join("app.json").exists());
        assert!(state.steps_completed.contains(&62));
    }

    #[test]
    fn step6d_idempotent_skips_files_that_already_exist() {
        // Session 24 env-mutation refactor: explicit home_override.
        // Operator re-runs init with --force: existing vault files
        // must NOT be clobbered (operator edits win).
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("Documents").join("NEOTH-Vault");
        std::fs::create_dir_all(&vault).unwrap();
        let sentinel = "OPERATOR EDIT — DO NOT OVERWRITE\n";
        std::fs::write(vault.join("README.md"), sentinel).unwrap();

        let mut state = fixture_state();
        let args = args_with_flag(|a| a.bootstrap_vault = true);
        step6d_obsidian_vault_bootstrap_with_home(&args, false, &mut state, Some(temp.path()))
            .unwrap();

        let body = std::fs::read_to_string(vault.join("README.md")).unwrap();
        assert_eq!(body, sentinel, "operator-edited README must be preserved");
    }

    #[tokio::test]
    async fn step6e_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {});
        step6e_n8n_install(&args, false, &mut state).await.unwrap();
        assert!(!state.install_n8n);
        assert!(state.steps_completed.contains(&63));
    }

    #[tokio::test]
    async fn step6e_non_interactive_records_when_flag_set() {
        let mut state = fixture_state();
        let args = args_with_flag(|a| a.install_n8n = true);
        step6e_n8n_install(&args, false, &mut state).await.unwrap();
        assert!(state.install_n8n);
        assert!(state.steps_completed.contains(&63));
    }

    #[test]
    fn step6f_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {});
        step6f_import_memory(&args, false, &mut state).unwrap();
        assert!(state.import_memory.is_none());
        assert!(state.steps_completed.contains(&64));
    }

    #[test]
    fn step6f_non_interactive_records_path_when_flag_set() {
        let temp = tempfile::tempdir().unwrap();
        let memory_path = temp.path().join("HIPPOCAMPUS_CORE.md");
        std::fs::write(&memory_path, "synthetic legacy-ai seed").unwrap();

        let mut state = fixture_state();
        let args = args_with_flag(|a| a.import_memory = Some(memory_path.clone()));
        step6f_import_memory(&args, false, &mut state).unwrap();
        assert_eq!(state.import_memory.as_ref(), Some(&memory_path));
        assert!(state.steps_completed.contains(&64));
    }

    // --- GOLD-HON-10: step 1d onboarding mode (new vs migration) ---

    #[test]
    fn step1d_non_interactive_defaults_to_new_without_import_flag() {
        let mut state = WizardState::default();
        let args = args_with_flag(|_| {});
        step1d_onboarding_mode(&args, false, &mut state).unwrap();
        assert_eq!(state.onboarding_mode, OnboardingMode::New);
        assert!(state
            .steps_completed
            .contains(&step_markers::STEP_1D_ONBOARDING_MODE));
    }

    #[test]
    fn step1d_non_interactive_infers_migration_from_import_flag() {
        let mut state = WizardState::default();
        let args = args_with_flag(|a| {
            a.import_memory = Some(std::path::PathBuf::from("import-manifest.yaml"));
        });
        step1d_onboarding_mode(&args, false, &mut state).unwrap();
        assert_eq!(state.onboarding_mode, OnboardingMode::Migration);
        assert!(state
            .steps_completed
            .contains(&step_markers::STEP_1D_ONBOARDING_MODE));
    }

    #[test]
    fn step1d_onboarding_mode_recorded_before_identity_step() {
        // The HON-10 contract: the new-vs-migration question precedes the
        // identity (operator-id) step. Run both on a fresh state and assert
        // the 1d marker lands before the step-2 marker.
        let mut state = WizardState::default();
        let args = args_with_flag(|_| {});
        step1d_onboarding_mode(&args, false, &mut state).unwrap();
        step2_operator_id(&args, false, &mut state).unwrap();
        let idx_1d = state
            .steps_completed
            .iter()
            .position(|&m| m == step_markers::STEP_1D_ONBOARDING_MODE)
            .expect("1d marker present");
        let idx_2 = state
            .steps_completed
            .iter()
            .position(|&m| m == step_markers::STEP_2_OPERATOR_ID)
            .expect("step-2 marker present");
        assert!(
            idx_1d < idx_2,
            "onboarding mode (1d) must be recorded before identity (step 2)"
        );
    }

    #[test]
    fn inference_uses_local_qwen_detects_default_slot() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};
        let mut topology = crate::config::inference::InferenceTopology::default();
        topology.default_slot = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        };
        assert!(inference_uses_local_qwen(&topology, &None));
    }

    #[test]
    fn inference_uses_local_qwen_detects_hemisphere_override() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};
        let mut topology = crate::config::inference::InferenceTopology::default();
        topology.left = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        };
        assert!(inference_uses_local_qwen(&topology, &None));
    }

    #[test]
    fn inference_uses_local_qwen_false_for_cloud_only_topology() {
        let topology = crate::config::inference::InferenceTopology::default();
        assert!(!inference_uses_local_qwen(
            &topology,
            &Some(ProviderKind::ClaudeCli)
        ));
    }

    // ── C-05 (Session 25) credential-import sidecar ────────────────────

    #[test]
    fn credential_import_sidecar_writes_redacted_payload_only() {
        // SC-17 invariant: the sidecar carries the redacted projection,
        // never the secrets. Test pins this contract for the wizard
        // step's disk shape.
        use crate::security::credential_redact::{ImportSource, RedactedCredentialImportPayload};
        let home = tempfile::tempdir().unwrap();
        let payload = RedactedCredentialImportPayload {
            source: ImportSource::Bitwarden,
            entry_count: 3,
            distinct_tags_sorted: vec!["banking".into(), "work".into()],
            services_hash: "deadbeefcafebabe".into(),
            target_vault_id: "primary".into(),
            ts_unix: 1_700_000_000,
            services_redacted: true,
        };
        let path = write_credential_import_sidecar(home.path(), 1_700_000_000, &payload).unwrap();
        assert!(path.exists());
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("credentials_import_1700000000.json"),
        );
        let body = std::fs::read_to_string(&path).unwrap();
        // SC-17 keys present; no secret-bearing keys leaked.
        assert!(body.contains("\"services_redacted\""));
        assert!(body.contains("\"entry_count\""));
        assert!(body.contains("\"services_hash\""));
        assert!(!body.contains("password"));
        assert!(!body.contains("secret"));
    }

    #[test]
    fn credential_import_sidecar_overwrites_existing_atomically() {
        // Re-running the wizard at the same ts_unix should overwrite,
        // not leave a `.tmp` companion + not error out on
        // Windows-style rename-over-existing.
        use crate::security::credential_redact::{ImportSource, RedactedCredentialImportPayload};
        let home = tempfile::tempdir().unwrap();
        let payload = RedactedCredentialImportPayload {
            source: ImportSource::Bitwarden,
            entry_count: 0,
            distinct_tags_sorted: Vec::new(),
            services_hash: "0000000000000000".into(),
            target_vault_id: "primary".into(),
            ts_unix: 100,
            services_redacted: true,
        };
        let first = write_credential_import_sidecar(home.path(), 100, &payload).unwrap();
        let second = write_credential_import_sidecar(home.path(), 100, &payload).unwrap();
        assert_eq!(first, second);
        // No `.tmp` companion leaked.
        let tmp = home.path().join("credentials_import_100.json.tmp");
        assert!(!tmp.exists());
    }

    // ── Session 27: NOOB-UX experience-level gates for step5c/5d/6e/7 ──
    //
    // Pattern matches step5b (Session 26): Beginner short-circuits
    // dialoguer prompts and takes safe defaults silently. The tests
    // exercise the early-return branch — if it regresses, step6e_n8n /
    // step7_autonomy would block on stdin instead of completing, which
    // surfaces as the test hanging the suite. Better to fail fast.

    #[test]
    fn step5d_beginner_records_marker() {
        // Beginner sees the 1-line plain-English summary; the marker
        // still lands so the audit chain has the same shape across
        // experience levels.
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Beginner;
        step5d_profile_approval_gate(true, &mut state).expect("step5d Beginner");
        assert!(
            state.steps_completed.contains(&60),
            "step5d marker (60) must be recorded irrespective of experience level",
        );
    }

    #[test]
    fn step5d_intermediate_records_marker() {
        // Intermediate operators still get the 6-line technical
        // version; assert the marker still records so future drift
        // (e.g. early-return-without-marker) is caught.
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Intermediate;
        step5d_profile_approval_gate(true, &mut state).expect("step5d Intermediate");
        assert!(state.steps_completed.contains(&60));
    }

    #[tokio::test]
    async fn step6e_beginner_skips_n8n_silently() {
        // Beginner gate MUST short-circuit before dialoguer. If this
        // regresses, the test hangs on stdin — fail-fast is the goal.
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Beginner;
        // Interactive=true would normally prompt; the Beginner gate
        // hits FIRST and short-circuits the dialoguer call.
        step6e_n8n_install(&args, true, &mut state)
            .await
            .expect("step6e Beginner");
        assert!(
            !state.install_n8n,
            "Beginner default is don't-install n8n — operator opts in via settings later",
        );
        assert!(state.steps_completed.contains(&63));
    }

    #[test]
    fn step7_beginner_takes_standard_silently() {
        // Beginner skips the 5-option autonomy matrix and lands on
        // Standard. The 5-option matrix uses jargon (paid-call
        // thresholds, policy.yaml::dangerous_targets) that scares
        // non-developers.
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Beginner;
        state.autonomy = crate::permissions::AutonomyLevel::Strict; // start non-default
        step7_autonomy(&args, true, &mut state).expect("step7 Beginner");
        assert_eq!(
            state.autonomy,
            crate::permissions::AutonomyLevel::Standard,
            "Beginner gate must land on Standard regardless of prior state",
        );
        assert!(state.steps_completed.contains(&7));
    }
}
