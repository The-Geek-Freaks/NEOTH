//! Wizard environment steps (GOLD-ARCH-05): mode selection, license,
//! environment detection, experience level, onboarding mode.
//! Split out of `cli/init.rs`.

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::{
    InitArgs, OnboardingMode, WizardModeChoice, WizardState, WizardStep,
    write_detect_complete_sidecar,
};

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
pub(crate) fn step0_mode_selection(
    args: &InitArgs,
    interactive: bool,
    neoth_home: &std::path::Path,
) -> Result<WizardModeChoice> {
    let explicit_env = explicit_interface_from_env()?;
    let headless = crate::wizard::env_probe::probe_and_classify().is_headless();
    step0_mode_selection_with_env(args, interactive, neoth_home, explicit_env, headless)
}

fn step0_mode_selection_with_env(
    args: &InitArgs,
    interactive: bool,
    neoth_home: &std::path::Path,
    explicit_env: Option<crate::interface_preference::InterfacePreference>,
    headless: bool,
) -> Result<WizardModeChoice> {
    debug!("wizard step 0: mode selection");
    if args.gui {
        return Ok(WizardModeChoice::Gui);
    }
    if args.cli {
        persist_cli_choice_unless_dry_run(args, neoth_home)?;
        return Ok(WizardModeChoice::Cli);
    }
    if let Some(preferred) = explicit_env {
        if preferred == crate::interface_preference::InterfacePreference::Cli {
            persist_cli_choice_unless_dry_run(args, neoth_home)?;
        }
        return Ok(preferred.into());
    }
    if !interactive || headless {
        // Headless and scripted installs never block on a UI question. This is
        // an execution fallback, not an operator choice, so it deliberately
        // ignores a stored desktop GUI default and does not consume the one-
        // time prompt. `--gui` / `NEOTH_INTERFACE=gui` remain explicit escape
        // hatches for controlled display-bearing automation.
        return Ok(WizardModeChoice::Cli);
    }
    if let Some(preferred) = crate::interface_preference::load_at(neoth_home)? {
        return Ok(preferred.into());
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
            0 => Ok(WizardModeChoice::Gui),
            _ => {
                persist_cli_choice_unless_dry_run(args, neoth_home)?;
                Ok(WizardModeChoice::Cli)
            }
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

fn explicit_interface_from_env() -> Result<Option<crate::interface_preference::InterfacePreference>>
{
    match std::env::var("NEOTH_INTERFACE") {
        Ok(raw) if !raw.trim().is_empty() => raw.parse().map(Some),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error).context("read NEOTH_INTERFACE"),
    }
}

fn persist_cli_choice_unless_dry_run(args: &InitArgs, neoth_home: &std::path::Path) -> Result<()> {
    if !args.dry_run {
        crate::interface_preference::save_at(
            neoth_home,
            crate::interface_preference::InterfacePreference::Cli,
        )?;
    }
    Ok(())
}

pub(crate) fn step1_license(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
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
            state.steps_completed.push(WizardStep::License as u8);
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

    state.steps_completed.push(WizardStep::License as u8);
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
pub(crate) async fn step1b_detect_environment(
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
        println!(
            "  (headless — GUI / browser-OAuth steps are optional here; `neoth init --cli` skips them)"
        );
    }
    let now_unix = crate::time::now_unix_secs();
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
pub(crate) fn step1c_experience_level(
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
/// scope: the wizard records intent and never mutates memory; the operator
/// previews and explicitly consents through `neoth-migrate apply --confirm`.
/// Non-interactive runs infer the mode from `--import-memory` (a declared
/// manifest ⇒ Migration).
pub(crate) fn step1d_onboarding_mode(
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
            println!(
                "\n[1d/9] Is this a fresh start, or are you moving in from another assistant?\n"
            );
            let options = [
                "Fresh install — start with an empty memory",
                "Migrate — import memory from a previous AI assistant",
            ];
            let picked = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
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
    state.steps_completed.push(WizardStep::OnboardingMode as u8);

    match (mode, interactive) {
        (OnboardingMode::Migration, true) => {
            println!(
                "  [1d/9] Migration mode — the wizard collects your prior-assistant import \
                 manifest later (step 6f). Preview it any time with `neoth-migrate dry-run \
                 --manifest <path>`, then explicitly import with `neoth-migrate apply \
                 --manifest <path> --confirm`. The wizard records your intent and never \
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

#[cfg(test)]
mod interface_tests {
    use super::*;
    use crate::interface_preference::InterfacePreference;

    #[test]
    fn explicit_cli_is_persisted_and_reused_without_a_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let args = InitArgs {
            cli: true,
            ..Default::default()
        };

        assert_eq!(
            step0_mode_selection_with_env(&args, false, dir.path(), None, false).unwrap(),
            WizardModeChoice::Cli
        );
        assert_eq!(
            crate::interface_preference::load_at(dir.path()).unwrap(),
            Some(InterfacePreference::Cli)
        );

        let args = InitArgs::default();
        assert_eq!(
            step0_mode_selection_with_env(&args, false, dir.path(), None, false).unwrap(),
            WizardModeChoice::Cli
        );
    }

    #[test]
    fn stored_gui_choice_is_reused_on_desktop_but_headless_stays_cli() {
        let dir = tempfile::tempdir().unwrap();
        crate::interface_preference::save_at(dir.path(), InterfacePreference::Gui).unwrap();
        assert_eq!(
            step0_mode_selection_with_env(&InitArgs::default(), true, dir.path(), None, false)
                .unwrap(),
            WizardModeChoice::Gui
        );

        assert_eq!(
            step0_mode_selection_with_env(&InitArgs::default(), false, dir.path(), None, false)
                .unwrap(),
            WizardModeChoice::Cli
        );
        assert_eq!(
            step0_mode_selection_with_env(&InitArgs::default(), true, dir.path(), None, true)
                .unwrap(),
            WizardModeChoice::Cli,
            "an SSH/headless TTY must not launch the stored GUI default"
        );
        assert_eq!(
            crate::interface_preference::load_at(dir.path()).unwrap(),
            Some(InterfacePreference::Gui),
            "headless fallback must not overwrite the desktop preference"
        );

        let fresh = tempfile::tempdir().unwrap();
        assert_eq!(
            step0_mode_selection_with_env(&InitArgs::default(), false, fresh.path(), None, false)
                .unwrap(),
            WizardModeChoice::Cli
        );
        assert_eq!(
            crate::interface_preference::load_at(fresh.path()).unwrap(),
            None
        );
    }

    #[test]
    fn environment_override_is_explicit_and_dry_run_never_writes() {
        let dir = tempfile::tempdir().unwrap();
        let dry = InitArgs {
            dry_run: true,
            ..Default::default()
        };
        assert_eq!(
            step0_mode_selection_with_env(
                &dry,
                false,
                dir.path(),
                Some(InterfacePreference::Cli),
                false,
            )
            .unwrap(),
            WizardModeChoice::Cli
        );
        assert_eq!(
            crate::interface_preference::load_at(dir.path()).unwrap(),
            None
        );

        let real = InitArgs::default();
        assert_eq!(
            step0_mode_selection_with_env(
                &real,
                false,
                dir.path(),
                Some(InterfacePreference::Cli),
                false,
            )
            .unwrap(),
            WizardModeChoice::Cli
        );
        assert_eq!(
            crate::interface_preference::load_at(dir.path()).unwrap(),
            Some(InterfacePreference::Cli)
        );
    }

    #[test]
    fn gui_choice_is_committed_only_by_the_successful_launcher() {
        let dir = tempfile::tempdir().unwrap();
        let args = InitArgs {
            gui: true,
            ..Default::default()
        };
        assert_eq!(
            step0_mode_selection_with_env(&args, false, dir.path(), None, false).unwrap(),
            WizardModeChoice::Gui
        );
        assert_eq!(
            crate::interface_preference::load_at(dir.path()).unwrap(),
            None
        );
    }
}
