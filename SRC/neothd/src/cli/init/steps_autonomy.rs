//! Wizard autonomy + finalization steps (GOLD-ARCH-05): step7 autonomy
//! level, step7b auto-update, step7c wasm plugin activation, step7d
//! supervisor, inline consent grant. Split out of `cli/init.rs`.

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::{WizardStep, InitArgs, ProviderKind, WizardState};

/// Step 7 — operator picks an autonomy level (Phase 28b R-23).
///
/// Five choices map to `permissions::AutonomyLevel`. Each one-line
/// consequence preview describes the *first* surprise the operator would
/// hit at that level so the choice stays concrete.
///
/// Non-interactive: honours `--autonomy <level>`. Falls back to `Standard`
/// if absent — least-surprise default per spec.
pub(crate) fn step7_autonomy(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
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
        state.steps_completed.push(WizardStep::Autonomy as u8);
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
            state.steps_completed.push(WizardStep::Autonomy as u8);
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

    state.steps_completed.push(WizardStep::Autonomy as u8);
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
pub(crate) fn step7b_auto_update(_args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 7b: auto-update");

    if !interactive {
        // Default = enabled:false, auto_apply:false. Already set
        // by WizardState::default(); just record the step.
        state.steps_completed.push(WizardStep::AutoUpdate as u8); // 7-and-a-half style marker
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

    state.steps_completed.push(WizardStep::AutoUpdate as u8);
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
pub(crate) fn step7c_wasm_plugin_activation(
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
        state.steps_completed.push(WizardStep::WasmPlugins as u8); // 7c marker (7-and-three-quarters)
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
        state.steps_completed.push(WizardStep::WasmPlugins as u8);
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

    state.steps_completed.push(WizardStep::WasmPlugins as u8);
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
pub(crate) fn step7d_supervisor(_args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 7d: supervisor");

    if !interactive {
        // Default = disabled (WizardState::default). Just record the step.
        state.steps_completed.push(WizardStep::Supervisor as u8);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        let kind = crate::daemon::supervisor::recommended_kind();
        if matches!(kind, crate::config::SupervisorKind::None) {
            println!("  [7d/9] supervisor: no supported supervisor for this OS — skipping");
            state.steps_completed.push(WizardStep::Supervisor as u8);
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

    state.steps_completed.push(WizardStep::Supervisor as u8);
    Ok(())
}

/// Resolve the current exe + config/home dirs and run the OS supervisor
/// install. Split out so the dialoguer branch stays readable + so the
/// path resolution is shared with a future `neoth supervisor` re-run.
#[cfg(feature = "wizard")]
pub(crate) fn install_supervisor_now() -> Result<crate::config::SupervisorKind> {
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
pub(crate) fn try_inline_consent_grant(
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
pub(crate) fn try_inline_consent_grant(
    _args: &InitArgs,
    _provider_kind: Option<ProviderKind>,
    _provider_display: &str,
) -> bool {
    false
}
