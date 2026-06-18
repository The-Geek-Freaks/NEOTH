//! Wizard identity steps (GOLD-ARCH-05): operator id, language, HMAC
//! backup, operator role. Split out of `cli/init.rs`.

use anyhow::{Context, Result};
use tracing::debug;

use super::{
    InitArgs, OperatorRole, WizardState, WizardStep, get_os_username, validate_bcp47,
    validate_operator_id,
};

pub(crate) fn step2_operator_id(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
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
    state.steps_completed.push(WizardStep::OperatorId as u8);
    Ok(())
}

pub(crate) fn step3_language(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
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
    state.steps_completed.push(WizardStep::Language as u8);
    Ok(())
}

/// SC-09 step 3b — optionally back up the WAL integrity (HMAC) key. The key is
/// bound to this machine/user (DPAPI on Windows, mode-0600 on Unix); a plaintext
/// backup is the ONLY way to recover the audit-chain history after a machine
/// change or Windows reinstall (see `PLAN/RUNBOOK_dpapi_hmac_recovery.md`).
/// Default NO — opt-in, since it writes a plaintext copy of a secret. Skipped
/// entirely in non-interactive runs (the operator can run
/// `neoth security backup-hmac-key` later).
pub(crate) fn step3b_hmac_backup(
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
                Ok(()) => eprintln!(
                    "[neoth init] WAL integrity key backed up to {}",
                    output.display()
                ),
                Err(e) => eprintln!("[neoth init] HMAC key backup failed (non-fatal): {e}"),
            }
        }
    }
    // `neoth_dir` + `state` are only consumed under the `wizard` feature.
    #[cfg(not(feature = "wizard"))]
    let _ = (neoth_dir, state);
    Ok(())
}

pub(crate) fn step4_role(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
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
    state.steps_completed.push(WizardStep::Role as u8);
    Ok(())
}
