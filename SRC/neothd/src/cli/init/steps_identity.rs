//! Wizard identity steps (GOLD-ARCH-05): operator id, language, HMAC
//! backup, operator role. Split out of `cli/init.rs`.

#[cfg(any(feature = "wizard", test))]
use anyhow::Context as _;
use anyhow::Result;
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
            let raw_output: String =
                dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(
                        "[3b/9] Absolute external/offline backup file (outside ~/.neoth; e.g. USB)",
                    )
                    .validate_with(|input: &String| {
                        let output = std::path::Path::new(input.trim());
                        if !output.is_absolute() {
                            return Err(
                                "enter an absolute file path so the recovery location is explicit"
                                    .to_string(),
                            );
                        }
                        crate::cli::security::resolve_hmac_backup_destination(neoth_dir, output)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    })
                    .interact_text()
                    .context("external HMAC-backup destination input")?;
            let output = std::path::PathBuf::from(raw_output.trim());
            let resolved = backup_hmac_key_to_destination(neoth_dir, &output).with_context(|| {
                format!(
                    "HMAC key backup to {} failed; onboarding stopped and no recovery backup was recorded",
                    output.display()
                )
            })?;
            eprintln!(
                "[neoth init] WAL integrity-key recovery backup complete: {}",
                resolved.display()
            );
        }
    }
    // `neoth_dir` + `state` are only consumed under the `wizard` feature.
    #[cfg(not(feature = "wizard"))]
    let _ = (neoth_dir, state);
    Ok(())
}

#[cfg(any(feature = "wizard", test))]
pub(crate) fn backup_hmac_key_to_destination(
    neoth_dir: &std::path::Path,
    output: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let resolved = crate::cli::security::resolve_hmac_backup_destination(neoth_dir, output)?;
    // A fresh wizard runs before the daemon has written its first WAL frame, so
    // the integrity key does not exist yet. Initialize it through the canonical
    // compaction-key path; RNG/DPAPI/permission failures abort onboarding.
    let key_path = neoth_dir.join("wal").join("hmac.key");
    crate::wal::compaction::load_or_init_key(&key_path)
        .context("initialize WAL integrity key for recovery backup")?;
    crate::cli::security::run_backup_hmac_key(&crate::cli::security::BackupHmacKeyArgs {
        output: resolved.clone(),
        force: false,
        home: Some(neoth_dir.to_path_buf()),
    })?;
    Ok(resolved)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_hmac_key(home: &std::path::Path) -> Vec<u8> {
        let key_path = home.join("wal").join("hmac.key");
        crate::wal::compaction::load_or_init_key(&key_path).expect("seed HMAC key")
    }

    #[test]
    fn fresh_wizard_hmac_backup_initializes_and_exports_the_exact_key() {
        let home = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let output = external.path().join("neoth-hmac-recovery.key");

        let resolved = backup_hmac_key_to_destination(home.path(), &output).unwrap();
        let expected =
            crate::wal::compaction::load_or_init_key(&home.path().join("wal").join("hmac.key"))
                .unwrap();

        assert_eq!(resolved, output.canonicalize().unwrap());
        assert_eq!(std::fs::read(&output).unwrap(), expected);
        assert!(
            !home.path().join("wal").join("hmac_backup.bin").exists(),
            "wizard must never leave the recovery copy inside NEOTH home"
        );
    }

    #[test]
    fn wizard_hmac_backup_rejects_destination_inside_neoth_home() {
        let home = tempfile::tempdir().unwrap();
        seed_hmac_key(home.path());
        let output = home.path().join("wal").join("recovery.key");

        let err = backup_hmac_key_to_destination(home.path(), &output).unwrap_err();

        assert!(err.to_string().contains("inside NEOTH home"), "got: {err}");
        assert!(!output.exists(), "rejected destination must stay unwritten");
    }

    #[test]
    fn wizard_hmac_backup_propagates_key_initialization_and_overwrite_failures() {
        let broken_home = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let output = external.path().join("recovery.key");
        std::fs::write(broken_home.path().join("wal"), b"not-a-directory").unwrap();

        let initialization =
            backup_hmac_key_to_destination(broken_home.path(), &output).unwrap_err();
        assert!(
            initialization
                .to_string()
                .contains("initialize WAL integrity key"),
            "got: {initialization}"
        );
        assert!(!output.exists());

        let home = tempfile::tempdir().unwrap();
        seed_hmac_key(home.path());
        std::fs::write(&output, b"older-recovery-key").unwrap();
        let overwrite = backup_hmac_key_to_destination(home.path(), &output).unwrap_err();
        assert!(
            overwrite.to_string().contains("refusing to overwrite"),
            "got: {overwrite}"
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"older-recovery-key");
    }

    #[test]
    fn hmac_backup_destination_rejects_parent_traversal() {
        let home = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let output = external
            .path()
            .join("nested")
            .join("..")
            .join("recovery.key");

        let err = crate::cli::security::resolve_hmac_backup_destination(home.path(), &output)
            .unwrap_err();

        assert!(
            err.to_string().contains("must not contain `..`"),
            "got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hmac_backup_destination_rejects_symlink_into_neoth_home() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let link = external.path().join("looks-external");
        symlink(home.path(), &link).unwrap();
        let output = link.join("recovery.key");

        let err = crate::cli::security::resolve_hmac_backup_destination(home.path(), &output)
            .unwrap_err();

        assert!(err.to_string().contains("inside NEOTH home"), "got: {err}");
    }
}
