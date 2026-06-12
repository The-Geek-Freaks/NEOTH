//! Sync helpers for the `neoth init` wizard (GOLD-ARCH-05): interactivity,
//! checkpoint resume, first-tour + sidecar markers, daemon spawn, input
//! validation. Split out of `cli/init.rs`.

use std::io::IsTerminal;

use anyhow::{Context, Result};
use tracing::info;

use super::{InitArgs, WizardState};

/// Effective interactivity: TTY on stdin AND --non-interactive not set.
/// On Windows, `IsTerminal` correctly handles ConHost/Terminal/MinTTY.
pub(crate) fn is_interactive(args: &InitArgs) -> bool {
    !args.non_interactive && std::io::stdin().is_terminal()
}

/// R-04 (Session 24) — best-effort checkpoint write between wizard
/// steps. Failures here log a `warn!` and continue: the wizard keeps
/// running with the in-memory state, and the operator can still finish
/// in one sitting if the crash never actually arrives. The checkpoint
/// only earns its keep when there IS a crash; making save failures
/// fatal would let a transient disk issue (full /tmp, AV scanner lock)
/// kill an otherwise-healthy wizard run.
pub(crate) fn save_checkpoint_best_effort(neoth_dir: &std::path::Path, state: &WizardState) {
    if let Err(e) = crate::cli::wizard_checkpoint::save_checkpoint(neoth_dir, state) {
        tracing::warn!(
            error = %e,
            "wizard checkpoint save failed; in-memory state intact, resume after crash will lose this step",
        );
    }
}

/// R-04 (Session 24) — entry-point resume gate. Called once before
/// step1. When a checkpoint file exists AND the operator is on a TTY,
/// prompts `Resume from your previous wizard? (last updated …) [Y/n]`.
/// On confirm: hydrates `state` from the file. On decline: clears the
/// file so the next boot starts clean. Non-interactive (CI / pipe /
/// `--non-interactive`) auto-resumes silently — a crashed CI run that
/// re-runs `neoth init --non-interactive` should pick up where it
/// left off without needing operator input.
pub(crate) fn maybe_resume_from_checkpoint(
    neoth_dir: &std::path::Path,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    let checkpoint = match crate::cli::wizard_checkpoint::load_checkpoint(neoth_dir) {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(()),
        Err(e) => {
            // Corrupt checkpoint shouldn't block a fresh wizard run.
            // Log + delete it so the next boot doesn't keep tripping.
            tracing::warn!(
                error = %e,
                "wizard checkpoint unreadable, ignoring + clearing",
            );
            let _ = crate::cli::wizard_checkpoint::clear_checkpoint(neoth_dir);
            return Ok(());
        }
    };

    let resume = if interactive {
        #[cfg(feature = "wizard")]
        {
            let age_hint = format_checkpoint_age(checkpoint.checkpoint_written_at_unix);
            let prompt = format!(
                "Found an incomplete wizard run ({age_hint}). \
                 Resume with your previous answers? (secrets must be re-entered)",
            );
            dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(prompt)
                .default(true)
                .interact()
                .context("wizard resume confirm")?
        }
        #[cfg(not(feature = "wizard"))]
        {
            // No dialoguer available → fall through to the
            // non-interactive default (auto-resume).
            true
        }
    } else {
        // CI / pipe: silently auto-resume so a re-run of `neoth init
        // --non-interactive` after a transient crash picks up the
        // saved progress without needing TTY input.
        true
    };

    if resume {
        info!(
            steps_completed = ?checkpoint.steps_completed,
            "wizard resumed from checkpoint",
        );
        checkpoint.apply_to(state);
    } else {
        info!("operator declined wizard resume; clearing checkpoint");
        let _ = crate::cli::wizard_checkpoint::clear_checkpoint(neoth_dir);
    }
    Ok(())
}

/// Human-readable age hint for the resume prompt. Operator-facing only;
/// not parsed back. Returns e.g. `"last updated 2 hours ago"` or
/// `"timestamp unavailable"` if the wall clock looks bogus.
pub(crate) fn format_checkpoint_age(ts_unix: i64) -> String {
    if ts_unix <= 0 {
        return "timestamp unavailable".into();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let delta = now.saturating_sub(ts_unix);
    let phrase = match delta {
        d if d < 60 => "less than a minute ago".to_string(),
        d if d < 3_600 => format!("{} minutes ago", d / 60),
        d if d < 86_400 => format!("{} hours ago", d / 3_600),
        d => format!("{} days ago", d / 86_400),
    };
    format!("last updated {phrase}")
}

/// Marker filename written under `~/.neoth/` to flag the very first
/// chat session post-wizard. `neoth chat` reads + deletes it on its
/// next run and prepends the first-tour greeting. Single-use; once
/// the chat session consumes it the operator is past onboarding.
pub const FIRST_TOUR_MARKER: &str = "first_tour_pending";

/// Body printed for the very first interactive `neoth chat` after the
/// wizard finishes. Lives next to the marker constant so the chat
/// path imports both from a single source of truth.
pub const FIRST_TOUR_MESSAGE: &str = "Hi, I'm running. Want a quick tour? \
                                      Type `neoth chat \"give me a tour\"` \
                                      or `neoth recall --help` to start exploring.";

/// Spawn the current binary with the `serve` subcommand as a detached
/// background process. Returns the child PID on success.
///
/// Detach semantics:
///   - **Unix**: `Stdio::null()` on stdin/stdout/stderr so the daemon
///     keeps running after the wizard's shell exits. The kernel inherits
///     orphaned processes by init/launchd, so an explicit `setsid` isn't
///     required for the wizard's "I just want it running" UX.
///   - **Windows**: `Stdio::null()` plus `CREATE_NEW_PROCESS_GROUP`
///     (via the `windows` crate's process flags) detaches the child
///     from the console so closing the wizard terminal doesn't SIGTERM
///     the daemon.
///
/// The path comes from `std::env::current_exe()` so a `cargo run
/// --bin neoth` invocation reuses the same binary instead of relying
/// on a `PATH` lookup that might miss a freshly-built dev binary.
pub(crate) fn spawn_daemon_detached() -> Result<u32> {
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().context("locate current neoth binary for daemon spawn")?;

    let mut cmd = Command::new(&exe);
    cmd.arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP = 0x00000200; DETACHED_PROCESS = 0x00000008.
        // The combination keeps the child alive after the wizard shell
        // closes + decouples it from Ctrl+C in the parent console.
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("spawn `{} serve`", exe.display()))?;
    Ok(child.id())
}

/// Drop the [`FIRST_TOUR_MARKER`] file. Idempotent — overwrites if
/// present (operator re-ran the wizard with `--force`, both runs
/// should land in the same onboarding-aware first-chat path).
pub(crate) fn write_first_tour_marker(neoth_dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(neoth_dir).with_context(|| {
        format!(
            "create neoth dir for first-tour marker: {}",
            neoth_dir.display(),
        )
    })?;
    let path = neoth_dir.join(FIRST_TOUR_MARKER);
    std::fs::write(&path, FIRST_TOUR_MESSAGE.as_bytes())
        .with_context(|| format!("write first-tour marker: {}", path.display()))?;
    Ok(())
}

/// Read + delete the first-tour marker. Returns `Some(message)` once
/// and `None` thereafter — used by the chat path to render the
/// greeting at most once per wizard run.
pub fn consume_first_tour_marker(neoth_dir: &std::path::Path) -> Option<String> {
    let path = neoth_dir.join(FIRST_TOUR_MARKER);
    let body = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    Some(body)
}

/// Render the operator-facing handoff message when the GUI surface
/// is picked. Kept separate so non-interactive `--gui` runs and the
/// interactive Select both print identical instructions.
pub(crate) fn print_gui_handoff_banner() {
    println!();
    println!("=================================================================");
    println!("  Launch the GUI wizard:");
    println!();
    println!("    neothd-gui");
    println!();
    println!("  The graphical wizard uses the same freedom.yaml + WAL backing");
    println!("  store as the CLI, so anything you configure there is visible");
    println!("  to `neoth chat` + `neoth serve` afterwards. To come back to");
    println!("  this terminal wizard at any point, run:");
    println!();
    println!("    neoth init --cli");
    println!("=================================================================");
    println!();
}

/// W-04 follow-up (Session 26): write the
/// [`DetectCompletePayload`](crate::wal::payloads_w08::DetectCompletePayload)
/// to a sidecar file under `~/.neoth/`. The daemon's
/// `detect_complete_sidecar` ingester picks it up on next tick,
/// emits the `0xD5 DETECT_COMPLETE` WAL frame, then deletes the
/// sidecar. Atomic via `.tmp` + rename, Windows-safe.
pub(crate) fn write_detect_complete_sidecar(
    neoth_dir: &std::path::Path,
    ts_unix: u64,
    payload: &crate::wal::payloads_w08::DetectCompletePayload,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(neoth_dir)?;
    // Zero-padded timestamp so lexicographic == chronological order
    // when the ingester walks the home dir.
    let final_path = neoth_dir.join(format!("detect_complete_{ts_unix:020}.json"));
    let tmp_path = final_path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(payload).map_err(std::io::Error::other)?;
    std::fs::write(&tmp_path, &body)?;
    if final_path.exists() {
        let _ = std::fs::remove_file(&final_path);
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// Write the SC-17-redacted credential-import payload to a sidecar
/// file under `~/.neoth/`. Pure-fn over the home dir + payload so
/// tests can exercise the disk shape without the wizard prompts.
pub(crate) fn write_credential_import_sidecar(
    neoth_dir: &std::path::Path,
    ts_unix: i64,
    payload: &crate::security::credential_redact::RedactedCredentialImportPayload,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(neoth_dir)?;
    let final_path = neoth_dir.join(format!("credentials_import_{ts_unix}.json"));
    let tmp_path = final_path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(payload).map_err(std::io::Error::other)?;
    std::fs::write(&tmp_path, &body)?;
    if final_path.exists() {
        let _ = std::fs::remove_file(&final_path);
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

pub(crate) const RESERVED_IDS: &[&str] = &["neoth", "root", "system", "admin", "daemon", "nobody"];

/// Validate operator-id: 2-32 ASCII chars, [a-zA-Z0-9_-], not reserved.
///
/// ASCII only is intentional. Operator IDs appear in WAL audit events,
/// filesystem paths, and tracing fields — Unicode here would cause
/// downstream issues (NTFS codepage clashes, log-parser breakage).
pub fn validate_operator_id(id: &str) -> Result<()> {
    if id.len() < 2 || id.len() > 32 {
        anyhow::bail!("operator-id must be 2-32 chars (got {})", id.len());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!("operator-id may only contain [a-zA-Z0-9_-]: {id}");
    }
    if RESERVED_IDS.contains(&id) {
        anyhow::bail!("operator-id '{}' is reserved", id);
    }
    Ok(())
}

/// Validate BCP-47 language code (simplified pattern check).
pub fn validate_bcp47(code: &str) -> Result<()> {
    if code.len() < 2 || code.split('-').any(|p| p.is_empty() || p.len() > 8) {
        anyhow::bail!("invalid BCP-47 language code: {code}");
    }
    Ok(())
}

/// Validate role: listed key or custom [a-z0-9_-] 1-32 chars.
pub fn validate_role(role: &str) -> Result<()> {
    const KNOWN: &[&str] = &[
        "developer",
        "security-researcher",
        "founder",
        "data-scientist",
        "writer",
        "none",
    ];
    if KNOWN.contains(&role) {
        return Ok(());
    }
    if role.len() > 32
        || !role
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!(
            "invalid role '{}'. Must be known or [a-z0-9_-] max 32 chars",
            role
        );
    }
    Ok(())
}

/// Validate Telegram bot token: {8-12 digits}:{35 alphanum/dash/underscore}.
pub fn validate_telegram_token(token: &str) -> Result<()> {
    let parts: Vec<&str> = token.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid Telegram token (expected <digits>:<hash>)");
    }
    let (id_part, hash_part) = (parts[0], parts[1]);
    if !id_part.chars().all(|c| c.is_ascii_digit()) || id_part.len() < 8 || id_part.len() > 12 {
        anyhow::bail!("invalid Telegram token: numeric ID must be 8-12 digits");
    }
    if hash_part.len() != 35
        || !hash_part
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!("invalid Telegram token: hash must be 35 alphanumeric chars");
    }
    Ok(())
}

pub(crate) fn get_os_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

pub(crate) fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(std::path::PathBuf::from))
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// Actionable "installed but not on PATH" guidance for an npm-installed
/// CLI. On Windows `npm i -g` writes a `.cmd` shim to `%APPDATA%\npm`,
/// which is NOT on PATH unless Node was installed via the official
/// installer — the #1 silent dead-end for a noob who used `winget install
/// OpenJS.NodeJS`. Give the exact shim path + a copy-paste PowerShell
/// command to add it to the user PATH. Non-Windows: the generic prefix hint.
#[cfg(feature = "wizard")]
pub(crate) fn npm_path_hint(binary: &str) -> String {
    if cfg!(windows) {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| "%APPDATA%".to_string());
        format!(
            "On Windows `npm i -g` writes the shim to {appdata}\\npm\\{binary}.cmd, which isn't on \
             PATH by default. Add it (PowerShell, then open a NEW terminal):\n      \
             [Environment]::SetEnvironmentVariable('Path', \
             [Environment]::GetEnvironmentVariable('Path','User') + ';' + \"$env:APPDATA\\npm\", 'User')"
        )
    } else {
        "Open a new shell, or check your npm prefix: `npm config get prefix` (its `bin/` must be on PATH)."
            .to_string()
    }
}

pub(crate) fn which_binary(name: &str) -> Option<String> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    let sep = if cfg!(windows) { ';' } else { ':' };
    // On Windows npm installs CLI shims as `<name>`, `<name>.cmd`, `<name>.ps1`.
    // CreateProcessW can only invoke .cmd/.bat/.exe directly — the bare
    // `<name>` script needs a shell. Prefer .cmd > .exe > .bat > bare.
    let extensions: &[&str] = if cfg!(windows) {
        &[".cmd", ".exe", ".bat", ""]
    } else {
        &[""]
    };
    for dir in path_var.split(sep) {
        for ext in extensions {
            let mut candidate = std::path::PathBuf::from(dir).join(name);
            if !ext.is_empty() {
                // PathBuf::set_extension would strip a trailing dot in name; use string append.
                candidate =
                    std::path::PathBuf::from(format!("{}{ext}", candidate.to_string_lossy()));
            }
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }
    None
}
