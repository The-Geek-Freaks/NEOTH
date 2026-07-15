//! `neoth gui` — thin launcher for the separate `neothd-gui` Slint binary.
//!
//! The GUI ships as its OWN binary (`neothd-gui`) so the daemon/CLI stays
//! dependency-light (no Slint/wgpu linked into `neoth`). This subcommand
//! resolves the copy sitting next to the current `neoth` executable (the full
//! release layout puts both bins in the same dir) and launches it so the
//! onboarding-documented `neoth gui` command Just Works under one roof instead
//! of asking operators to know the second binary name. The launcher never
//! searches `PATH`: a different same-named program must not masquerade as the
//! GUI belonging to this NEOTH installation.
//!
//! If the GUI isn't installed it prints the EXACT install command rather than a
//! raw OS spawn error. Deliberately thin: zero GUI code links here, so the CLI
//! footprint is unchanged and the launcher is headless-testable via `--locate`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::interface_preference::{self, InterfacePreference};

#[derive(Args, Debug, Clone, Default)]
pub struct GuiArgs {
    /// Resolve + print the `neothd-gui` binary path (and whether it was found
    /// beside `neoth`) WITHOUT launching it. Diagnostic / scriptable /
    /// headless-safe — the launch path needs a display the CI box lacks.
    #[arg(long)]
    pub locate: bool,
}

/// Binary stem of the GUI app (without the platform executable suffix).
const GUI_BIN_STEM: &str = "neothd-gui";
const GUI_READY_FILE_ENV: &str = "NEOTH_GUI_READY_FILE";
const GUI_READY_TOKEN_ENV: &str = "NEOTH_GUI_READY_TOKEN";
const GUI_PARENT_COMMIT_ENV: &str = "NEOTH_GUI_PARENT_COMMIT";
const GUI_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const GUI_READY_POLL: std::time::Duration = std::time::Duration::from_millis(25);
const MAX_GUI_READY_BYTES: u64 = 256;
static GUI_HANDSHAKE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A GUI binary proven to be a file beside this exact `neoth` executable.
/// Carrying this type into the default-launch decision prevents a missing GUI
/// from becoming an optimistic bare-name `PATH` spawn later.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuiBinary(PathBuf);

impl GuiBinary {
    fn from_path(path: PathBuf) -> Self {
        Self(path)
    }

    fn as_path(&self) -> &Path {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GuiAvailability {
    Installed(GuiBinary),
    Missing,
}

#[cfg(test)]
pub(crate) fn installed_gui_for_test(path: PathBuf) -> GuiAvailability {
    GuiAvailability::Installed(GuiBinary::from_path(path))
}

struct GuiLaunchHandshake {
    directory: PathBuf,
    ready_path: PathBuf,
    token: String,
}

impl GuiLaunchHandshake {
    fn create(home: &Path) -> Result<Self> {
        use std::sync::atomic::Ordering;

        std::fs::create_dir_all(home)
            .with_context(|| format!("create NEOTH home {}", home.display()))?;
        let root = home.join(".gui-launch");
        let root_created = match std::fs::create_dir(&root) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(&root)
                    .with_context(|| format!("inspect {}", root.display()))?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "GUI handshake root {} is not a private directory",
                        root.display()
                    );
                }
                false
            }
            Err(error) => {
                return Err(error).with_context(|| format!("create {}", root.display()));
            }
        };
        if let Err(error) = set_private_gui_handshake_directory(&root) {
            if root_created {
                let _ = std::fs::remove_dir(&root);
            }
            return Err(error);
        }

        let epoch_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..16 {
            let counter = GUI_HANDSHAKE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let directory = root.join(format!(
                "gui-{:08x}-{epoch_nanos:032x}-{counter:016x}",
                std::process::id()
            ));
            match std::fs::create_dir(&directory) {
                Ok(()) => {
                    if let Err(error) = set_private_gui_handshake_directory(&directory) {
                        let _ = std::fs::remove_dir(&directory);
                        if root_created {
                            let _ = std::fs::remove_dir(&root);
                        }
                        return Err(error);
                    }
                    return Ok(Self {
                        ready_path: directory.join("ready"),
                        directory,
                        token: format!(
                            "{:08x}{epoch_nanos:032x}{counter:016x}",
                            std::process::id()
                        ),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    if root_created {
                        let _ = std::fs::remove_dir(&root);
                    }
                    return Err(error).with_context(|| format!("create {}", directory.display()));
                }
            }
        }
        if root_created {
            let _ = std::fs::remove_dir(&root);
        }
        anyhow::bail!("could not allocate a unique GUI handshake directory")
    }

    fn cleanup(self) -> Result<()> {
        let root = self.directory.parent().map(Path::to_path_buf);
        match std::fs::remove_dir_all(&self.directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("remove {}", self.directory.display()));
            }
        }
        if let Some(root) = root {
            let _ = std::fs::remove_dir(root);
        }
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_gui_handshake_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restrict GUI handshake directory {}", path.display()))
}

#[cfg(windows)]
fn set_private_gui_handshake_directory(path: &Path) -> Result<()> {
    crate::wal::win_native::set_private_current_user_directory_dacl(path)
        .with_context(|| format!("restrict GUI handshake directory {}", path.display()))
}

#[cfg(all(not(unix), not(windows)))]
fn set_private_gui_handshake_directory(path: &Path) -> Result<()> {
    let _ = path;
    Ok(())
}

fn finish_gui_handshake_result(
    directory: &Path,
    result: Result<()>,
    cleanup: Result<()>,
) -> Result<()> {
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_error)) => {
            tracing::warn!(
                error = %cleanup_error,
                path = %directory.display(),
                "GUI is ready; stale handshake cleanup failed"
            );
            Ok(())
        }
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(error).context(format!(
            "GUI launch failed and handshake cleanup also failed for {}: {cleanup_error:#}",
            directory.display()
        )),
    }
}

fn finish_gui_handshake(handshake: GuiLaunchHandshake, result: Result<()>) -> Result<()> {
    let directory = handshake.directory.clone();
    let cleanup = handshake.cleanup();
    finish_gui_handshake_result(&directory, result, cleanup)
}

fn gui_ready_token(path: &Path) -> Result<Option<Vec<u8>>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(MAX_GUI_READY_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > MAX_GUI_READY_BYTES {
        anyhow::bail!("GUI ready token at {} is oversized", path.display());
    }
    Ok(Some(bytes))
}

fn wait_for_gui_ready_with<ChildRunning>(
    ready_path: &Path,
    token: &str,
    timeout: std::time::Duration,
    mut child_running: ChildRunning,
) -> Result<()>
where
    ChildRunning: FnMut() -> Result<bool>,
{
    let started = std::time::Instant::now();
    loop {
        if !child_running()? {
            anyhow::bail!("GUI process exited before signalling readiness");
        }
        if let Some(bytes) = gui_ready_token(ready_path)? {
            if bytes != token.as_bytes() {
                anyhow::bail!("GUI returned a mismatched ready token");
            }
            if !child_running()? {
                anyhow::bail!("GUI process exited while signalling readiness");
            }
            return Ok(());
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            anyhow::bail!("GUI did not become ready within {} ms", timeout.as_millis());
        }
        std::thread::sleep(GUI_READY_POLL.min(timeout - elapsed));
    }
}

fn await_gui_ready(child: &mut Child, handshake: GuiLaunchHandshake) -> Result<()> {
    let result = wait_for_gui_ready_with(
        &handshake.ready_path,
        &handshake.token,
        GUI_READY_TIMEOUT,
        || match child.try_wait().context("query GUI process status")? {
            Some(status) => {
                tracing::warn!(%status, "GUI process exited before readiness");
                Ok(false)
            }
            None => Ok(true),
        },
    );
    let result = finish_gui_handshake(handshake, result);
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn commit_after_gui_ready_with<T>(
    ready: Result<()>,
    commit_gui_preference: bool,
    commit: impl FnOnce() -> Result<T>,
) -> Result<Option<T>> {
    ready?;
    if commit_gui_preference {
        commit().map(Some)
    } else {
        Ok(None)
    }
}

fn canonical_gui_home(configured: &Path) -> Result<PathBuf> {
    let current_dir = std::env::current_dir().context("resolve current directory")?;
    let configured = absolutize_gui_home(configured, &current_dir);
    std::fs::create_dir_all(&configured)
        .with_context(|| format!("create NEOTH home {}", configured.display()))?;
    configured
        .canonicalize()
        .with_context(|| format!("canonicalize NEOTH home {}", configured.display()))
}

fn absolutize_gui_home(configured: &Path, current_dir: &Path) -> PathBuf {
    if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        current_dir.join(configured)
    }
}

/// Platform binary file name (`neothd-gui` on unix, `neothd-gui.exe` on win).
fn gui_bin_filename() -> String {
    format!("{GUI_BIN_STEM}{}", std::env::consts::EXE_SUFFIX)
}

/// Resolve the GUI binary sitting next to the current `neoth` executable — the
/// layout produced by the full release installer. A core-only install is a
/// first-class `Missing` state; it never falls through to `PATH`.
pub(crate) fn gui_availability() -> GuiAvailability {
    let Some(executable) = std::env::current_exe().ok() else {
        return GuiAvailability::Missing;
    };
    gui_availability_beside(&executable)
}

fn gui_availability_beside(executable: &Path) -> GuiAvailability {
    let Some(directory) = executable.parent() else {
        return GuiAvailability::Missing;
    };
    let candidate = directory.join(gui_bin_filename());
    if candidate.is_file() {
        GuiAvailability::Installed(GuiBinary::from_path(candidate))
    } else {
        GuiAvailability::Missing
    }
}

/// Human/JSON description of where the launcher would find the GUI binary.
fn resolved_label(availability: &GuiAvailability) -> String {
    match availability {
        GuiAvailability::Installed(binary) => binary.as_path().display().to_string(),
        GuiAvailability::Missing => format!("{} (missing beside neoth)", gui_bin_filename()),
    }
}

pub(crate) fn missing_gui_error() -> anyhow::Error {
    anyhow::anyhow!(
        "GUI binary `{}` is not installed beside `neoth`. This is a core-only NEOTH installation: run `neoth init` to use the CLI, or repair/update NEOTH with the full installer to add the GUI. PATH entries are deliberately not used.",
        gui_bin_filename()
    )
}

pub fn run_gui(args: GuiArgs, output: OutputFormat) -> Result<()> {
    let availability = gui_availability();
    if args.locate {
        render_location(&availability, output);
        return Ok(());
    }
    let GuiAvailability::Installed(binary) = availability else {
        return Err(missing_gui_error());
    };
    launch_gui(binary, output, true)
}

/// Open the packaged GUI for the product's first desktop launch without
/// pre-selecting GUI. The GUI owns the exactly-once GUI-vs-CLI chooser and
/// persists the operator's answer only after they click a choice.
pub(crate) fn run_first_launch_chooser(binary: GuiBinary) -> Result<()> {
    launch_gui(binary, OutputFormat::Table, false)
}

pub(crate) fn run_installed_gui(binary: GuiBinary, output: OutputFormat) -> Result<()> {
    launch_gui(binary, output, true)
}

fn render_location(availability: &GuiAvailability, output: OutputFormat) {
    let found = matches!(availability, GuiAvailability::Installed(_));
    let shown = resolved_label(availability);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "binary": GUI_BIN_STEM,
                "resolved": shown,
                "found_beside_neoth": found,
            })
        ),
        OutputFormat::Table => {
            println!("GUI binary       : {shown}");
            println!("beside `neoth`   : {found}");
            if !found {
                println!(
                    "(GUI missing — the CLI remains available via `neoth init`; repair/update NEOTH with the full installer to add the GUI)"
                );
            }
        }
    }
}

fn launch_gui(binary: GuiBinary, output: OutputFormat, commit_gui_preference: bool) -> Result<()> {
    // The unique handshake makes the real Slint event loop, not a successful
    // spawn(), the interface-preference commit point.
    let program = binary.as_path();
    let home = canonical_gui_home(&crate::config::FreedomConfig::default_neoth_home())?;
    let handshake = GuiLaunchHandshake::create(&home)?;
    let mut command = Command::new(program);
    command
        .env("NEOTH_HOME", &home)
        .env(GUI_READY_FILE_ENV, &handshake.ready_path)
        .env(GUI_READY_TOKEN_ENV, &handshake.token)
        .env(
            GUI_PARENT_COMMIT_ENV,
            if commit_gui_preference { "1" } else { "0" },
        );
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let result = if error.kind() == std::io::ErrorKind::NotFound {
                Err(anyhow::anyhow!(
                    "GUI binary `{}` disappeared after it was detected beside `neoth`. Repair or update NEOTH with the full installer, then run `neoth gui` again.",
                    gui_bin_filename()
                ))
            } else {
                Err(anyhow::Error::new(error)
                    .context("failed to launch the NEOTH GUI (`neothd-gui`)"))
            };
            return finish_gui_handshake(handshake, result);
        }
    };
    let pid = child.id();
    let ready = await_gui_ready(&mut child, handshake);
    let preference_path = match commit_after_gui_ready_with(ready, commit_gui_preference, || {
        interface_preference::save_at(&home, InterfacePreference::Gui)
    }) {
        Ok(path) => path,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error)
                .context("GUI launch rolled back before the interface preference was committed");
        }
    };
    drop(child);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "launched": true,
                "ready": true,
                "pid": pid,
                "binary": program.display().to_string(),
                "preferred": commit_gui_preference.then_some("gui"),
                "choice_required": !commit_gui_preference,
                "preference_path": preference_path,
            })
        ),
        OutputFormat::Table => println!("Launched {} (pid {pid}; ready).", program.display()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn gui_bin_filename_carries_platform_suffix() {
        let name = gui_bin_filename();
        assert!(name.starts_with("neothd-gui"));
        // On Windows the suffix is `.exe`; elsewhere it's empty.
        assert!(name == "neothd-gui" || name == "neothd-gui.exe");
        assert!(name.ends_with(std::env::consts::EXE_SUFFIX));
    }

    #[test]
    fn locate_does_not_launch_and_is_ok() {
        // `--locate` must succeed in any environment (no display, no GUI
        // binary) precisely because it never spawns.
        run_gui(GuiArgs { locate: true }, OutputFormat::Table).expect("locate is infallible");
        run_gui(GuiArgs { locate: true }, OutputFormat::Json).expect("locate json is infallible");
    }

    #[test]
    fn availability_label_never_promises_a_path_fallback() {
        let missing = resolved_label(&GuiAvailability::Missing);
        assert!(missing.contains("neothd-gui") && missing.contains("missing"));
        assert!(!missing.contains("PATH"));

        let installed = resolved_label(&GuiAvailability::Installed(GuiBinary::from_path(
            PathBuf::from("/opt/neoth/neothd-gui"),
        )));
        assert!(installed.contains("/opt/neoth/neothd-gui"));
        assert!(!installed.contains("PATH"));
    }

    #[test]
    fn sibling_availability_requires_a_real_file() {
        let installation = tempfile::tempdir().unwrap();
        let executable = installation
            .path()
            .join(format!("neoth{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&executable, b"cli").unwrap();

        assert_eq!(
            gui_availability_beside(&executable),
            GuiAvailability::Missing
        );

        let gui = installation.path().join(gui_bin_filename());
        std::fs::write(&gui, b"gui").unwrap();
        assert_eq!(
            gui_availability_beside(&executable),
            GuiAvailability::Installed(GuiBinary::from_path(gui))
        );
    }

    #[test]
    fn explicit_gui_missing_error_is_actionable_and_rejects_path() {
        let error = missing_gui_error().to_string();
        assert!(error.contains("core-only NEOTH installation"));
        assert!(error.contains("neoth init"));
        assert!(error.contains("full installer"));
        assert!(error.contains("PATH entries are deliberately not used"));
    }

    #[test]
    fn gui_ready_wait_accepts_only_the_exact_live_child_token() {
        let home = tempfile::tempdir().unwrap();
        let handshake = GuiLaunchHandshake::create(home.path()).unwrap();
        std::fs::write(&handshake.ready_path, &handshake.token).unwrap();

        wait_for_gui_ready_with(
            &handshake.ready_path,
            &handshake.token,
            std::time::Duration::from_millis(10),
            || Ok(true),
        )
        .unwrap();
        let directory = handshake.directory.clone();
        finish_gui_handshake(handshake, Ok(())).unwrap();
        assert!(!directory.exists());
    }

    #[test]
    fn ready_gui_cleanup_failure_is_warning_not_false_launch_failure() {
        let directory = Path::new("stale-gui-handshake");
        finish_gui_handshake_result(
            directory,
            Ok(()),
            Err(anyhow::anyhow!("locked stale directory")),
        )
        .unwrap();

        let error = finish_gui_handshake_result(
            directory,
            Err(anyhow::anyhow!("GUI failed")),
            Err(anyhow::anyhow!("cleanup failed")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cleanup also failed"));
    }

    #[test]
    fn relative_gui_home_is_bound_to_an_absolute_current_directory() {
        let current_dir = tempfile::tempdir().unwrap();
        let home = absolutize_gui_home(Path::new("relative-home"), current_dir.path());
        assert!(home.is_absolute());
        assert_eq!(home, current_dir.path().join("relative-home"));
    }

    #[test]
    fn gui_ready_wait_rejects_mismatch_exit_and_timeout() {
        let home = tempfile::tempdir().unwrap();

        let mismatch = GuiLaunchHandshake::create(home.path()).unwrap();
        std::fs::write(&mismatch.ready_path, b"wrong").unwrap();
        let mismatch_dir = mismatch.directory.clone();
        let error = wait_for_gui_ready_with(
            &mismatch.ready_path,
            &mismatch.token,
            std::time::Duration::from_millis(10),
            || Ok(true),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("mismatched"));
        finish_gui_handshake(mismatch, Err(error)).unwrap_err();
        assert!(!mismatch_dir.exists());

        let exited = GuiLaunchHandshake::create(home.path()).unwrap();
        let exited_dir = exited.directory.clone();
        let error = wait_for_gui_ready_with(
            &exited.ready_path,
            &exited.token,
            std::time::Duration::from_millis(10),
            || Ok(false),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("exited"));
        finish_gui_handshake(exited, Err(error)).unwrap_err();
        assert!(!exited_dir.exists());

        let timeout = GuiLaunchHandshake::create(home.path()).unwrap();
        let timeout_dir = timeout.directory.clone();
        let error = wait_for_gui_ready_with(
            &timeout.ready_path,
            &timeout.token,
            std::time::Duration::from_millis(1),
            || Ok(true),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("did not become ready"));
        finish_gui_handshake(timeout, Err(error)).unwrap_err();
        assert!(!timeout_dir.exists());
    }

    #[test]
    fn failed_readiness_never_commits_interface_preference() {
        let commits = Cell::new(0);
        let result =
            commit_after_gui_ready_with::<()>(Err(anyhow::anyhow!("not ready")), true, || {
                commits.set(commits.get() + 1);
                Ok(())
            });
        assert!(result.is_err());
        assert_eq!(commits.get(), 0);

        commit_after_gui_ready_with(Ok(()), false, || {
            commits.set(commits.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(commits.get(), 0);
    }
}
