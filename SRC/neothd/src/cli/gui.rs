//! `neoth gui` — thin launcher for the separate `neothd-gui` Slint binary.
//!
//! The GUI ships as its OWN binary (`neothd-gui`) so the daemon/CLI stays
//! dependency-light (no Slint/wgpu linked into `neoth`). This subcommand
//! resolves that binary — a copy sitting next to the current `neoth`
//! executable first (the normal `cargo install` / release layout puts both
//! bins in the same dir), else a bare-name spawn the OS resolves via `PATH` —
//! and launches it so the onboarding-documented `neoth gui` command Just Works
//! under one roof instead of asking operators to know the second binary name.
//!
//! If the GUI isn't installed it prints the EXACT install command rather than a
//! raw OS spawn error. Deliberately thin: zero GUI code links here, so the CLI
//! footprint is unchanged and the launcher is headless-testable via `--locate`.

use std::path::PathBuf;
use std::process::Command;

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

/// Platform binary file name (`neothd-gui` on unix, `neothd-gui.exe` on win).
fn gui_bin_filename() -> String {
    format!("{GUI_BIN_STEM}{}", std::env::consts::EXE_SUFFIX)
}

/// Resolve the GUI binary sitting next to the current `neoth` executable — the
/// layout `cargo install` and the release archive both produce. Returns `None`
/// when the current exe can't be located or no sibling exists (the caller then
/// falls back to a bare-name spawn that the OS resolves through `PATH`).
fn sibling_gui_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join(gui_bin_filename());
    candidate.is_file().then_some(candidate)
}

/// Human/JSON description of where the launcher would find the GUI binary.
fn resolved_label(resolved: &Option<PathBuf>) -> String {
    resolved
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| format!("{} (resolved via PATH)", gui_bin_filename()))
}

pub fn run_gui(args: GuiArgs, output: OutputFormat) -> Result<()> {
    launch_gui(args, output, true)
}

/// Open the packaged GUI for the product's first desktop launch without
/// pre-selecting GUI. The GUI owns the exactly-once GUI-vs-CLI chooser and
/// persists the operator's answer only after they click a choice.
pub(crate) fn run_first_launch_chooser() -> Result<()> {
    launch_gui(GuiArgs::default(), OutputFormat::Table, false)
}

fn launch_gui(args: GuiArgs, output: OutputFormat, commit_gui_preference: bool) -> Result<()> {
    let resolved = sibling_gui_path();

    if args.locate {
        let found = resolved.is_some();
        let shown = resolved_label(&resolved);
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
                        "(not installed — `cargo install --path neothd-gui`, then `neoth gui`)"
                    );
                }
            }
        }
        return Ok(());
    }

    // Prefer the sibling path; else spawn by bare name and let the OS resolve
    // it through PATH. Inherit stdio — the GUI is an interactive foreground app
    // the operator just asked to open; spawn + detach (drop the handle) so
    // `neoth gui` returns immediately and the OS reparents the window.
    let program = resolved.unwrap_or_else(|| PathBuf::from(GUI_BIN_STEM));
    match Command::new(&program).spawn() {
        Ok(mut child) => {
            let pid = child.id();
            // Launch success is the commit point for an explicit CLI -> GUI
            // switch. The first-launch chooser is deliberately different: it
            // must observe a missing preference and records only the button the
            // operator actually selects inside the GUI.
            let preference_path = if commit_gui_preference {
                match interface_preference::save_default(InterfacePreference::Gui) {
                    Ok(path) => Some(path),
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error).context(
                            "GUI launch rolled back because the interface preference could not be persisted",
                        );
                    }
                }
            } else {
                None
            };
            drop(child);
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::json!({
                        "launched": true,
                        "pid": pid,
                        "binary": program.display().to_string(),
                        "preferred": commit_gui_preference.then_some("gui"),
                        "choice_required": !commit_gui_preference,
                        "preference_path": preference_path,
                    })
                ),
                OutputFormat::Table => println!("Launched {} (pid {pid}).", program.display()),
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
            "GUI binary `{}` not found. Install it with:\n    cargo install --path neothd-gui\nthen run `neoth gui` again.",
            gui_bin_filename()
        ),
        Err(e) => Err(e).context("failed to launch the NEOTH GUI (`neothd-gui`)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn resolved_label_distinguishes_path_vs_path_fallback() {
        let none = resolved_label(&None);
        assert!(none.contains("neothd-gui") && none.contains("PATH"));
        let some = resolved_label(&Some(PathBuf::from("/opt/neoth/neothd-gui")));
        assert!(some.contains("/opt/neoth/neothd-gui") && !some.contains("PATH"));
    }
}
