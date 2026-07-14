//! `neoth supervisor` — MV-01b prereq #3 operator surface.
//!
//! Installs / removes the OS-native process supervisor (systemd user
//! unit / launchd LaunchAgent / Windows Task Scheduler) that keeps
//! `neoth serve` running + auto-restarts it, so unattended self-update
//! can activate an operator-applied new binary. All user-scoped — no
//! root/admin.
//!
//! `loop` is the built-in restart wrapper the Windows Task Scheduler
//! `onlogon` task targets (Task Scheduler has no restart-on-crash for
//! user tasks). On Linux/macOS systemd/launchd restart natively, so the
//! loop is rarely the target there but is OS-agnostic.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::daemon::supervisor;

#[derive(Args, Debug, Clone)]
pub struct SupervisorArgs {
    #[command(subcommand)]
    pub action: SupervisorAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SupervisorAction {
    /// Install the OS-native supervisor (systemd user unit / launchd
    /// LaunchAgent / Windows Task) + enable it. User-scoped, no
    /// root/admin. After install, set `supervisor.enabled: true` in
    /// freedom.yaml (the wizard does this automatically) so the
    /// self-update task knows a supervisor is present.
    Install,
    /// Disable + remove the supervisor unit.
    Uninstall,
    /// Show the host's supervisor kind + whether it's installed + the
    /// freedom.yaml flag.
    Status,
    /// Built-in restart wrapper (the Windows Task Scheduler target):
    /// spawn `neoth serve` and relaunch it after every exit. Stop the
    /// wrapper through Task Scheduler or `supervisor uninstall`.
    Loop,
}

pub fn run_supervisor(args: SupervisorArgs) -> Result<()> {
    let exe = std::env::current_exe().context("locate current executable")?;
    let home = FreedomConfig::default_neoth_home();
    let config_home = config_home_dir();

    match args.action {
        SupervisorAction::Install => {
            let kind = supervisor::install(&exe, &config_home, &home)?;
            render_install(kind, &args.output);
            Ok(())
        }
        SupervisorAction::Uninstall => {
            supervisor::uninstall(&config_home, &home)?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::json!({ "uninstalled": true }));
                }
                OutputFormat::Table => println!("supervisor removed"),
            }
            Ok(())
        }
        SupervisorAction::Status => {
            let kind = supervisor::recommended_kind();
            let installed = supervisor::is_installed(&config_home, &home);
            let cfg_enabled = FreedomConfig::load_from_default_path_or_default()?
                .supervisor
                .enabled;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "kind": kind.as_str(),
                            "installed": installed,
                            "config_enabled": cfg_enabled,
                        })
                    );
                }
                OutputFormat::Table => {
                    println!("supervisor kind   : {}", kind.as_str());
                    println!("unit installed    : {installed}");
                    println!("freedom.yaml flag : supervisor.enabled = {cfg_enabled}");
                }
            }
            Ok(())
        }
        SupervisorAction::Loop => supervisor::run_supervisor_loop(&exe),
    }
}

fn render_install(kind: crate::config::SupervisorKind, output: &OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({ "installed": true, "kind": kind.as_str() })
            );
        }
        OutputFormat::Table => {
            println!("supervisor installed: {}", kind.as_str());
            println!(
                "Set `supervisor:\\n  enabled: true\\n  kind: {}` in freedom.yaml \
                 (or re-run `neoth init`) so self-update knows the daemon \
                 can auto-restart.",
                kind.as_str()
            );
        }
    }
}

/// The operator's config dir for the systemd user unit: `XDG_CONFIG_HOME`
/// when set, else `~/.config`. Other OSes ignore it (launchd uses the
/// home dir; Windows uses Task Scheduler, no path).
fn config_home_dir() -> std::path::PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return std::path::PathBuf::from(xdg);
        }
    }
    dirs_home().join(".config")
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}
