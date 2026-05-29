//! MV-01b prereq #3 — OS-native process supervisor install.
//!
//! `neoth serve` is a bare foreground process today: when it exits,
//! nothing relaunches it. Unattended self-update therefore can't
//! activate the new binary (the swap lands on disk, but the running
//! daemon keeps executing the old image until something restarts it).
//! This module installs a per-OS, **user-scoped (no root/admin)**
//! supervisor so the daemon survives logout + auto-restarts:
//!
//! - **Linux** — systemd USER unit + `loginctl enable-linger`.
//! - **macOS** — launchd LaunchAgent (`KeepAlive` + `RunAtLoad`).
//! - **Windows** — Task Scheduler `onlogon` task pointing at the
//!   built-in `neoth supervisor loop` restart wrapper (a bare
//!   `schtasks` task has no restart-on-crash; the loop provides it).
//!
//! The content generators are pure (unit-tested); `install` / `uninstall`
//! wrap them with the platform's enable/disable command. Everything is
//! user-scoped — the AIO "Alex's mom, no dev tools, no admin" rule.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub use crate::config::SupervisorKind;

/// macOS LaunchAgent label / launchd job name.
pub const LAUNCHD_LABEL: &str = "io.neoth.daemon";
/// Windows Task Scheduler task name.
pub const WINDOWS_TASK_NAME: &str = "NEOTH Daemon";
/// Exit code the supervisor treats as "deliberate stop — do NOT restart".
/// `neoth serve` returns this on an operator-initiated `neoth stop`.
/// Any other exit code = "restart me" (crash or self-update swap).
pub const EXIT_CODE_STOP: i32 = 2;

/// The supervisor kind native to the host OS. `None` on unknown targets.
pub fn recommended_kind() -> SupervisorKind {
    if cfg!(target_os = "linux") {
        SupervisorKind::SystemdUser
    } else if cfg!(target_os = "macos") {
        SupervisorKind::LaunchdAgent
    } else if cfg!(target_os = "windows") {
        SupervisorKind::WindowsTask
    } else {
        SupervisorKind::None
    }
}

// ── pure content generators (unit-tested) ──────────────────────────────

/// systemd user-unit text. `Restart=always` covers crash + self-update
/// exit; `RestartSec=3` lets the pidfile lock release first.
pub fn systemd_unit_text(exe: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=NEOTH daemon\n\
         After=default.target\n\
         \n\
         [Service]\n\
         ExecStart={exe} serve\n\
         Restart=always\n\
         RestartSec=3\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe = exe.display()
    )
}

/// launchd LaunchAgent plist. `KeepAlive` restarts on any exit;
/// `RunAtLoad` starts at login.
pub fn launchd_plist_text(exe: &Path, home: &Path) -> String {
    let out = home.join("neoth.stdout.log");
    let err = home.join("neoth.stderr.log");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key><string>{label}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array><string>{exe}</string><string>serve</string></array>\n\
         \t<key>KeepAlive</key><true/>\n\
         \t<key>RunAtLoad</key><true/>\n\
         \t<key>StandardOutPath</key><string>{out}</string>\n\
         \t<key>StandardErrorPath</key><string>{err}</string>\n\
         </dict>\n\
         </plist>\n",
        label = LAUNCHD_LABEL,
        exe = exe.display(),
        out = out.display(),
        err = err.display(),
    )
}

/// The `schtasks /create` argv for an onlogon task that runs the
/// built-in supervisor loop (`neoth supervisor loop`), which spawns +
/// restarts `neoth serve`. `/f` overwrites idempotently.
pub fn windows_task_argv(exe: &Path) -> Vec<String> {
    vec![
        "/create".into(),
        "/tn".into(),
        WINDOWS_TASK_NAME.into(),
        "/tr".into(),
        format!("\"{}\" supervisor loop", exe.display()),
        "/sc".into(),
        "onlogon".into(),
        "/f".into(),
    ]
}

// ── install paths ──────────────────────────────────────────────────────

/// systemd user-unit path under the operator's config dir. Falls back to
/// `~/.config/...` when `XDG_CONFIG_HOME` is unset.
pub fn systemd_unit_path(config_home: &Path) -> PathBuf {
    config_home
        .join("systemd")
        .join("user")
        .join("neoth.service")
}

/// launchd LaunchAgent plist path under the operator's home.
pub fn launchd_plist_path(home: &Path) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"))
}

/// `true` when this host already has the native supervisor installed.
/// File-existence check only (cheap; the wizard uses it for idempotency).
pub fn is_installed(config_home: &Path, home: &Path) -> bool {
    match recommended_kind() {
        SupervisorKind::SystemdUser => systemd_unit_path(config_home).exists(),
        SupervisorKind::LaunchdAgent => launchd_plist_path(home).exists(),
        // Windows task existence needs a `schtasks /query`; treated as
        // "unknown" here — the install path uses `/f` so re-install is
        // idempotent regardless.
        SupervisorKind::WindowsTask => false,
        SupervisorKind::None => false,
    }
}

/// Write the supervisor unit + enable it. User-scoped, no root/admin.
/// Returns the installed [`SupervisorKind`]. The actual enable command
/// (`systemctl --user` / `launchctl` / `schtasks`) is shelled out;
/// failures surface as `Err` with the command + stderr.
pub fn install(exe: &Path, config_home: &Path, home: &Path) -> Result<SupervisorKind> {
    let kind = recommended_kind();
    match kind {
        SupervisorKind::SystemdUser => {
            let path = systemd_unit_path(config_home);
            write_unit(&path, &systemd_unit_text(exe))?;
            run_cmd("loginctl", &["enable-linger".into(), current_user()])?;
            run_cmd(
                "systemctl",
                &[
                    "--user".into(),
                    "enable".into(),
                    "--now".into(),
                    "neoth".into(),
                ],
            )?;
        }
        SupervisorKind::LaunchdAgent => {
            let path = launchd_plist_path(home);
            write_unit(&path, &launchd_plist_text(exe, home))?;
            // Best-effort unload first so re-install doesn't error on an
            // already-loaded label.
            let _ = run_cmd("launchctl", &["unload".into(), path_str(&path)]);
            run_cmd("launchctl", &["load".into(), path_str(&path)])?;
        }
        SupervisorKind::WindowsTask => {
            run_cmd("schtasks", &windows_task_argv(exe))?;
        }
        SupervisorKind::None => {
            anyhow::bail!("no supported supervisor for this OS");
        }
    }
    Ok(kind)
}

/// Disable + remove the supervisor unit. Best-effort per-step so a
/// partially-installed state still cleans up.
pub fn uninstall(config_home: &Path, home: &Path) -> Result<()> {
    match recommended_kind() {
        SupervisorKind::SystemdUser => {
            let _ = run_cmd(
                "systemctl",
                &[
                    "--user".into(),
                    "disable".into(),
                    "--now".into(),
                    "neoth".into(),
                ],
            );
            let path = systemd_unit_path(config_home);
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("remove {}", path.display()))?;
            }
        }
        SupervisorKind::LaunchdAgent => {
            let path = launchd_plist_path(home);
            let _ = run_cmd("launchctl", &["unload".into(), path_str(&path)]);
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("remove {}", path.display()))?;
            }
        }
        SupervisorKind::WindowsTask => {
            run_cmd(
                "schtasks",
                &[
                    "/delete".into(),
                    "/tn".into(),
                    WINDOWS_TASK_NAME.into(),
                    "/f".into(),
                ],
            )?;
        }
        SupervisorKind::None => {}
    }
    Ok(())
}

/// Should the supervisor loop relaunch `neoth serve` given its exit
/// code? Everything except the deliberate-stop code restarts (a crash
/// or a self-update swap both exit non-2). A `None` code (killed by
/// signal) also restarts — a SIGKILL/console-close should bring the
/// daemon back.
pub fn should_restart(exit_code: Option<i32>) -> bool {
    exit_code != Some(EXIT_CODE_STOP)
}

/// The `neoth supervisor-loop` body: spawn `neoth serve` as a child,
/// wait, relaunch unless it exited with [`EXIT_CODE_STOP`]. This is the
/// target the Windows Task Scheduler `onlogon` task runs (Task Scheduler
/// has no restart-on-crash for user tasks; systemd/launchd provide it
/// natively, so this loop is primarily the Windows path but is OS-
/// agnostic). Never returns while restarts continue; returns `Ok(())`
/// after a deliberate stop.
pub fn run_supervisor_loop(exe: &Path) -> Result<()> {
    loop {
        let status = std::process::Command::new(exe)
            .arg("serve")
            .status()
            .with_context(|| format!("spawn {} serve", exe.display()))?;
        if !should_restart(status.code()) {
            tracing::info!(
                code = EXIT_CODE_STOP,
                "supervisor-loop: deliberate stop — not restarting"
            );
            return Ok(());
        }
        tracing::warn!(
            code = ?status.code(),
            "supervisor-loop: `neoth serve` exited; restarting in 3s"
        );
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}

// ── restart contract (MV-01b #5 follow) ───────────────────────────────
//
// After an operator-confirmed self-update swaps the binary on disk, the
// RUNNING daemon still executes the old image. With a supervisor
// installed, the daemon exits → the supervisor relaunches onto the new
// binary. The apply path drops a `restart.request` marker; the daemon's
// watcher consumes it + triggers a graceful drain+exit. Stop (as opposed
// to restart) goes through the supervisor's own command (`neoth
// supervisor uninstall` / `systemctl --user stop` / Task end), NOT an
// exit code — so a plain restart needs no exit-code juggling.

/// `~/.neoth/restart.request` — the cross-process "please restart"
/// marker the apply path writes + the daemon watcher consumes.
pub fn restart_request_path(neoth_home: &Path) -> PathBuf {
    neoth_home.join("restart.request")
}

/// Write the restart-request marker (apply path). Best-effort caller
/// decides; this returns the IO error so the CLI can warn.
pub fn request_restart(neoth_home: &Path) -> std::io::Result<()> {
    std::fs::write(restart_request_path(neoth_home), b"restart\n")
}

/// Consume the restart-request marker: returns `true` (and removes the
/// file) when a restart was requested, `false` otherwise. The daemon
/// watcher polls this.
pub fn take_restart_request(neoth_home: &Path) -> bool {
    let path = restart_request_path(neoth_home);
    if path.exists() {
        let _ = std::fs::remove_file(&path);
        true
    } else {
        false
    }
}

fn write_unit(path: &Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create supervisor dir {}", parent.display()))?;
    }
    std::fs::write(path, body).with_context(|| format!("write supervisor unit {}", path.display()))
}

fn path_str(p: &Path) -> String {
    p.display().to_string()
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn run_cmd(program: &str, args: &[String]) -> Result<()> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("spawn {program}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_has_restart_always_and_exec() {
        let txt = systemd_unit_text(Path::new("/home/alex/.cargo/bin/neoth"));
        assert!(txt.contains("ExecStart=/home/alex/.cargo/bin/neoth serve"));
        assert!(txt.contains("Restart=always"));
        assert!(txt.contains("WantedBy=default.target"));
    }

    #[test]
    fn launchd_plist_has_keepalive_and_runatload() {
        let txt = launchd_plist_text(
            Path::new("/usr/local/bin/neoth"),
            Path::new("/Users/alex/.neoth"),
        );
        assert!(txt.contains("<string>io.neoth.daemon</string>"));
        assert!(txt.contains("<key>KeepAlive</key><true/>"));
        assert!(txt.contains("<key>RunAtLoad</key><true/>"));
        assert!(txt.contains("/usr/local/bin/neoth"));
        // The log path is `home.join(...)`, so the separator is the
        // host's — assert the stable filename, not the full slash-path
        // (this test also runs on Windows builds).
        assert!(txt.contains("neoth.stdout.log"));
        assert!(txt.contains("neoth.stderr.log"));
    }

    #[test]
    fn windows_task_targets_supervisor_loop_with_force() {
        let argv = windows_task_argv(Path::new("C:\\neoth\\neoth.exe"));
        assert!(argv.iter().any(|a| a.contains("supervisor loop")));
        assert!(argv.contains(&"onlogon".to_string()));
        assert!(argv.contains(&"/f".to_string()));
        assert!(argv.contains(&WINDOWS_TASK_NAME.to_string()));
    }

    #[test]
    fn systemd_unit_path_is_user_scoped() {
        let p = systemd_unit_path(Path::new("/home/alex/.config"));
        assert!(p.ends_with("systemd/user/neoth.service"));
    }

    #[test]
    fn launchd_plist_path_is_user_scoped() {
        let p = launchd_plist_path(Path::new("/Users/alex"));
        assert!(p.ends_with("Library/LaunchAgents/io.neoth.daemon.plist"));
    }

    #[test]
    fn recommended_kind_matches_host_os() {
        let k = recommended_kind();
        if cfg!(target_os = "windows") {
            assert_eq!(k, SupervisorKind::WindowsTask);
        } else if cfg!(target_os = "linux") {
            assert_eq!(k, SupervisorKind::SystemdUser);
        } else if cfg!(target_os = "macos") {
            assert_eq!(k, SupervisorKind::LaunchdAgent);
        }
    }

    #[test]
    fn should_restart_only_skips_deliberate_stop_code() {
        assert!(
            !should_restart(Some(EXIT_CODE_STOP)),
            "stop code = no restart"
        );
        assert!(
            should_restart(Some(0)),
            "clean exit (self-update swap) = restart"
        );
        assert!(should_restart(Some(1)), "crash exit = restart");
        assert!(should_restart(Some(101)), "panic abort = restart");
        assert!(should_restart(None), "signal-killed = restart");
    }

    #[test]
    fn restart_request_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        // No marker yet.
        assert!(!take_restart_request(home));
        // Apply path writes it.
        request_restart(home).unwrap();
        assert!(restart_request_path(home).exists());
        // Watcher consumes it exactly once (removes the file).
        assert!(take_restart_request(home), "first take sees the request");
        assert!(!take_restart_request(home), "second take is clean");
        assert!(
            !restart_request_path(home).exists(),
            "marker removed on take"
        );
    }

    #[test]
    fn supervisor_kind_strings_stable() {
        assert_eq!(SupervisorKind::SystemdUser.as_str(), "systemd_user");
        assert_eq!(SupervisorKind::LaunchdAgent.as_str(), "launchd_agent");
        assert_eq!(SupervisorKind::WindowsTask.as_str(), "windows_task");
        assert_eq!(SupervisorKind::None.as_str(), "none");
    }
}
