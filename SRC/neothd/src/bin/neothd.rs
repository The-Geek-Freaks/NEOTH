//! Compatibility launcher for deployments that still invoke `neothd`.
//!
//! The implementation deliberately delegates to the sibling `neoth` binary.
//! Keeping a second copy of the daemon here would let self-update refresh the
//! public executable while old services continued running stale code.

use std::process::Command;

fn main() {
    if let Err(error) = neothd::updater::release_bundle::recover_running_portable_transaction() {
        eprintln!("neothd compatibility launcher could not recover its installation: {error:#}");
        std::process::exit(1);
    }
    let sibling = std::env::current_exe().ok().map(|mut path| {
        path.set_file_name(if cfg!(windows) { "neoth.exe" } else { "neoth" });
        path
    });
    let executable = sibling
        .filter(|path| path.is_file())
        .unwrap_or_else(|| "neoth".into());
    let mut command = Command::new(&executable);
    command.args(std::env::args_os().skip(1));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let error = command.exec();
        eprintln!("neothd compatibility launcher could not execute neoth: {error}");
        std::process::exit(127);
    }

    #[cfg(not(unix))]
    match command.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(error) => {
            eprintln!("neothd compatibility launcher could not execute neoth: {error}");
            std::process::exit(1);
        }
    }
}
