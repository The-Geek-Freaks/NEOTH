//! Public executable contract: v1 ships `neoth` and preserves `neothd` as a
//! compatibility launcher. The legacy name must delegate to the public binary,
//! so self-update has only one daemon implementation to replace.

use std::process::Command;

#[test]
fn public_and_compatibility_binaries_report_the_same_version() {
    let public = Command::new(env!("CARGO_BIN_EXE_neoth"))
        .arg("--version")
        .output()
        .expect("run public neoth binary");
    let compatibility = Command::new(env!("CARGO_BIN_EXE_neothd"))
        .arg("--version")
        .output()
        .expect("run compatibility neothd binary");

    assert!(public.status.success(), "neoth --version failed");
    assert!(
        compatibility.status.success(),
        "neothd --version compatibility path failed"
    );
    assert_eq!(public.stdout, compatibility.stdout);
    assert_eq!(
        String::from_utf8_lossy(&public.stdout).trim(),
        "neoth 1.0.0"
    );
}

#[test]
fn provider_help_exposes_only_implemented_subcommands() {
    let output = Command::new(env!("CARGO_BIN_EXE_neoth"))
        .args(["provider", "--help"])
        .output()
        .expect("run provider help");

    assert!(output.status.success(), "neoth provider --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in ["list", "show", "known", "test"] {
        assert!(
            stdout
                .lines()
                .any(|line| line.trim_start().starts_with(command)),
            "implemented provider subcommand `{command}` missing from help: {stdout}"
        );
    }
    for placeholder in ["add", "remove"] {
        assert!(
            !stdout
                .lines()
                .any(|line| line.trim_start().starts_with(placeholder)),
            "placeholder provider subcommand `{placeholder}` leaked into public help: {stdout}"
        );
    }
}
