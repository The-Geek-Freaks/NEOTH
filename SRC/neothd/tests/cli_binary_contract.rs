//! Public executable contract: v1 ships `neoth` and preserves `neothd` as a
//! compatibility launcher. The legacy name must delegate to the public binary,
//! so self-update has only one daemon implementation to replace.

use std::process::Command;

#[test]
fn w107_json_status_preserves_stdout_with_text_and_json_diagnostics() {
    let temp = tempfile::tempdir().expect("isolated binary contract fixture");
    let root = temp.path().join("repository with spaces");
    let home = temp.path().join("private NEOTH_HOME");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&home).unwrap();

    for binary in [env!("CARGO_BIN_EXE_neoth"), env!("CARGO_BIN_EXE_neothd")] {
        for format in [None, Some("json"), Some("jsonl"), Some("ndjson")] {
            let mut command = Command::new(binary);
            command
                .current_dir(&root)
                .env("NEOTH_HOME", &home)
                .env("NEOTH_LOG", "neothd=info")
                .env("NO_COLOR", "1")
                .args(["--output", "json", "code-map", "status"])
                .arg(&root);
            if let Some(format) = format {
                command.env("NEOTH_LOG_FORMAT", format);
            } else {
                command.env_remove("NEOTH_LOG_FORMAT");
            }
            let output = command.output().expect("run real status binary");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "{binary} {format:?}: {stderr}");
            let status: serde_json::Value = serde_json::from_slice(&output.stdout)
                .expect("stdout must contain exactly one complete JSON document");
            assert_eq!(status["lifecycle"]["state"]["kind"], "absent");
            assert!(
                stderr.contains(neothd::BANNER),
                "diagnostics must remain observable on stderr: {stderr}"
            );
            if format.is_some() {
                for line in stderr.lines() {
                    let event: serde_json::Value =
                        serde_json::from_str(line).expect("structured diagnostic JSON line");
                    assert!(event.is_object());
                }
            }
            assert!(!home.join("code_map.db").exists());
        }
    }
}

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
