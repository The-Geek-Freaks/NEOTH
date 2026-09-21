//! Process-level W155 regression contract for the bounded citation CLI.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::process::{Command, Stdio};

fn field_set(value: &serde_json::Value) -> BTreeSet<&str> {
    value
        .as_object()
        .expect("receipt object")
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn ordinary_and_gui_offline_lookups_emit_typed_receipts_before_nonzero_without_authorizer_wal() {
    let cases = [
        ("ordinary", vec![]),
        ("gui-ready", vec!["--request-id", "gui-revision-7"]),
        (
            "gui-confirm",
            vec!["--request-id", "gui-revision-7", "--gui-approval-stdin"],
        ),
    ];

    for (label, gui_args) in cases {
        let temp = tempfile::tempdir().expect("isolated citation CLI fixture");
        let home = temp.path().join(format!("private NEOTH_HOME {label}"));
        std::fs::create_dir(&home).expect("create isolated NEOTH_HOME");

        let mut command = Command::new(env!("CARGO_BIN_EXE_neoth"));
        command
            .current_dir(temp.path())
            .env("NEOTH_HOME", &home)
            .env("NEOTH_LOG", "warn")
            .env("NO_COLOR", "1")
            .args([
                "--output",
                "json",
                "citation",
                "lookup",
                "--claim",
                "bound claim",
                "--doi",
                "10.1000/example",
                "--provider",
                "crossref",
            ])
            .args(gui_args)
            .arg("--offline");
        let output = command.output().expect("run real offline citation command");

        assert!(
            !output.status.success(),
            "{label}: offline cache miss must remain a command failure after its receipt"
        );
        let receipt: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout must contain one JSON receipt");
        assert_eq!(
            field_set(&receipt),
            BTreeSet::from([
                "attempts",
                "cache_read",
                "cache_write",
                "claim",
                "display",
                "providers",
                "result",
            ])
        );
        assert_eq!(receipt["claim"], "bound claim");
        assert_eq!(receipt["providers"], serde_json::json!(["crossref"]));
        assert_eq!(receipt["cache_read"], "miss");
        assert_eq!(receipt["cache_write"], "not_attempted");
        assert_eq!(receipt["result"]["status"], "unavailable");
        assert_eq!(receipt["result"]["provider"], "crossref");
        assert_eq!(receipt["result"]["state"]["kind"], "offline_cache_miss");
        assert!(receipt["display"].is_null());

        let attempts = receipt["attempts"].as_array().expect("attempt array");
        assert_eq!(attempts.len(), 1);
        let attempt = &attempts[0];
        assert_eq!(
            field_set(attempt),
            BTreeSet::from(["cache_read", "cache_write", "doi", "provider", "result"])
        );
        assert_eq!(attempt["provider"], "crossref");
        assert_eq!(attempt["doi"], "10.1000/example");
        assert_eq!(attempt["result"], receipt["result"]);
        assert_eq!(attempt["cache_read"], "miss");
        assert_eq!(attempt["cache_write"], "not_attempted");
        assert!(
            !home.join("wal").exists(),
            "{label}: offline cache miss must not construct the live authorizer or its WAL sink"
        );
    }
}
#[test]
fn gui_lookup_rejects_invalid_input_before_private_proof_or_authorizer() {
    let temp = tempfile::tempdir().expect("isolated invalid GUI citation fixture");
    let home = temp.path().join("private NEOTH_HOME");
    std::fs::create_dir(&home).expect("create isolated NEOTH_HOME");

    let output = Command::new(env!("CARGO_BIN_EXE_neoth"))
        .current_dir(temp.path())
        .env("NEOTH_HOME", &home)
        .env("NEOTH_LOG", "warn")
        .env("NO_COLOR", "1")
        .args([
            "--output",
            "json",
            "citation",
            "lookup",
            "--claim",
            "\n",
            "--doi",
            "10.1000/example",
            "--provider",
            "crossref",
            "--request-id",
            "gui-revision-7",
            "--gui-approval-stdin",
        ])
        .output()
        .expect("run real invalid GUI citation command");

    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "invalid input must not emit a receipt"
    );
    assert!(
        !home.join("wal").exists(),
        "invalid GUI input must not read a proof or construct an authorizer"
    );
}

#[test]
fn gui_decide_rejects_oversized_private_stdin_before_consent_mutation() {
    let temp = tempfile::tempdir().expect("isolated GUI decision fixture");
    let home = temp.path().join("private NEOTH_HOME");
    std::fs::create_dir(&home).expect("create isolated NEOTH_HOME");

    let mut child = Command::new(env!("CARGO_BIN_EXE_neoth"))
        .current_dir(temp.path())
        .env("NEOTH_HOME", &home)
        .env("NEOTH_LOG", "warn")
        .env("NO_COLOR", "1")
        .args([
            "--output",
            "json",
            "citation",
            "gui-decide",
            "--claim",
            "bound claim",
            "--doi",
            "10.1000/example",
            "--provider",
            "crossref",
            "--request-id",
            "gui-revision-7",
            "--decision",
            "approve",
            "--approval-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start real GUI citation decision command");
    child
        .stdin
        .as_mut()
        .expect("private stdin")
        .write_all(&vec![b'x'; 257])
        .expect("write oversized private envelope");
    drop(child.stdin.take());
    let output = child
        .wait_with_output()
        .expect("wait for GUI citation decision");

    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "invalid private envelope must not emit a receipt"
    );
    assert!(
        !home.join("consent").exists() && !home.join("wal").exists(),
        "invalid private envelope must not create consent state or an authorizer WAL sink"
    );
}