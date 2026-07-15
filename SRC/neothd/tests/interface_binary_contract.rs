//! Installed-product contract for the bare `neoth` launcher.
//!
//! These tests cross the real binary boundary: an explicit first choice must
//! be durable in the selected instance home, a later bare launch must not ask
//! again, and a malformed environment override must fail without mutating the
//! last valid choice.

use std::path::Path;
use std::process::{Command, Output};

const TEST_OPERATOR: &str = "gui-contract-test";

fn run_bare(home: &Path, interface: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_neoth"));
    command.env("NEOTH_HOME", home).env("NO_COLOR", "1");
    match interface {
        Some(value) => {
            command.env("NEOTH_INTERFACE", value);
        }
        None => {
            command.env_remove("NEOTH_INTERFACE");
        }
    }
    command.output().expect("run the public bare neoth binary")
}

fn run_bare_relative(workdir: &Path, relative_home: &Path, interface: Option<&str>) -> Output {
    assert!(relative_home.is_relative());
    let mut command = Command::new(env!("CARGO_BIN_EXE_neoth"));
    command
        .current_dir(workdir)
        .env("NEOTH_HOME", relative_home)
        .env("NO_COLOR", "1");
    match interface {
        Some(value) => {
            command.env("NEOTH_INTERFACE", value);
        }
        None => {
            command.env_remove("NEOTH_INTERFACE");
        }
    }
    command
        .output()
        .expect("run public bare neoth binary with relative NEOTH_HOME")
}

fn write_valid_config(home: &Path) {
    let mut config = neothd::config::FreedomConfig::default();
    config.operator_id = Some(TEST_OPERATOR.to_string());
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&config).unwrap(),
    )
    .unwrap();
}

fn write_marker(home: &Path, operator: &str, steps_completed: &[u8]) {
    let marker = serde_json::json!({
        "wizard_version": 2,
        "neoth_version": env!("CARGO_PKG_VERSION"),
        "operator_id": operator,
        "steps_completed": steps_completed,
        "init_time_unix": 1_700_000_000_u64,
        "init_time_iso8601": "2023-11-14T22:13:20Z",
        "provider_kind": null,
        "channels": [],
    });
    std::fs::write(
        home.join(".initialized"),
        serde_json::to_vec_pretty(&marker).unwrap(),
    )
    .unwrap();
}

fn write_legacy_v1_marker(home: &Path) {
    let marker = serde_json::json!({
        "wizard_version": 1,
        "operator_id": TEST_OPERATOR,
        "steps_completed": [1, 2, 3, 4, 5, 6, 7],
        "init_time_unix": 1_700_000_000_u64,
    });
    std::fs::write(
        home.join(".initialized"),
        serde_json::to_vec_pretty(&marker).unwrap(),
    )
    .unwrap();
}

fn write_valid_initialized_home(home: &Path) {
    write_valid_config(home);
    write_marker(home, TEST_OPERATOR, &[1, 2, 3, 4, 5, 6, 7, 8]);
}

fn write_cli_preference(home: &Path) {
    std::fs::write(
        home.join("interface.json"),
        b"{\n  \"schema_version\": 1,\n  \"preferred\": \"cli\"\n}\n",
    )
    .unwrap();
}

#[test]
fn bare_cli_choice_is_persisted_once_and_reused_by_the_next_process() {
    let home = tempfile::tempdir().unwrap();
    write_valid_initialized_home(home.path());

    let first = run_bare(home.path(), Some("cli"));
    assert!(
        first.status.success(),
        "first bare launch failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let preference_path = home.path().join("interface.json");
    let first_bytes = std::fs::read(&preference_path).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(record["schema_version"], 1);
    assert_eq!(record["preferred"], "cli");

    let second = run_bare(home.path(), None);
    assert!(
        second.status.success(),
        "second bare launch failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(String::from_utf8_lossy(&second.stdout).contains("NEOTH CLI is ready."));
    assert_eq!(std::fs::read(preference_path).unwrap(), first_bytes);
}

#[test]
fn malformed_environment_override_fails_without_overwriting_the_valid_choice() {
    let home = tempfile::tempdir().unwrap();
    write_valid_initialized_home(home.path());
    let initial = run_bare(home.path(), Some("cli"));
    assert!(initial.status.success());
    let preference_path = home.path().join("interface.json");
    let before = std::fs::read(&preference_path).unwrap();

    let invalid = run_bare(home.path(), Some("GUI"));
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("expected exactly `gui` or `cli`"));
    assert_eq!(std::fs::read(preference_path).unwrap(), before);
}

#[test]
fn gui_completed_home_with_cli_preference_enters_cli_home() {
    let home = tempfile::tempdir().unwrap();
    write_valid_initialized_home(home.path());
    write_cli_preference(home.path());
    let preference_path = home.path().join("interface.json");
    let before = std::fs::read(&preference_path).unwrap();

    let output = run_bare(home.path(), None);

    assert!(
        output.status.success(),
        "bare launch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("NEOTH CLI is ready."));
    assert_eq!(std::fs::read(preference_path).unwrap(), before);
}

#[test]
fn corrupt_existing_marker_fails_closed_without_overwriting_preference() {
    let home = tempfile::tempdir().unwrap();
    write_valid_initialized_home(home.path());
    write_cli_preference(home.path());
    std::fs::write(home.path().join(".initialized"), b"ready\n").unwrap();
    let preference_path = home.path().join("interface.json");
    let before = std::fs::read(&preference_path).unwrap();

    let output = run_bare(home.path(), Some("gui"));

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("initialization marker"), "stderr: {stderr}");
    assert!(stderr.contains("malformed"), "stderr: {stderr}");
    assert!(stderr.contains("neoth init --force"), "stderr: {stderr}");
    assert_eq!(std::fs::read(preference_path).unwrap(), before);
}

#[test]
fn legacy_gui_config_without_marker_is_ready() {
    let home = tempfile::tempdir().unwrap();
    write_valid_config(home.path());
    write_cli_preference(home.path());

    let output = run_bare(home.path(), None);

    assert!(
        output.status.success(),
        "legacy GUI-shaped launch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("NEOTH CLI is ready."));
    assert!(!home.path().join(".initialized").exists());
}

#[test]
fn legacy_v1_marker_and_config_remain_ready() {
    let home = tempfile::tempdir().unwrap();
    write_valid_config(home.path());
    write_legacy_v1_marker(home.path());
    write_cli_preference(home.path());

    let output = run_bare(home.path(), None);

    assert!(
        output.status.success(),
        "legacy v1 launch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("NEOTH CLI is ready."));
}

#[test]
fn relative_neoth_home_resolves_preference_in_the_child_working_directory() {
    let workdir = tempfile::tempdir().unwrap();
    let relative_home = Path::new("relative-neoth-home");
    let absolute_home = workdir.path().join(relative_home);
    std::fs::create_dir(&absolute_home).unwrap();
    write_valid_initialized_home(&absolute_home);

    let output = run_bare_relative(workdir.path(), relative_home, Some("cli"));

    assert!(
        output.status.success(),
        "relative-home launch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let preference_path = absolute_home.join("interface.json");
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(preference_path).unwrap()).unwrap();
    assert_eq!(record["preferred"], "cli");
}

#[test]
fn marker_without_config_fails_closed() {
    let home = tempfile::tempdir().unwrap();
    write_marker(home.path(), TEST_OPERATOR, &[1, 2, 3, 4, 5, 6, 7, 8]);
    write_cli_preference(home.path());
    let preference_path = home.path().join("interface.json");
    let before = std::fs::read(&preference_path).unwrap();

    let output = run_bare(home.path(), None);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("declares completed onboarding"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("freedom.yaml is missing"),
        "stderr: {stderr}"
    );
    assert_eq!(std::fs::read(preference_path).unwrap(), before);
}

#[test]
fn partial_marker_without_summary_fails_closed() {
    let home = tempfile::tempdir().unwrap();
    write_valid_config(home.path());
    write_marker(home.path(), TEST_OPERATOR, &[1]);
    write_cli_preference(home.path());

    let output = run_bare(home.path(), None);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("completed Summary step"),
        "stderr: {stderr}"
    );
}

#[test]
fn malformed_config_and_identity_mismatch_both_fail_closed() {
    let malformed = tempfile::tempdir().unwrap();
    write_marker(malformed.path(), TEST_OPERATOR, &[1, 2, 3, 4, 5, 6, 7, 8]);
    std::fs::write(malformed.path().join("freedom.yaml"), b"not: [yaml").unwrap();
    write_cli_preference(malformed.path());
    let malformed_output = run_bare(malformed.path(), None);
    assert!(!malformed_output.status.success());
    assert!(
        String::from_utf8_lossy(&malformed_output.stderr)
            .contains("existing initialization config")
    );

    let mismatched = tempfile::tempdir().unwrap();
    write_valid_config(mismatched.path());
    write_marker(
        mismatched.path(),
        "different-operator",
        &[1, 2, 3, 4, 5, 6, 7, 8],
    );
    write_cli_preference(mismatched.path());
    let mismatch_output = run_bare(mismatched.path(), None);
    assert!(!mismatch_output.status.success());
    assert!(
        String::from_utf8_lossy(&mismatch_output.stderr)
            .contains("initialization identity mismatch")
    );
}
