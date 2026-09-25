use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::*;

struct UninstallFake {
    present: BTreeSet<String>,
    ids: BTreeMap<String, (String, String)>,
    ordered_ids: Vec<String>,
    commands: Vec<Vec<String>>,
    foreign_inspect_ids: BTreeSet<String>,
    fail_rm_after_remove_for: BTreeSet<String>,
    fail_rm_while_present_for: BTreeSet<String>,
    listing_error_ids: BTreeSet<String>,
    volume_set_id: Option<String>,
}

impl UninstallFake {
    fn from_receipt(bytes: &[u8]) -> Self {
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let mut ids = BTreeMap::new();
        let mut present = BTreeSet::new();
        let mut ordered_ids = Vec::new();
        for container in value["containers"].as_array().unwrap() {
            let id = container["id"].as_str().unwrap().to_owned();
            ids.insert(
                id.clone(),
                (
                    container["service"].as_str().unwrap().to_owned(),
                    container["image_id"].as_str().unwrap().to_owned(),
                ),
            );
            present.insert(id.clone());
            ordered_ids.push(id);
        }
        Self {
            present,
            ids,
            ordered_ids,
            commands: Vec::new(),
            foreign_inspect_ids: BTreeSet::new(),
            fail_rm_after_remove_for: BTreeSet::new(),
            fail_rm_while_present_for: BTreeSet::new(),
            listing_error_ids: BTreeSet::new(),
            volume_set_id: value["volume_set_id"].as_str().map(str::to_owned),
        }
    }

    fn remove_commands(&self) -> Vec<String> {
        self.commands
            .iter()
            .filter(|command| command.iter().any(|part| part == "rm"))
            .map(|command| command.last().unwrap().clone())
            .collect()
    }
}

#[async_trait]
impl ComposeExecutor for UninstallFake {
    async fn run(&mut self, argv: &[String], cwd: &Path) -> Result<CommandOutput, LifecycleError> {
        self.commands.push(argv.to_vec());
        if argv
            .windows(2)
            .any(|pair| pair[0] == "context" && pair[1] == "show")
        {
            return Ok(CommandOutput {
                stdout: "desktop-linux\n".into(),
            });
        }
        if argv
            .windows(2)
            .any(|pair| pair[0] == "context" && pair[1] == "inspect")
        {
            return Ok(CommandOutput {
                stdout: "\"npipe:////./pipe/docker_engine\"".into(),
            });
        }
        if argv.iter().any(|part| part == "version") {
            return Ok(CommandOutput {
                stdout: r#"{"Os":"linux","Arch":"amd64"}"#.into(),
            });
        }
        if argv.iter().any(|part| part == "volume") {
            let name = argv
                .iter()
                .skip_while(|part| *part != "inspect")
                .nth(1)
                .unwrap();
            let logical = paperless_staging::PAPERLESS_VOLUMES
                .iter()
                .find(|volume| name.ends_with(volume.logical_name))
                .unwrap();
            return Ok(CommandOutput {
                stdout: format!(
                    r#"{{"Name":"{name}","Labels":{{"com.docker.compose.project":"{}","com.docker.compose.volume":"{}"{}}}}}"#,
                    project_name(cwd),
                    logical.logical_name,
                    self.volume_set_id
                        .as_deref()
                        .map(|id| format!(r#",\"io.neoth.paperless.volume-set-id\":\"{id}\""#))
                        .unwrap_or_default()
                        .replace("\\\"", "\""),
                ),
            });
        }
        if argv.iter().any(|part| part == "container") && argv.iter().any(|part| part == "ls") {
            assert!(
                argv.iter().any(|part| part == "--no-trunc"),
                "exact ownership checks require an untruncated container ID"
            );
            let id = argv
                .iter()
                .find_map(|part| part.strip_prefix("id="))
                .unwrap();
            if self.listing_error_ids.contains(id) {
                return Err(LifecycleError::Command("fake_container_listing_error"));
            }
            return Ok(CommandOutput {
                stdout: if self.present.contains(id) {
                    format!("{id}\n")
                } else {
                    String::new()
                },
            });
        }
        if let Some(remove) = argv.iter().position(|part| part == "rm") {
            if argv.len() != remove + 3 || argv[remove + 1] != "-f" {
                return Err(LifecycleError::Command("fake_remove_shape"));
            }
            let id = argv.last().unwrap().clone();
            if !self.ids.contains_key(&id) {
                return Err(LifecycleError::Command("fake_remove_id"));
            }
            if self.fail_rm_while_present_for.contains(&id) {
                return Err(LifecycleError::Command("fake_rm_failure"));
            }
            self.present.remove(&id);
            if self.fail_rm_after_remove_for.contains(&id) {
                return Err(LifecycleError::Command("fake_rm_failure"));
            }
            return Ok(CommandOutput {
                stdout: String::new(),
            });
        }
        if argv.iter().any(|part| part == "container") {
            let id = argv
                .iter()
                .skip_while(|part| *part != "inspect")
                .nth(1)
                .unwrap();
            let (service, image) = self.ids.get(id).unwrap();
            let project = project_name(cwd);
            let service = if self.foreign_inspect_ids.contains(id) {
                "foreign"
            } else {
                service
            };
            let mounts = paperless_staging::PAPERLESS_VOLUMES
                .iter()
                .filter(|volume| volume.service == service)
                .map(|volume| {
                    format!(
                        r#"{{"Type":"volume","Name":"{}","Destination":"{}"}}"#,
                        volume_name(&project, volume.logical_name),
                        volume.destination
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let ports = if service == "webserver" {
                r#"{"8000/tcp":[{"HostIp":"127.0.0.1","HostPort":"18000"}]}"#
            } else {
                "{}"
            };
            return Ok(CommandOutput {
                stdout: format!(
                    r#"{{"Id":"{id}","Image":"{image}","State":{{"Running":false}},"Config":{{"Labels":{{"com.docker.compose.project":"{project}","com.docker.compose.service":"{service}"}}}},"NetworkSettings":{{"Ports":{ports}}},"Mounts":[{mounts}]}}"#
                ),
            });
        }
        Err(LifecycleError::Command("fake_unexpected"))
    }
}

fn custody_path(home: &Path) -> std::path::PathBuf {
    crate::config::InstancePaths::for_home(home)
        .paperless_root
        .join(RECEIPT_DIR)
        .join(UNINSTALL_RECEIPT_NAME)
}

async fn completed_custody_fixture() -> (tempfile::TempDir, Credentials, Vec<u8>, Vec<u8>) {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut fake = UninstallFake::from_receipt(&original);
    assert_eq!(
        uninstall_at_with(home.path(), &credentials, &mut fake)
            .await
            .unwrap()
            .phase,
        PaperlessUninstallPhase::Complete
    );
    let custody = std::fs::read(custody_path(home.path())).unwrap();
    (home, credentials, original, custody)
}

type CustodyMutation = fn(&mut serde_json::Value);

fn wrong_project(value: &mut serde_json::Value) {
    value["project"] = serde_json::Value::String("foreign-project".into());
}
fn wrong_operation(value: &mut serde_json::Value) {
    value["operation"] = serde_json::Value::String("other.operation".into());
}
fn wrong_schema(value: &mut serde_json::Value) {
    value["schema_version"] = serde_json::Value::from(3);
}
fn wrong_hash(value: &mut serde_json::Value) {
    value["install_receipt_sha256"] = serde_json::Value::String("0".repeat(64));
}
fn subset_ids(value: &mut serde_json::Value) {
    value["original_container_ids"]
        .as_array_mut()
        .unwrap()
        .pop();
}
fn duplicate_id(value: &mut serde_json::Value) {
    let id = value["original_container_ids"][0].clone();
    value["original_container_ids"][1] = id.clone();
    value["containers"][1]["id"] = id;
}
fn wrong_service(value: &mut serde_json::Value) {
    value["containers"][2]["service"] = serde_json::Value::String("foreign".into());
}
fn unremoved_complete(value: &mut serde_json::Value) {
    value["containers"][0]["removed"] = serde_json::Value::Bool(false);
}
fn dispatched_complete(value: &mut serde_json::Value) {
    value["dispatched_id"] = value["original_container_ids"][0].clone();
}
fn omitted_retained_volume(value: &mut serde_json::Value) {
    value["retained_volumes"].as_array_mut().unwrap().pop();
}

#[tokio::test]
async fn uninstall_success_removes_owned_stopped_containers_and_retains_six_volumes() {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut fake = UninstallFake::from_receipt(&original);
    let receipt = uninstall_at_with(home.path(), &credentials, &mut fake)
        .await
        .unwrap();
    assert_eq!(receipt.phase, PaperlessUninstallPhase::Complete);
    assert_eq!(
        receipt.retained_volumes.len(),
        paperless_staging::PAPERLESS_VOLUMES.len()
    );
    assert_eq!(
        std::fs::read(lifecycle_receipt_path(home.path())).unwrap(),
        original
    );
    assert!(fake.present.is_empty());
    assert_eq!(fake.remove_commands().len(), receipt.containers.len());
    assert!(
        !fake
            .commands
            .iter()
            .any(|command| command.iter().any(|part| part == "volume")
                && command.iter().any(|part| part == "rm"))
    );
}

#[tokio::test]
async fn legacy_unlabelled_install_receipt_remains_safe_uninstall_compatible() {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut legacy: serde_json::Value = serde_json::from_slice(&original).unwrap();
    legacy["schema_version"] = serde_json::Value::from(1);
    legacy.as_object_mut().unwrap().remove("volume_set_id");
    for volume in legacy["volumes"].as_array_mut().unwrap() {
        volume.as_object_mut().unwrap().remove("volume_set_id");
    }
    let legacy = serde_json::to_vec(&legacy).unwrap();
    std::fs::write(lifecycle_receipt_path(home.path()), &legacy).unwrap();
    std::fs::remove_file(
        crate::config::InstancePaths::for_home(home.path())
            .paperless_root
            .join(RECEIPT_DIR)
            .join(VOLUME_SET_NAME),
    )
    .unwrap();
    let mut fake = UninstallFake::from_receipt(&legacy);
    let receipt = uninstall_at_with(home.path(), &credentials, &mut fake)
        .await
        .unwrap();
    assert_eq!(receipt.schema_version, 1);
    assert_eq!(receipt.phase, PaperlessUninstallPhase::Complete);
    assert!(
        receipt
            .retained_volume_snapshot
            .iter()
            .all(|volume| volume.volume_set_id.is_none())
    );
    assert!(fake.present.is_empty());
}

#[tokio::test]
async fn completed_custody_tampering_rejects_before_docker_or_mutation() {
    let mutations: [(&str, CustodyMutation); 10] = [
        ("project", wrong_project),
        ("operation", wrong_operation),
        ("schema", wrong_schema),
        ("install_hash", wrong_hash),
        ("original_id_subset", subset_ids),
        ("duplicate_id", duplicate_id),
        ("service", wrong_service),
        ("unremoved_complete", unremoved_complete),
        ("dispatched_complete", dispatched_complete),
        ("retained_volume_omission", omitted_retained_volume),
    ];
    for (name, mutate) in mutations {
        let (home, credentials, original, completed) = completed_custody_fixture().await;
        let path = custody_path(home.path());
        let mut value: serde_json::Value = serde_json::from_slice(&completed).unwrap();
        mutate(&mut value);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut fake = UninstallFake::from_receipt(&original);

        assert!(
            uninstall_at_with(home.path(), &credentials, &mut fake)
                .await
                .is_err(),
            "{name}"
        );
        assert!(fake.commands.is_empty(), "{name} must reject before Docker");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "{name} must not rewrite custody"
        );
    }
}

#[tokio::test]
async fn prepared_custody_with_late_wrong_service_id_pair_rejects_before_any_remove() {
    let (home, credentials, original, completed) = completed_custody_fixture().await;
    let path = custody_path(home.path());
    let mut value: serde_json::Value = serde_json::from_slice(&completed).unwrap();
    value["phase"] = serde_json::Value::String("prepared".into());
    value["containers"][2]["removed"] = serde_json::Value::Bool(false);
    value["containers"][2]["service"] = serde_json::Value::String("foreign".into());
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let before = std::fs::read(&path).unwrap();
    let mut fake = UninstallFake::from_receipt(&original);

    assert!(
        uninstall_at_with(home.path(), &credentials, &mut fake)
            .await
            .is_err()
    );
    assert!(fake.commands.is_empty());
    assert_eq!(fake.remove_commands().len(), 0);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[tokio::test]
async fn status_rejects_malformed_and_foreign_custody_without_rewriting_it() {
    let (home, _credentials, _original, completed) = completed_custody_fixture().await;
    let path = custody_path(home.path());
    for bytes in [b"not-json".to_vec(), {
        let mut foreign: serde_json::Value = serde_json::from_slice(&completed).unwrap();
        wrong_project(&mut foreign);
        serde_json::to_vec(&foreign).unwrap()
    }] {
        std::fs::write(&path, &bytes).unwrap();
        assert!(uninstall_status_at(home.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[tokio::test]
async fn completed_uninstall_repeat_is_read_only_and_does_not_select_docker() {
    let (home, credentials, original, completed) = completed_custody_fixture().await;
    let mut fake = UninstallFake::from_receipt(&original);

    assert_eq!(
        uninstall_at_with(home.path(), &credentials, &mut fake)
            .await
            .unwrap()
            .phase,
        PaperlessUninstallPhase::Complete
    );
    assert!(fake.commands.is_empty());
    assert_eq!(std::fs::read(custody_path(home.path())).unwrap(), completed);
}

#[tokio::test]
async fn uninstall_missing_original_id_rejects_before_any_remove() {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut fake = UninstallFake::from_receipt(&original);
    let missing_id = fake.ordered_ids[0].clone();
    fake.present.remove(&missing_id);
    assert!(matches!(
        uninstall_at_with(home.path(), &credentials, &mut fake).await,
        Err(LifecycleError::Container(
            "paperless_uninstall_original_container_missing"
        ))
    ));
    assert!(fake.remove_commands().is_empty());
}

#[tokio::test]
async fn uninstall_listing_error_is_not_treated_as_observed_absence() {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut fake = UninstallFake::from_receipt(&original);
    let id = fake.ordered_ids[0].clone();
    fake.listing_error_ids.insert(id);

    assert!(matches!(
        uninstall_at_with(home.path(), &credentials, &mut fake).await,
        Err(LifecycleError::Command("fake_container_listing_error"))
    ));
    assert!(fake.remove_commands().is_empty());
}

#[tokio::test]
async fn uninstall_foreign_original_id_rejects_before_any_remove() {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut fake = UninstallFake::from_receipt(&original);
    let foreign_id = fake.ordered_ids[0].clone();
    fake.foreign_inspect_ids.insert(foreign_id);
    assert!(
        uninstall_at_with(home.path(), &credentials, &mut fake)
            .await
            .is_err()
    );
    assert!(fake.remove_commands().is_empty());
}

#[tokio::test]
async fn uninstall_failed_remove_after_actual_absence_reopens_without_second_remove() {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut fake = UninstallFake::from_receipt(&original);
    let first_id = fake.ordered_ids[0].clone();
    fake.fail_rm_after_remove_for.insert(first_id.clone());
    assert!(
        uninstall_at_with(home.path(), &credentials, &mut fake)
            .await
            .is_err()
    );
    assert_eq!(fake.remove_commands(), vec![first_id.clone()]);
    fake.fail_rm_after_remove_for.clear();
    let receipt = uninstall_at_with(home.path(), &credentials, &mut fake)
        .await
        .unwrap();
    assert_eq!(receipt.phase, PaperlessUninstallPhase::Complete);
    assert_eq!(
        fake.remove_commands()
            .iter()
            .filter(|id| *id == &first_id)
            .count(),
        1
    );
}

#[tokio::test]
async fn uninstall_failed_remove_with_present_container_holds_without_second_remove() {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut fake = UninstallFake::from_receipt(&original);
    let first_id = fake.ordered_ids[0].clone();
    fake.fail_rm_while_present_for.insert(first_id.clone());
    assert!(
        uninstall_at_with(home.path(), &credentials, &mut fake)
            .await
            .is_err()
    );
    let custody_path = crate::config::InstancePaths::for_home(home.path())
        .paperless_root
        .join(RECEIPT_DIR)
        .join(UNINSTALL_RECEIPT_NAME);
    let custody_before = std::fs::read(&custody_path).unwrap();
    let commands_before_status = fake.commands.len();
    assert_eq!(
        uninstall_status_at(home.path()).unwrap().unwrap().phase,
        PaperlessUninstallPhase::RemoveDispatched
    );
    assert_eq!(std::fs::read(&custody_path).unwrap(), custody_before);
    assert_eq!(fake.commands.len(), commands_before_status);
    fake.fail_rm_while_present_for.clear();
    assert!(matches!(
        uninstall_at_with(home.path(), &credentials, &mut fake).await,
        Err(LifecycleError::Command(
            "paperless_uninstall_remove_outcome_ambiguous"
        ))
    ));
    assert_eq!(fake.remove_commands(), vec![first_id]);
}

#[tokio::test]
async fn install_is_blocked_while_uninstall_custody_is_pending() {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut fake = UninstallFake::from_receipt(&original);
    let pending_id = fake.ordered_ids[0].clone();
    fake.fail_rm_while_present_for.insert(pending_id);
    assert!(
        uninstall_at_with(home.path(), &credentials, &mut fake)
            .await
            .is_err()
    );
    assert!(matches!(
        reinstall_for_uninstall_test(home.path(), &credentials).await,
        Err(LifecycleError::Command("paperless_uninstall_in_progress"))
    ));
}

#[tokio::test]
async fn completed_custody_does_not_apply_to_a_fresh_install_generation() {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut first_fake = UninstallFake::from_receipt(&original);
    assert_eq!(
        uninstall_at_with(home.path(), &credentials, &mut first_fake)
            .await
            .unwrap()
            .phase,
        PaperlessUninstallPhase::Complete
    );

    let fresh = reinstall_for_uninstall_test(home.path(), &credentials)
        .await
        .unwrap();
    let fresh_bytes = std::fs::read(lifecycle_receipt_path(home.path())).unwrap();
    assert_ne!(fresh_bytes, original);
    let mut second_fake = UninstallFake::from_receipt(&fresh_bytes);
    let second = uninstall_at_with(home.path(), &credentials, &mut second_fake)
        .await
        .unwrap();

    assert_eq!(second.phase, PaperlessUninstallPhase::Complete);
    assert_eq!(second_fake.remove_commands().len(), fresh.containers.len());
}

#[tokio::test]
async fn uninstall_partial_sequence_recovery_does_not_redelete_earlier_container() {
    let (home, credentials, original) = installed_home_for_uninstall_test().await;
    let mut fake = UninstallFake::from_receipt(&original);
    let first_id = fake.ordered_ids[0].clone();
    let later_id = fake.ordered_ids[1].clone();
    fake.fail_rm_after_remove_for.insert(later_id.clone());
    assert!(
        uninstall_at_with(home.path(), &credentials, &mut fake)
            .await
            .is_err()
    );
    assert_eq!(
        fake.remove_commands(),
        vec![first_id.clone(), later_id.clone()]
    );
    fake.fail_rm_after_remove_for.clear();
    let receipt = uninstall_at_with(home.path(), &credentials, &mut fake)
        .await
        .unwrap();
    assert_eq!(receipt.phase, PaperlessUninstallPhase::Complete);
    assert_eq!(
        fake.remove_commands()
            .iter()
            .filter(|id| *id == &first_id)
            .count(),
        1
    );
    assert_eq!(
        fake.remove_commands()
            .iter()
            .filter(|id| *id == &later_id)
            .count(),
        1
    );
}
