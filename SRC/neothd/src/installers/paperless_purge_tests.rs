use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::*;

struct PurgeFake {
    present_containers: BTreeSet<String>,
    container_data: BTreeMap<String, (String, String)>,
    volumes: BTreeSet<String>,
    commands: Vec<Vec<String>>,
    volume_set_id: String,
    omit_label_for: Option<String>,
    attached_volume: Option<String>,
    fail_remove_while_present_for: Option<String>,
    fail_remove_after_effect_for: Option<String>,
    fail_next_volume_list: bool,
}

impl PurgeFake {
    fn from_receipt(bytes: &[u8]) -> Self {
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let mut present_containers = BTreeSet::new();
        let mut container_data = BTreeMap::new();
        for container in value["containers"].as_array().unwrap() {
            let id = container["id"].as_str().unwrap().to_owned();
            present_containers.insert(id.clone());
            container_data.insert(
                id,
                (
                    container["service"].as_str().unwrap().to_owned(),
                    container["image_id"].as_str().unwrap().to_owned(),
                ),
            );
        }
        let project = value["project"].as_str().unwrap();
        let volumes = paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .map(|volume| volume_name(project, volume.logical_name))
            .collect();
        Self {
            present_containers,
            container_data,
            volumes,
            commands: Vec::new(),
            volume_set_id: value["volume_set_id"].as_str().unwrap().to_owned(),
            omit_label_for: None,
            attached_volume: None,
            fail_remove_while_present_for: None,
            fail_remove_after_effect_for: None,
            fail_next_volume_list: false,
        }
    }

    fn volume_remove_commands(&self) -> Vec<String> {
        self.commands
            .iter()
            .filter(|argv| argv.windows(2).any(|pair| pair == ["volume", "rm"]))
            .map(|argv| argv.last().unwrap().clone())
            .collect()
    }

    fn volume_json(&self, name: &str, cwd: &Path) -> Result<String, LifecycleError> {
        let logical = paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .find(|volume| name.ends_with(volume.logical_name))
            .ok_or(LifecycleError::Container("fake_purge_volume"))?;
        let generation = if self.omit_label_for.as_deref() == Some(name) {
            String::new()
        } else {
            format!(
                r#",\"io.neoth.paperless.volume-set-id\":\"{}\""#,
                self.volume_set_id
            )
        }
        .replace("\\\"", "\"");
        Ok(format!(
            r#"{{"Name":"{name}","Labels":{{"com.docker.compose.project":"{}","com.docker.compose.volume":"{}"{generation}}}}}"#,
            project_name(cwd),
            logical.logical_name
        ))
    }
}

#[async_trait]
impl ComposeExecutor for PurgeFake {
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
            if argv.iter().any(|part| part == "ls") {
                if self.fail_next_volume_list {
                    self.fail_next_volume_list = false;
                    return Err(LifecycleError::Command("fake_purge_volume_list"));
                }
                let filter = argv
                    .iter()
                    .find_map(|part| part.strip_prefix("name=^"))
                    .and_then(|part| part.strip_suffix('$'))
                    .ok_or(LifecycleError::Command("fake_purge_volume_list_shape"))?;
                return Ok(CommandOutput {
                    stdout: self
                        .volumes
                        .contains(filter)
                        .then(|| format!("{filter}\n"))
                        .unwrap_or_default(),
                });
            }
            if let Some(position) = argv.iter().position(|part| part == "rm") {
                if argv.len() != position + 2 || argv.iter().any(|part| part == "--force") {
                    return Err(LifecycleError::Command("fake_purge_volume_rm_shape"));
                }
                let name = argv.last().unwrap().clone();
                if self.fail_remove_while_present_for.as_deref() == Some(name.as_str()) {
                    return Err(LifecycleError::Command("fake_purge_volume_rm"));
                }
                if !self.volumes.remove(&name) {
                    return Err(LifecycleError::Command("fake_purge_volume_missing"));
                }
                if self.fail_remove_after_effect_for.as_deref() == Some(name.as_str()) {
                    self.fail_next_volume_list = true;
                    return Err(LifecycleError::Command("fake_purge_volume_rm"));
                }
                return Ok(CommandOutput {
                    stdout: String::new(),
                });
            }
            let name = argv
                .iter()
                .skip_while(|part| *part != "inspect")
                .nth(1)
                .ok_or(LifecycleError::Command("fake_purge_volume_inspect_shape"))?;
            if !self.volumes.contains(name) {
                return Err(LifecycleError::Command("fake_purge_volume_missing"));
            }
            return Ok(CommandOutput {
                stdout: self.volume_json(name, cwd)?,
            });
        }
        if argv.iter().any(|part| part == "container") && argv.iter().any(|part| part == "ls") {
            let filter = argv
                .iter()
                .find_map(|part| part.strip_prefix("id=").map(|id| ("id", id)))
                .or_else(|| {
                    argv.iter()
                        .find_map(|part| part.strip_prefix("volume=").map(|name| ("volume", name)))
                })
                .ok_or(LifecycleError::Command("fake_purge_container_list_shape"))?;
            let stdout = match filter {
                ("id", id) if self.present_containers.contains(id) => format!("{id}\n"),
                ("volume", name) if self.attached_volume.as_deref() == Some(name) => {
                    "f".repeat(64) + "\n"
                }
                _ => String::new(),
            };
            return Ok(CommandOutput { stdout });
        }
        if let Some(position) = argv.iter().position(|part| part == "rm") {
            if argv.len() != position + 3 || argv[position + 1] != "-f" {
                return Err(LifecycleError::Command("fake_purge_container_rm_shape"));
            }
            self.present_containers.remove(argv.last().unwrap());
            return Ok(CommandOutput {
                stdout: String::new(),
            });
        }
        if argv.iter().any(|part| part == "container") {
            let id = argv
                .iter()
                .skip_while(|part| *part != "inspect")
                .nth(1)
                .ok_or(LifecycleError::Command(
                    "fake_purge_container_inspect_shape",
                ))?;
            let (service, image) = self
                .container_data
                .get(id)
                .ok_or(LifecycleError::Command("fake_purge_container_missing"))?;
            let project = project_name(cwd);
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
        Err(LifecycleError::Command("fake_purge_unexpected"))
    }
}

async fn completed_fixture() -> (tempfile::TempDir, Credentials, Vec<u8>, PurgeFake) {
    let (home, credentials, install) = installed_home_for_uninstall_test().await;
    let mut fake = PurgeFake::from_receipt(&install);
    assert_eq!(
        uninstall_at_with(home.path(), &credentials, &mut fake)
            .await
            .unwrap()
            .phase,
        PaperlessUninstallPhase::Complete
    );
    (home, credentials, install, fake)
}

fn purge_custody_path(home: &Path) -> std::path::PathBuf {
    crate::config::InstancePaths::for_home(home)
        .paperless_root
        .join(RECEIPT_DIR)
        .join(PURGE_CUSTODY_NAME)
}

#[tokio::test]
async fn preview_is_read_only_and_uses_current_completed_receipt_chain() {
    let (home, _credentials, _install, fake) = completed_fixture().await;
    let command_count = fake.commands.len();
    let preview = paperless_purge::preview_at(home.path()).unwrap();
    assert_eq!(preview.state, PaperlessPurgeState::ConfirmationRequired);
    assert_eq!(
        preview.volumes.len(),
        paperless_staging::PAPERLESS_VOLUMES.len()
    );
    assert_eq!(preview.operation, PURGE_OPERATION);
    assert!(
        preview
            .confirmation
            .contains(&preview.install_receipt_sha256)
    );
    assert!(preview.confirmation.ends_with(&preview.volume_set_id));
    assert_eq!(fake.commands.len(), command_count);
    assert!(!purge_custody_path(home.path()).exists());
}

#[tokio::test]
async fn wrong_confirmation_rejects_before_lock_custody_or_docker() {
    let (home, _credentials, _install, mut fake) = completed_fixture().await;
    let command_count = fake.commands.len();
    assert!(matches!(
        paperless_purge::purge_at_with(home.path(), "wrong", &mut fake).await,
        Err(LifecycleError::Command(
            "paperless_purge_confirmation_mismatch"
        ))
    ));
    assert_eq!(fake.commands.len(), command_count);
    assert!(!purge_custody_path(home.path()).exists());
}

#[tokio::test]
async fn owner_lock_blocks_confirmed_purge_without_docker_selection() {
    let (home, _credentials, _install, mut fake) = completed_fixture().await;
    let command_count = fake.commands.len();
    let preview = paperless_purge::preview_at(home.path()).unwrap();
    let root_path = crate::config::InstancePaths::for_home(home.path()).paperless_root;
    let owned = paperless_staging::open_owned_root_at(&root_path).unwrap();
    let _held =
        paperless_operation_lock::acquire(&owned, OsStr::new(OPERATIONS_LOCK_NAME)).unwrap();
    assert!(matches!(
        paperless_purge::purge_at_with(home.path(), &preview.confirmation, &mut fake).await,
        Err(LifecycleError::Command("paperless_operation_in_progress"))
    ));
    assert_eq!(fake.commands.len(), command_count);
}

#[tokio::test]
async fn happy_path_removes_only_six_receipt_bound_volumes_and_keeps_credentials() {
    let (home, _credentials, _install, mut fake) = completed_fixture().await;
    let preview = paperless_purge::preview_at(home.path()).unwrap();
    let credential_path = home.path().join("credentials.yaml");
    // The wrapper fixture uses in-memory credentials; seed the disk preservation witness.
    std::fs::write(&credential_path, b"paperless_token: fixture-preserved-token\n").unwrap();
    let credentials_before = std::fs::read(&credential_path).unwrap();
    let receipt = paperless_purge::purge_at_with(home.path(), &preview.confirmation, &mut fake)
        .await
        .unwrap();
    assert_eq!(receipt.state, PaperlessPurgeState::VolumesRemoved);
    assert_eq!(
        receipt.volumes.len(),
        paperless_staging::PAPERLESS_VOLUMES.len()
    );
    assert!(
        receipt
            .volumes
            .iter()
            .all(|volume| volume.state == PaperlessPurgeVolumeState::AbsentVerified)
    );
    assert_eq!(
        fake.volume_remove_commands(),
        preview
            .volumes
            .iter()
            .map(|v| v.name.clone())
            .collect::<Vec<_>>()
    );
    assert!(fake.volumes.is_empty());
    assert_eq!(std::fs::read(credential_path).unwrap(), credentials_before);
}

#[tokio::test]
async fn missing_or_substituted_generation_label_blocks_all_volume_removes() {
    let (home, _credentials, _install, mut fake) = completed_fixture().await;
    let preview = paperless_purge::preview_at(home.path()).unwrap();
    fake.omit_label_for = Some(preview.volumes[3].name.clone());
    assert!(
        paperless_purge::purge_at_with(home.path(), &preview.confirmation, &mut fake)
            .await
            .is_err()
    );
    assert!(fake.volume_remove_commands().is_empty());
}

#[tokio::test]
async fn dispatched_after_effect_reconciles_absence_without_second_remove() {
    let (home, _credentials, _install, mut fake) = completed_fixture().await;
    let preview = paperless_purge::preview_at(home.path()).unwrap();
    let first = preview.volumes[0].name.clone();
    fake.fail_remove_after_effect_for = Some(first.clone());
    assert!(
        paperless_purge::purge_at_with(home.path(), &preview.confirmation, &mut fake)
            .await
            .is_err()
    );
    assert_eq!(fake.volume_remove_commands(), vec![first.clone()]);
    fake.fail_remove_after_effect_for = None;
    let receipt = paperless_purge::purge_at_with(home.path(), &preview.confirmation, &mut fake)
        .await
        .unwrap();
    assert_eq!(receipt.state, PaperlessPurgeState::VolumesRemoved);
    assert_eq!(
        fake.volume_remove_commands()
            .iter()
            .filter(|name| *name == &first)
            .count(),
        1
    );
}

#[tokio::test]
async fn repeat_completed_purge_reobserves_absence_but_never_removes_again() {
    let (home, _credentials, _install, mut fake) = completed_fixture().await;
    let preview = paperless_purge::preview_at(home.path()).unwrap();
    paperless_purge::purge_at_with(home.path(), &preview.confirmation, &mut fake)
        .await
        .unwrap();
    let removes = fake.volume_remove_commands();
    let receipt = paperless_purge::purge_at_with(home.path(), &preview.confirmation, &mut fake)
        .await
        .unwrap();
    assert_eq!(receipt.state, PaperlessPurgeState::VolumesRemoved);
    assert_eq!(fake.volume_remove_commands(), removes);
}
