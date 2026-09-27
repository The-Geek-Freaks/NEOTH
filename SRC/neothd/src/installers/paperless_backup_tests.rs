use super::*;
use crate::installers::paperless_staging::PAPERLESS_VOLUMES;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Ready(AtomicBool);
#[async_trait::async_trait]
impl ReadinessVerifier for Ready {
    async fn ready(&self, _: &Path, _: &Credentials) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}
struct EventuallyReady(AtomicUsize);
impl EventuallyReady {
    fn new() -> Self {
        Self(AtomicUsize::new(0))
    }
    fn calls(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}
#[async_trait::async_trait]
impl ReadinessVerifier for EventuallyReady {
    async fn ready(&self, _: &Path, _: &Credentials) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst) >= 2
    }
}

/// A backup-specific Docker double.  Its inspect responses are stateful: an
/// exit-zero stop/start changes the next inspection, so coordinator tests do
/// not accidentally accept command status as source-state evidence.
struct StatefulBackupExecutor {
    running: BTreeMap<String, bool>,
    commands: Vec<Vec<String>>,
    fail_stop_without_transition: bool,
    fail_start_without_transition: bool,
    lose_copy_after_dispatch: bool,
    corrupt_readback: bool,
}
impl StatefulBackupExecutor {
    fn new(running: bool) -> Self {
        Self {
            running: ["webserver", "broker", "db"]
                .into_iter()
                .map(|s| (s.into(), running))
                .collect(),
            commands: vec![],
            fail_stop_without_transition: false,
            fail_start_without_transition: false,
            lose_copy_after_dispatch: false,
            corrupt_readback: false,
        }
    }
    fn mixed() -> Self {
        let mut f = Self::new(true);
        f.running.insert("broker".into(), false);
        f
    }
    fn streams(&self) -> usize {
        self.commands
            .iter()
            .filter(|c| c.iter().any(|p| p == "cp"))
            .count()
    }
    fn commands(&self, verb: &str) -> usize {
        self.commands
            .iter()
            .filter(|c| c.iter().any(|p| p == verb))
            .count()
    }
    fn effects(&self) -> bool {
        self.commands
            .iter()
            .any(|c| c.iter().any(|p| p == "stop" || p == "start" || p == "cp"))
    }
    fn service(id: &str) -> Result<&str, LifecycleError> {
        match id.as_bytes().first().copied() {
            Some(b'a') | Some(b'd') => Ok("webserver"),
            Some(b'b') | Some(b'e') => Ok("broker"),
            Some(b'c') | Some(b'f') => Ok("db"),
            _ => Err(LifecycleError::Container("fake_container")),
        }
    }
    fn inspect(&self, id: &str, cwd: &Path) -> Result<CommandOutput, LifecycleError> {
        let service = Self::service(id)?;
        let image = super::super::expected_images()?
            .into_iter()
            .find(|i| i.service == service)
            .ok_or(LifecycleError::Receipt)?;
        let config = image
            .configs
            .get("linux/amd64")
            .ok_or(LifecycleError::Receipt)?;
        let project = super::super::project_name(cwd);
        let port = super::super::dotenv_port(
            &std::fs::read(cwd.join("paperless.env")).map_err(|_| LifecycleError::Io)?,
        )?;
        let ports = if service == "webserver" {
            format!(r#"{{"8000/tcp":[{{"HostIp":"127.0.0.1","HostPort":"{port}"}}]}}"#)
        } else {
            "{}".into()
        };
        let mounts = paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .filter(|v| v.service == service)
            .map(|v| {
                format!(
                    r#"{{"Type":"volume","Name":"{}","Destination":"{}"}}"#,
                    super::super::volume_name(&project, v.logical_name),
                    v.destination
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        Ok(CommandOutput {
            stdout: format!(
                r#"{{"Id":"{id}","Image":"{config}","State":{{"Running":{}}},"Config":{{"Labels":{{"com.docker.compose.project":"{project}","com.docker.compose.service":"{service}"}}}},"HostConfig":{{"PortBindings":{ports}}},"NetworkSettings":{{"Ports":{ports}}},"Mounts":[{mounts}]}}"#,
                self.running[service]
            ),
        })
    }
    fn volume(&self, argv: &[String], cwd: &Path) -> Result<CommandOutput, LifecycleError> {
        if argv.iter().any(|p| p == "ls") {
            let project = super::super::project_name(cwd);
            return Ok(CommandOutput {
                stdout: paperless_staging::PAPERLESS_VOLUMES
                    .iter()
                    .map(|v| format!("{}\n", super::super::volume_name(&project, v.logical_name)))
                    .collect(),
            });
        }
        let name = argv
            .iter()
            .skip_while(|p| *p != "inspect")
            .nth(1)
            .ok_or(LifecycleError::Receipt)?;
        let volume = paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .find(|v| name.ends_with(v.logical_name))
            .ok_or(LifecycleError::Receipt)?;
        let snapshot: PaperlessVolumeSetSnapshot = serde_json::from_slice(
            &std::fs::read(cwd.join(RECEIPT_DIR).join(VOLUME_SET_NAME))
                .map_err(|_| LifecycleError::Receipt)?,
        )
        .map_err(|_| LifecycleError::Receipt)?;
        Ok(CommandOutput {
            stdout: format!(
                r#"{{"Name":"{name}","Labels":{{"com.docker.compose.project":"{}","com.docker.compose.volume":"{}","io.neoth.paperless.volume-set-id":"{}"}}}}"#,
                super::super::project_name(cwd),
                volume.logical_name,
                snapshot.volume_set_id
            ),
        })
    }
}
#[async_trait::async_trait]
impl ComposeExecutor for StatefulBackupExecutor {
    async fn run(&mut self, argv: &[String], cwd: &Path) -> Result<CommandOutput, LifecycleError> {
        self.commands.push(argv.to_vec());
        if argv.windows(2).any(|p| p[0] == "context" && p[1] == "show") {
            return Ok(CommandOutput {
                stdout: "desktop-linux\n".into(),
            });
        }
        if argv
            .windows(2)
            .any(|p| p[0] == "context" && p[1] == "inspect")
        {
            return Ok(CommandOutput {
                stdout: "\"npipe:////./pipe/docker_engine\"".into(),
            });
        }
        if argv.iter().any(|p| p == "version") {
            return Ok(CommandOutput {
                stdout: r#"{"Os":"linux","Arch":"amd64"}"#.into(),
            });
        }
        if argv.iter().any(|p| p == "volume") {
            return self.volume(argv, cwd);
        }
        if argv.iter().any(|p| p == "container") {
            let id = argv
                .iter()
                .skip_while(|p| *p != "inspect" && *p != "stop" && *p != "start")
                .nth(1)
                .ok_or(LifecycleError::Receipt)?;
            let service = Self::service(id)?.to_owned();
            if argv.iter().any(|p| p == "inspect") {
                return self.inspect(id, cwd);
            }
            if argv.iter().any(|p| p == "stop") {
                if !self.fail_stop_without_transition {
                    self.running.insert(service, false);
                }
                return Ok(CommandOutput {
                    stdout: String::new(),
                });
            }
            if argv.iter().any(|p| p == "start") {
                if !self.fail_start_without_transition {
                    self.running.insert(service, true);
                }
                return Ok(CommandOutput {
                    stdout: String::new(),
                });
            }
        }
        Ok(CommandOutput {
            stdout: String::new(),
        })
    }
    async fn run_stream_to_file(
        &mut self,
        argv: &[String],
        _: &Path,
        mut output: std::fs::File,
        limit: u64,
    ) -> Result<StreamedArchive, LifecycleError> {
        self.commands.push(argv.to_vec());
        if self.running.values().any(|running| *running) {
            return Err(LifecycleError::Command("copy_while_source_running"));
        }
        let cp = argv
            .iter()
            .position(|part| part == "cp")
            .ok_or(LifecycleError::Receipt)?;
        let source = argv.get(cp + 1).ok_or(LifecycleError::Receipt)?;
        let (_, mount) = source.split_once(':').ok_or(LifecycleError::Receipt)?;
        let volume = paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .find(|v| v.destination == mount)
            .ok_or(LifecycleError::Receipt)?;
        let bytes = format!("paperless-backup:{}", volume.logical_name).into_bytes();
        if bytes.len() as u64 > limit {
            return Err(LifecycleError::Command("fake_stream_limit"));
        }
        output.write_all(&bytes).map_err(|_| LifecycleError::Io)?;
        output.sync_all().map_err(|_| LifecycleError::Io)?;
        if self.corrupt_readback {
            output
                .write_all(b"changed-after-stream")
                .map_err(|_| LifecycleError::Io)?;
            output.sync_all().map_err(|_| LifecycleError::Io)?;
        }
        if self.lose_copy_after_dispatch {
            return Err(LifecycleError::Command("fake_stream_lost_after_dispatch"));
        }
        Ok(StreamedArchive {
            bytes: bytes.len() as u64,
            sha256: digest(&bytes),
        })
    }
}
fn receipt_path(home: &Path) -> PathBuf {
    crate::config::InstancePaths::for_home(home)
        .paperless_root
        .join("state")
        .join(RECEIPT_NAME)
}
fn state(home: &Path) -> PathBuf {
    crate::config::InstancePaths::for_home(home)
        .paperless_root
        .join("state")
}
fn receipt_count(state: &Path) -> usize {
    state
        .join("backups")
        .read_dir()
        .ok()
        .into_iter()
        .flatten()
        .filter(|e| {
            e.as_ref()
                .ok()
                .is_some_and(|e| e.path().join("receipt.v1.json").is_file())
        })
        .count()
}
fn source_path(home: &Path, job_id: &str) -> PathBuf {
    state(home)
        .join("backups")
        .join(job_id)
        .join(BACKUP_SOURCE_NAME)
}
fn completed_repair_journal(before: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let receipt: serde_json::Value = serde_json::from_slice(before).unwrap();
    let after = serde_json::to_vec(&receipt).unwrap();
    let members = receipt["containers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|container| {
            serde_json::json!({
                "service": container["service"].as_str().unwrap(),
                "prior_id": container["id"].as_str().unwrap(),
                "image_id": container["image_id"].as_str().unwrap(),
                "action": "healthy",
                "current_id": container["id"].as_str().unwrap(),
            })
        })
        .collect::<Vec<_>>();
    let journal = serde_json::json!({
        "schema_version": 1,
        "operation": "paperless.repair",
        "phase": "complete",
        "project": receipt["project"].as_str().unwrap(),
        "volume_set_id": receipt["volume_set_id"].as_str().unwrap(),
        "install_receipt_sha256": digest(before),
        "before_receipt_bytes": before,
        "after_receipt_bytes": after,
        "members": members,
        "effect_service": null,
    });
    (serde_json::to_vec(&journal).unwrap(), after)
}

#[tokio::test]
async fn coordinator_copies_the_exact_six_archives_and_restores_running_source() {
    let (home, credentials, install_bytes) =
        super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    let receipt = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    assert_eq!(receipt.install_receipt_sha256, digest(&install_bytes));
    assert_eq!(receipt.archives.len(), 6);
    assert!(receipt.original_running.iter().all(|s| s.running));
    assert_eq!(receipt.original_running, receipt.restored_running);
    assert!(receipt.authenticated_api_ready);
    assert_eq!(fake.streams(), 6);
    assert_eq!(fake.commands("stop"), 3);
    assert_eq!(fake.commands("start"), 3);
    assert!(fake.running.values().all(|v| *v));
    let unique: BTreeSet<_> = receipt
        .archives
        .iter()
        .map(|a| {
            (
                &a.logical_name,
                &a.service,
                &a.container_id,
                &a.mounted_source,
            )
        })
        .collect();
    assert_eq!(unique.len(), 6);
    for (archive, volume) in receipt.archives.iter().zip(PAPERLESS_VOLUMES) {
        let bytes =
            std::fs::read(home.path().join("paperless").join(&archive.archive_path)).unwrap();
        assert_eq!(
            (
                archive.logical_name.as_str(),
                archive.service.as_str(),
                archive.mounted_source.as_str()
            ),
            (volume.logical_name, volume.service, volume.destination)
        );
        let sha256 = digest(&bytes);
        assert_eq!(
            (archive.bytes, archive.sha256.as_str()),
            (bytes.len() as u64, sha256.as_str())
        );
    }
}
#[tokio::test]
async fn all_stopped_and_mixed_sources_are_returned_to_their_exact_original_state() {
    for mut fake in [
        StatefulBackupExecutor::new(false),
        StatefulBackupExecutor::mixed(),
    ] {
        let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
        let original = fake.running.clone();
        let receipt = backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(false)),
        )
        .await
        .unwrap();
        assert_eq!(fake.running, original);
        assert_eq!(receipt.original_running, receipt.restored_running);
        assert_eq!(
            receipt.authenticated_api_ready,
            original.values().all(|v| *v)
        );
        assert_eq!(fake.streams(), 6);
    }
}
#[tokio::test]
async fn backup_readiness_waits_after_source_restart_and_committed_receipt_reentry() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    let after_restart = EventuallyReady::new();
    let completed = backup_at_with(home.path(), &credentials, &mut fake, &after_restart)
        .await
        .unwrap();
    assert!(completed.authenticated_api_ready);
    assert_eq!(after_restart.calls(), 3);
    let streams = fake.streams();
    let stops = fake.commands("stop");
    let starts = fake.commands("start");
    let custody_path = state(home.path()).join(BACKUP_CUSTODY_NAME);
    let mut custody: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&custody_path).unwrap()).unwrap();
    custody["phase"] = serde_json::Value::String("archive_verified".into());
    custody["pending_start"] = serde_json::Value::Null;
    std::fs::write(&custody_path, serde_json::to_vec(&custody).unwrap()).unwrap();
    let committed_reentry = EventuallyReady::new();
    let resumed = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &committed_reentry,
    )
    .await
    .unwrap();
    assert_eq!(resumed.job_id, completed.job_id);
    assert_eq!(committed_reentry.calls(), 3);
    assert_eq!(fake.streams(), streams);
    assert_eq!(fake.commands("stop"), stops);
    assert_eq!(fake.commands("start"), starts);
}
#[tokio::test]
async fn exit_zero_stop_or_start_that_did_not_change_state_blocks_copy_or_receipt() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    fake.fail_stop_without_transition = true;
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(fake.streams(), 0);
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    fake.fail_start_without_transition = true;
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(receipt_count(&state(home.path())), 0);
}
#[tokio::test]
async fn ambiguous_copy_is_durably_held_and_reentry_never_dispatches_a_second_copy() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    fake.lose_copy_after_dispatch = true;
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(fake.streams(), 1);
    assert!(state(home.path()).join(BACKUP_CUSTODY_NAME).is_file());
    assert!(fake.running.values().all(|v| *v));
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(fake.streams(), 1);
}
#[tokio::test]
async fn corrupt_receipt_is_rejected_before_effects_and_readback_mismatch_restores_state() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    std::fs::write(receipt_path(home.path()), b"{}\n").unwrap();
    let mut fake = StatefulBackupExecutor::new(true);
    assert!(matches!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await,
        Err(LifecycleError::Receipt)
    ));
    assert!(!fake.effects());
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    fake.corrupt_readback = true;
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(fake.streams(), 1);
    assert!(fake.running.values().all(|v| *v));
}
#[tokio::test]
async fn corrupt_volume_set_snapshot_is_rejected_before_stop_copy_or_start() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    std::fs::write(state(home.path()).join(VOLUME_SET_NAME), b"{}\n").unwrap();
    let mut fake = StatefulBackupExecutor::new(true);
    assert!(matches!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await,
        Err(LifecycleError::Receipt)
    ));
    assert!(!fake.effects());
}
#[tokio::test]
async fn lock_and_failed_readiness_fence_receipt_and_effects() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let root = crate::config::InstancePaths::for_home(home.path()).paperless_root;
    let owned = paperless_staging::open_owned_root_at(&root).unwrap();
    let _guard =
        paperless_operation_lock::acquire(&owned, std::ffi::OsStr::new(OPERATIONS_LOCK_NAME))
            .unwrap();
    let mut fake = StatefulBackupExecutor::new(true);
    assert!(matches!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await,
        Err(LifecycleError::Command("paperless_operation_in_progress"))
    ));
    assert!(!fake.effects());
    drop(_guard);
    let mut fake = StatefulBackupExecutor::new(true);
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(false))
        )
        .await
        .is_err()
    );
    assert!(fake.running.values().all(|v| *v));
    assert_eq!(receipt_count(&state(home.path())), 0);
}
#[tokio::test]
async fn valid_complete_backup_uses_a_fresh_job_while_committed_receipt_reentry_does_not_recopy() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    let first = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let custody_path = state(home.path()).join(BACKUP_CUSTODY_NAME);
    let mut custody: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&custody_path).unwrap()).unwrap();
    custody["phase"] = serde_json::Value::String("archive_verified".into());
    std::fs::write(&custody_path, serde_json::to_vec(&custody).unwrap()).unwrap();
    let resumed = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    assert_eq!(resumed.job_id, first.job_id);
    assert_eq!(fake.streams(), 6);
    fake.running
        .values_mut()
        .for_each(|running| *running = false);
    let second = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(false)),
    )
    .await
    .unwrap();
    assert_ne!(second.job_id, first.job_id);
    assert!(second.original_running.iter().all(|state| !state.running));
    assert_eq!(fake.streams(), 12);
    assert_eq!(fake.commands("start"), 3);
    assert_eq!(receipt_count(&state(home.path())), 2);
}
#[tokio::test]
async fn tampered_committed_archive_and_incomplete_custody_hold_before_new_effects() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    let receipt = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    std::fs::write(
        home.path()
            .join("paperless")
            .join(&receipt.archives[0].archive_path),
        b"tampered",
    )
    .unwrap();
    // Keep phase Complete: a completed receipt is itself admission input and
    // must be checked before a fresh job is allocated.
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(fake.streams(), 6);
    assert_eq!(fake.commands("stop"), 3);
}
#[tokio::test]
async fn custody_traversal_or_foreign_archive_binding_is_rejected_before_a_new_effect() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    let _receipt = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let custody_path = state(home.path()).join(BACKUP_CUSTODY_NAME);
    let mut custody: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&custody_path).unwrap()).unwrap();
    custody["archives"][0]["archive_path"] = serde_json::Value::String("../../foreign.tar".into());
    custody["archives"][0]["container_id"] = serde_json::Value::String("f".repeat(64));
    std::fs::write(&custody_path, serde_json::to_vec(&custody).unwrap()).unwrap();
    assert!(matches!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await,
        Err(LifecycleError::Receipt)
    ));
    assert_eq!(fake.streams(), 6);
    assert_eq!(fake.commands("stop"), 3);
}
#[tokio::test]
async fn pending_start_crash_is_observed_without_replaying_the_uncertain_start() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    let receipt = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let custody_path = state(home.path()).join(BACKUP_CUSTODY_NAME);
    let mut custody: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&custody_path).unwrap()).unwrap();
    custody["phase"] = serde_json::Value::String("start_dispatched".into());
    custody["pending_start"] = serde_json::Value::String("webserver".into());
    std::fs::write(&custody_path, serde_json::to_vec(&custody).unwrap()).unwrap();
    std::fs::remove_file(
        home.path()
            .join("paperless")
            .join("state/backups")
            .join(&receipt.job_id)
            .join("receipt.v1.json"),
    )
    .unwrap();
    fake.running.insert("webserver".into(), false);
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(fake.commands("start"), 3);
    assert_eq!(fake.streams(), 6);
}
#[tokio::test]
async fn source_restored_with_six_archives_and_missing_receipt_commits_same_job_without_effect_replay()
 {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    let completed = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let source_path = source_path(home.path(), &completed.job_id);
    let source_before = std::fs::read(&source_path).unwrap();
    let custody_path = state(home.path()).join(BACKUP_CUSTODY_NAME);
    let mut custody: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&custody_path).unwrap()).unwrap();
    custody["phase"] = serde_json::Value::String("source_restored".into());
    custody["pending_start"] = serde_json::Value::Null;
    std::fs::write(&custody_path, serde_json::to_vec(&custody).unwrap()).unwrap();
    std::fs::remove_file(
        home.path()
            .join("paperless")
            .join("state/backups")
            .join(&completed.job_id)
            .join("receipt.v1.json"),
    )
    .unwrap();
    let resumed = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    assert_eq!(resumed.job_id, completed.job_id);
    assert_eq!(fake.streams(), 6);
    assert_eq!(fake.commands("stop"), 3);
    assert_eq!(fake.commands("start"), 3);
    assert_eq!(std::fs::read(source_path).unwrap(), source_before);
    assert!(
        home.path()
            .join("paperless")
            .join("state/backups")
            .join(&completed.job_id)
            .join("receipt.v1.json")
            .is_file()
    );
}
#[tokio::test]
async fn source_restored_with_partial_archives_cannot_commit_a_receipt() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    let completed = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let custody_path = state(home.path()).join(BACKUP_CUSTODY_NAME);
    let mut custody: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&custody_path).unwrap()).unwrap();
    custody["phase"] = serde_json::Value::String("source_restored".into());
    custody["archives"].as_array_mut().unwrap().pop();
    std::fs::write(&custody_path, serde_json::to_vec(&custody).unwrap()).unwrap();
    let receipt_path = home
        .path()
        .join("paperless")
        .join("state/backups")
        .join(&completed.job_id)
        .join("receipt.v1.json");
    std::fs::remove_file(&receipt_path).unwrap();
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(fake.streams(), 6);
    assert_eq!(fake.commands("stop"), 3);
    assert_eq!(fake.commands("start"), 3);
    assert!(!receipt_path.is_file());
}
#[tokio::test]
async fn historical_complete_repair_with_different_active_receipt_allows_backup() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let before = std::fs::read(receipt_path(home.path())).unwrap();
    let (journal, historical_after) = completed_repair_journal(&before);
    std::fs::write(
        state(home.path()).join(".neoth-paperless-repair.v1.json"),
        journal,
    )
    .unwrap();
    let different_active = [b"\n".as_slice(), historical_after.as_slice()].concat();
    assert_ne!(different_active, historical_after);
    std::fs::write(receipt_path(home.path()), different_active).unwrap();
    let mut fake = StatefulBackupExecutor::new(true);
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await
        .is_ok()
    );
    assert_eq!(fake.streams(), 6);
}
#[tokio::test]
async fn arbitrary_complete_repair_json_rejects_before_backup_effects() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    std::fs::write(
        state(home.path()).join(".neoth-paperless-repair.v1.json"),
        br#"{"phase":"complete"}"#,
    )
    .unwrap();
    let mut fake = StatefulBackupExecutor::new(true);
    assert!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert!(!fake.effects());
}
#[tokio::test]
async fn completed_backup_accepts_changed_active_receipt_and_preserves_first_immutable_receipt() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    let first = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let first_receipt_path = home
        .path()
        .join("paperless")
        .join("state/backups")
        .join(&first.job_id)
        .join("receipt.v1.json");
    let first_receipt_bytes = std::fs::read(&first_receipt_path).unwrap();
    let first_source_path = source_path(home.path(), &first.job_id);
    let first_source_bytes = std::fs::read(&first_source_path).unwrap();
    let first_source: BackupSource = serde_json::from_slice(&first_source_bytes).unwrap();
    let active = std::fs::read(receipt_path(home.path())).unwrap();
    assert_eq!(first_source.schema_version, 1);
    assert_eq!(first_source.operation, "paperless.backup.source");
    assert_eq!(first_source.job_id, first.job_id);
    assert_eq!(first_source.install_receipt_bytes, active);
    assert_eq!(
        first_source.volume_set_snapshot_bytes,
        std::fs::read(state(home.path()).join(VOLUME_SET_NAME)).unwrap()
    );
    let changed_active = [b"\n".as_slice(), active.as_slice()].concat();
    std::fs::write(receipt_path(home.path()), &changed_active).unwrap();
    let second = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    assert_ne!(second.job_id, first.job_id);
    assert_eq!(second.install_receipt_sha256, digest(&changed_active));
    assert_eq!(
        std::fs::read(&first_receipt_path).unwrap(),
        first_receipt_bytes
    );
    assert_eq!(std::fs::read(first_source_path).unwrap(), first_source_bytes);
    assert_eq!(fake.streams(), 12);
}
#[tokio::test]
async fn completed_backup_rejects_missing_tampered_or_foreign_source_companion_before_effects() {
    for mutation in ["missing", "tampered", "foreign"] {
        let (home, credentials, _) =
            super::super::tests::installed_home_for_uninstall_test().await;
        let mut fake = StatefulBackupExecutor::new(true);
        let receipt = backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true)),
        )
        .await
        .unwrap();
        let path = source_path(home.path(), &receipt.job_id);
        match mutation {
            "missing" => std::fs::remove_file(&path).unwrap(),
            "tampered" => std::fs::write(&path, b"{}\n").unwrap(),
            "foreign" => {
                let mut source: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                source["job_id"] = serde_json::Value::String(format!(
                    "paperless-backup-{}",
                    "f".repeat(64)
                ));
                std::fs::write(&path, serde_json::to_vec(&source).unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            backup_at_with(
                home.path(),
                &credentials,
                &mut fake,
                &Ready(AtomicBool::new(true))
            )
            .await,
            Err(LifecycleError::Receipt)
        ));
        assert_eq!(fake.streams(), 6, "{mutation}");
        assert_eq!(fake.commands("stop"), 3, "{mutation}");
        assert_eq!(fake.commands("start"), 3, "{mutation}");
    }
}
#[tokio::test]
async fn source_restored_with_receipt_but_missing_source_companion_rejects_without_recreation_or_effects()
{
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = StatefulBackupExecutor::new(true);
    let completed = backup_at_with(
        home.path(),
        &credentials,
        &mut fake,
        &Ready(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let custody_path = state(home.path()).join(BACKUP_CUSTODY_NAME);
    let mut custody: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&custody_path).unwrap()).unwrap();
    custody["phase"] = serde_json::Value::String("source_restored".into());
    custody["pending_start"] = serde_json::Value::Null;
    std::fs::write(&custody_path, serde_json::to_vec(&custody).unwrap()).unwrap();
    let source_path = source_path(home.path(), &completed.job_id);
    std::fs::remove_file(&source_path).unwrap();
    assert!(home
        .path()
        .join("paperless")
        .join("state/backups")
        .join(&completed.job_id)
        .join("receipt.v1.json")
        .is_file());
    let streams = fake.streams();
    let stops = fake.commands("stop");
    let starts = fake.commands("start");
    assert!(matches!(
        backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true))
        )
        .await,
        Err(LifecycleError::Command(
            "paperless_backup_source_companion_invalid"
        ))
    ));
    assert!(!source_path.is_file());
    assert_eq!(fake.streams(), streams);
    assert_eq!(fake.commands("stop"), stops);
    assert_eq!(fake.commands("start"), starts);
}
#[tokio::test]
async fn corrupt_interrupted_source_companion_restores_then_holds_without_copy_replay() {
    for phase in ["stopped", "archive_verified"] {
        let (home, credentials, _) =
            super::super::tests::installed_home_for_uninstall_test().await;
        let mut fake = StatefulBackupExecutor::new(true);
        let completed = backup_at_with(
            home.path(),
            &credentials,
            &mut fake,
            &Ready(AtomicBool::new(true)),
        )
        .await
        .unwrap();
        let custody_path = state(home.path()).join(BACKUP_CUSTODY_NAME);
        let mut custody: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&custody_path).unwrap()).unwrap();
        custody["phase"] = serde_json::Value::String(phase.into());
        custody["pending_start"] = serde_json::Value::Null;
        if phase == "stopped" {
            custody["archives"] = serde_json::Value::Array(vec![]);
        } else {
            std::fs::remove_file(
                home.path()
                    .join("paperless")
                    .join("state/backups")
                    .join(&completed.job_id)
                    .join("receipt.v1.json"),
            )
            .unwrap();
        }
        std::fs::write(&custody_path, serde_json::to_vec(&custody).unwrap()).unwrap();
        let source_path = source_path(home.path(), &completed.job_id);
        std::fs::write(&source_path, b"{}\n").unwrap();
        fake.running.values_mut().for_each(|running| *running = false);
        let streams = fake.streams();
        let stops = fake.commands("stop");
        let starts = fake.commands("start");
        assert!(matches!(
            backup_at_with(
                home.path(),
                &credentials,
                &mut fake,
                &Ready(AtomicBool::new(true))
            )
            .await,
            Err(LifecycleError::Command(
                "paperless_backup_source_companion_invalid"
            ))
        ));
        assert!(fake.running.values().all(|running| *running), "{phase}");
        assert_eq!(fake.streams(), streams, "{phase}");
        assert_eq!(fake.commands("stop"), stops, "{phase}");
        assert_eq!(fake.commands("start"), starts + 3, "{phase}");
        let held: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&custody_path).unwrap()).unwrap();
        assert_eq!(held["phase"], "held", "{phase}");
        assert_eq!(std::fs::read(&source_path).unwrap(), b"{}\n");
        assert!(matches!(
            backup_at_with(
                home.path(),
                &credentials,
                &mut fake,
                &Ready(AtomicBool::new(true))
            )
            .await,
            Err(LifecycleError::Receipt)
        ));
        assert_eq!(fake.streams(), streams, "{phase}");
        assert_eq!(fake.commands("stop"), stops, "{phase}");
        assert_eq!(fake.commands("start"), starts + 3, "{phase}");
    }
}
