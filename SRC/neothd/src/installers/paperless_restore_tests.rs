//! Restore coordinator regression contracts.
//!
//! The coordinator is injected through restore_at_with and ReadinessVerifier.
//! These contracts pin the durable lineage and exact-ID preconditions.

use super::*;

#[test]
fn restore_job_id_is_canonical_and_bounded() {
    assert!(valid_restore_job_id(
        "paperless-restore-01234567-89ab-cdef-0123-456789abcdef"
    ));
    assert!(!valid_restore_job_id("paperless-restore-../../escape"));
    assert!(!valid_restore_job_id(
        "paperless-restore-01234567-89ab-cdef-0123-456789abcdeg"
    ));
}

#[test]
fn backup_job_id_refuses_noncanonical_or_unbounded_input() {
    let canonical = format!("paperless-backup-{}", "a".repeat(64));
    assert!(valid_backup_job_id(&canonical));
    assert!(!valid_backup_job_id("paperless-backup-A"));
    assert!(!valid_backup_job_id(&format!("{canonical}x")));
}

fn committed_lineage() -> RestoreCustody {
    let backup_job_id = format!("paperless-backup-{}", "a".repeat(64));
    let restored_volume_set_id = "22222222-2222-2222-2222-222222222222".to_owned();
    let restore_project = restore_project_name(
        "neoth-paperless-123456789abc",
        &backup_job_id,
        &restored_volume_set_id,
    )
    .unwrap();
    RestoreCustody {
        schema_version: 1,
        operation: RESTORE_OPERATION.to_owned(),
        phase: RestorePhase::Committed,
        restore_job_id: "paperless-restore-01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        backup_job_id,
        base_project: "neoth-paperless-123456789abc".to_owned(),
        source_project: "neoth-paperless-123456789abc".to_owned(),
        source_volume_set_id: "11111111-1111-1111-1111-111111111111".to_owned(),
        restore_project,
        restored_volume_set_id,
        rollback_project: "neoth-paperless-123456789abc".to_owned(),
        rollback_volume_set_id: "11111111-1111-1111-1111-111111111111".to_owned(),
        authorized_volume_set_ids: vec![
            "22222222-2222-2222-2222-222222222222".to_owned(),
            "33333333-3333-3333-3333-333333333333".to_owned(),
        ],
        source_install_receipt_sha256: "a".repeat(64),
        source_install_receipt_bytes: vec![],
        prior_install_receipt_bytes: vec![],
        source_volume_set_snapshot_bytes: vec![],
        prior_volume_set_snapshot_bytes: vec![],
        archives: vec![],
        old_containers: vec![],
        candidate_container_ids: vec![],
        active_container_ids: vec![],
        committed_install_receipt_sha256: None,
        prior_active_pointer: None,
        rollback_restore_binding: None,
    }
}

fn schema3_receipt(
    project: &str,
    volume_set_id: &str,
    container_id: &str,
) -> StoredPaperlessInstallReceipt {
    StoredPaperlessInstallReceipt {
        schema_version: 3,
        operation: "install".to_owned(),
        contract_id: paperless_staging::OCI_CONTRACT_ID.to_owned(),
        project: project.to_owned(),
        loopback_port: 18000,
        images: vec![],
        containers: vec![StoredVerifiedContainer {
            service: "webserver".to_owned(),
            id: container_id.to_owned(),
            image_id: "sha256:changed".to_owned(),
        }],
        volumes: vec![],
        volume_set_id: Some(volume_set_id.to_owned()),
        authenticated_api_ready: true,
    }
}

#[test]
fn committed_restore_authorizes_repaired_and_successor_generations_but_not_forged_ones() {
    let custody = committed_lineage();
    let legacy = serde_json::to_value(&custody).unwrap();
    assert!(legacy.get("prior_active_pointer").is_none());
    assert!(legacy.get("rollback_restore_binding").is_none());
    let legacy_round_trip: RestoreCustody = serde_json::from_value(legacy).unwrap();
    assert_eq!(legacy_round_trip.schema_version, 1);
    assert!(legacy_round_trip.prior_active_pointer.is_none());
    assert!(legacy_round_trip.rollback_restore_binding.is_none());
    let pointer = RestoreActivePointer {
        schema_version: 1,
        operation: RESTORE_OPERATION.to_owned(),
        restore_job_id: custody.restore_job_id.clone(),
        custody_name: "immutable.json".into(),
        custody_sha256: "b".repeat(64),
        authorized_volume_set_ids: custody.authorized_volume_set_ids.clone(),
    };
    let repaired = schema3_receipt(
        &custody.restore_project,
        &custody.restored_volume_set_id,
        "replacement-after-repair",
    );
    let successor = schema3_receipt(
        &custody.restore_project,
        "33333333-3333-3333-3333-333333333333",
        "replacement-after-reinstall",
    );
    let forged_project = schema3_receipt(
        "neoth-paperless-forged",
        &custody.restored_volume_set_id,
        "new-id",
    );
    let forged_set = schema3_receipt(
        &custody.restore_project,
        "44444444-4444-4444-4444-444444444444",
        "new-id",
    );
    assert!(restore_receipt_identity_authorized(
        &custody, &pointer, &repaired
    ));
    assert!(restore_receipt_identity_authorized(
        &custody, &pointer, &successor
    ));
    assert!(!restore_receipt_identity_authorized(
        &custody,
        &pointer,
        &forged_project
    ));
    assert!(!restore_receipt_identity_authorized(
        &custody,
        &pointer,
        &forged_set
    ));
}

#[test]
fn candidate_service_lookup_is_exact_and_never_falls_back_to_another_container() {
    let ids = vec![
        format!("webserver:{}", "d".repeat(64)),
        format!("broker:{}", "e".repeat(64)),
        format!("db:{}", "f".repeat(64)),
    ];
    assert_eq!(
        candidate_id_for_service(&ids, "webserver").unwrap(),
        "d".repeat(64)
    );
    assert_eq!(
        candidate_id_for_service(&ids, "broker").unwrap(),
        "e".repeat(64)
    );
    assert!(candidate_id_for_service(&ids, "unknown").is_err());
}

#[test]
fn restore_generation_name_is_deterministic_and_bounded() {
    let backup = format!("paperless-backup-{}", "a".repeat(64));
    let volume_set = "01234567-89ab-cdef-0123-456789abcdef";
    let one = restore_project_name("neoth-paperless-123456789abc", &backup, volume_set).unwrap();
    assert_eq!(
        Some(one.clone()),
        restore_project_name("neoth-paperless-123456789abc", &backup, volume_set)
    );
    assert!(one.len() <= 63);
}

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

struct RestoreReady(AtomicBool);
#[async_trait::async_trait]
impl ReadinessVerifier for RestoreReady {
    async fn ready(&self, _: &Path, _: &Credentials) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Stateful Docker double: successful stop/start/up changes later inspection.
/// Each restore has distinct stopped candidate and loopback active ID sets.
struct RestoreFake {
    running: BTreeMap<String, bool>,
    commands: Vec<Vec<String>>,
    project: String,
    volume_set: String,
    candidate: bool,
    active: bool,
    lose_copy: bool,
    fail_ps: bool,
    removed: Vec<String>,
    generation: usize,
    candidate_ids: Vec<String>,
    active_ids: Vec<String>,
    id_projects: BTreeMap<String, String>,
    project_sets: BTreeMap<String, String>,
    stdin_failures: usize,
    stdin_calls: usize,
    stdin_fatal: bool,
}
impl RestoreFake {
    fn new(mixed: bool) -> Self {
        let mut running = BTreeMap::new();
        for (p, v) in [('a', true), ('b', !mixed), ('c', true)] {
            running.insert(p.to_string().repeat(64), v);
        }
        for p in ['d', 'e', 'f', '1', '2', '3', '4', '5', '6', '7', '8', '9'] {
            running.insert(p.to_string().repeat(64), false);
        }
        Self {
            running,
            commands: vec![],
            project: String::new(),
            volume_set: String::new(),
            candidate: false,
            active: false,
            lose_copy: false,
            fail_ps: false,
            removed: vec![],
            generation: 0,
            candidate_ids: vec![],
            active_ids: vec![],
            id_projects: BTreeMap::new(),
            project_sets: BTreeMap::new(),
            stdin_failures: 0,
            stdin_calls: 0,
            stdin_fatal: false,
        }
    }
    fn count(&self, name: &str) -> usize {
        self.commands
            .iter()
            .filter(|v| v.iter().any(|x| x == name))
            .count()
    }
    fn effects(&self) -> usize {
        self.commands
            .iter()
            .filter(|v| {
                v.iter()
                    .any(|x| matches!(x.as_str(), "create" | "up" | "cp" | "stop" | "rm" | "start"))
            })
            .count()
    }
    fn source_state(&self) -> Vec<bool> {
        ['a', 'b', 'c']
            .iter()
            .map(|p| self.running[&p.to_string().repeat(64)])
            .collect()
    }
    fn service(id: &str) -> Result<&'static str, LifecycleError> {
        match id.as_bytes().first() {
            Some(b'a' | b'd' | b'1' | b'4' | b'7') => Ok("webserver"),
            Some(b'b' | b'e' | b'2' | b'5' | b'8') => Ok("broker"),
            Some(b'c' | b'f' | b'3' | b'6' | b'9') => Ok("db"),
            _ => Err(LifecycleError::Receipt),
        }
    }
    fn id(&self, svc: &str) -> String {
        let i = match svc {
            "webserver" => 0,
            "broker" => 1,
            _ => 2,
        };
        if self.active {
            self.active_ids[i].clone()
        } else {
            self.candidate_ids[i].clone()
        }
    }
    fn inspect(&self, id: &str, cwd: &Path) -> Result<CommandOutput, LifecycleError> {
        if self.removed.iter().any(|known| known == id) {
            return Err(LifecycleError::Command("fake_container_absent"));
        }
        let service = Self::service(id)?;
        let image = expected_images()?
            .into_iter()
            .find(|i| i.service == service)
            .ok_or(LifecycleError::Receipt)?;
        let config = image
            .configs
            .get("linux/amd64")
            .ok_or(LifecycleError::Receipt)?;
        let source_project = project_name(cwd);
        let project = self.id_projects.get(id).unwrap_or(&source_project);
        let port = dotenv_port(
            &std::fs::read(cwd.join("paperless.env")).map_err(|_| LifecycleError::Io)?,
        )?;
        let publishes = matches!(id.as_bytes().first(), Some(b'a' | b'1' | b'7'));
        let ports = if service == "webserver" && publishes {
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
                    volume_name(project, v.logical_name),
                    v.destination
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        Ok(CommandOutput {
            stdout: format!(
                r#"{{"Id":"{id}","Image":"{config}","State":{{"Running":{}}},"Config":{{"Labels":{{"com.docker.compose.project":"{project}","com.docker.compose.service":"{service}"}}}},"HostConfig":{{"PortBindings":{ports}}},"NetworkSettings":{{"Ports":{ports}}},"Mounts":[{mounts}]}}"#,
                self.running.get(id).copied().unwrap_or(false)
            ),
        })
    }
    fn volume(&self, argv: &[String], cwd: &Path) -> Result<CommandOutput, LifecycleError> {
        if argv.iter().any(|x| x == "ls") {
            let name = argv
                .iter()
                .position(|x| x == "--filter")
                .and_then(|i| argv.get(i + 1))
                .and_then(|x| x.strip_prefix("name="))
                .ok_or(LifecycleError::Receipt)?;
            let source_project = project_name(cwd);
            let known = std::iter::once(&source_project)
                .chain(self.project_sets.keys())
                .any(|project| {
                    paperless_staging::PAPERLESS_VOLUMES
                        .iter()
                        .any(|v| name == volume_name(project, v.logical_name))
                });
            return Ok(CommandOutput {
                stdout: known.then(|| format!("{name}\n")).unwrap_or_default(),
            });
        }
        let name = argv
            .iter()
            .skip_while(|x| *x != "inspect")
            .nth(1)
            .ok_or(LifecycleError::Receipt)?;
        let source_project = project_name(cwd);
        let (project, spec) = std::iter::once(&source_project)
            .chain(self.project_sets.keys())
            .find_map(|project| {
                paperless_staging::PAPERLESS_VOLUMES
                    .iter()
                    .find(|v| name == &volume_name(project, v.logical_name))
                    .map(|spec| (project, spec))
            })
            .ok_or(LifecycleError::Receipt)?;
        let set = if let Some(set) = self.project_sets.get(project) {
            set.clone()
        } else {
            let bytes = std::fs::read(cwd.join(RECEIPT_DIR).join(VOLUME_SET_NAME))
                .map_err(|_| LifecycleError::Receipt)?;
            serde_json::from_slice::<PaperlessVolumeSetSnapshot>(&bytes)
                .map_err(|_| LifecycleError::Receipt)?
                .volume_set_id
        };
        Ok(CommandOutput {
            stdout: format!(
                r#"{{"Name":"{name}","Labels":{{"com.docker.compose.project":"{project}","com.docker.compose.volume":"{}","io.neoth.paperless.volume-set-id":"{set}"}}}}"#,
                spec.logical_name
            ),
        })
    }
}
#[async_trait::async_trait]
impl ComposeExecutor for RestoreFake {
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
        if argv.iter().any(|x| x == "version") {
            return Ok(CommandOutput {
                stdout: r#"{"Os":"linux","Arch":"amd64"}"#.into(),
            });
        }
        if argv.iter().any(|x| x == "image") {
            let r = argv
                .iter()
                .skip_while(|x| *x != "inspect")
                .nth(1)
                .ok_or(LifecycleError::Receipt)?;
            let i = expected_images()?
                .into_iter()
                .find(|i| i.reference == r)
                .ok_or(LifecycleError::Receipt)?;
            return Ok(CommandOutput {
                stdout: format!(
                    r#"{{"Id":"{}","RepoDigests":["{}"],"Os":"linux","Architecture":"amd64"}}"#,
                    i.configs["linux/amd64"], i.repo_digest
                ),
            });
        }
        if argv.iter().any(|x| x == "volume") {
            return self.volume(argv, cwd);
        }
        if argv.iter().any(|x| x == "container") {
            let id = argv
                .iter()
                .skip_while(|x| *x != "inspect" && *x != "stop" && *x != "start" && *x != "rm")
                .nth(1)
                .ok_or(LifecycleError::Receipt)?;
            if argv.iter().any(|x| x == "inspect") {
                return self.inspect(id, cwd);
            }
            if argv.iter().any(|x| x == "stop" || x == "rm") {
                self.running.insert(id.clone(), false);
            }
            if argv.iter().any(|x| x == "rm") {
                self.removed.push(id.clone());
            }
            if argv.iter().any(|x| x == "start") {
                self.running.insert(id.clone(), true);
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
        mut f: std::fs::File,
        limit: u64,
    ) -> Result<StreamedArchive, LifecycleError> {
        self.commands.push(argv.to_vec());
        let cp = argv
            .iter()
            .position(|x| x == "cp")
            .ok_or(LifecycleError::Receipt)?;
        let (_, dst) = argv
            .get(cp + 1)
            .ok_or(LifecycleError::Receipt)?
            .split_once(':')
            .ok_or(LifecycleError::Receipt)?;
        let spec = paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .find(|v| v.destination == dst)
            .ok_or(LifecycleError::Receipt)?;
        let b = format!("archive:{}", spec.logical_name).into_bytes();
        if b.len() as u64 > limit {
            return Err(LifecycleError::Receipt);
        }
        f.write_all(&b).map_err(|_| LifecycleError::Io)?;
        f.sync_all().map_err(|_| LifecycleError::Io)?;
        Ok(StreamedArchive {
            bytes: b.len() as u64,
            sha256: restore_digest(&b),
        })
    }
}
#[async_trait::async_trait]
impl RetainedComposeExecutor for RestoreFake {
    async fn run_with_stdin(
        &mut self,
        argv: &[String],
        _: &OwnedPaperlessRoot,
        _: Zeroizing<Vec<u8>>,
    ) -> Result<CommandOutput, LifecycleError> {
        self.commands.push(argv.to_vec());
        self.stdin_calls += 1;
        if self.stdin_fatal {
            return Err(LifecycleError::Command("paperless_stdin_spawn_failed"));
        }
        if self.stdin_failures > 0 {
            self.stdin_failures -= 1;
            return Err(LifecycleError::Command("paperless_stdin_failed"));
        }
        let web = self.id("webserver");
        if !argv.iter().any(|x| x == &web) || !self.running[&web] {
            return Err(LifecycleError::Command("candidate_auth_before_ready"));
        }
        Ok(CommandOutput {
            stdout: String::new(),
        })
    }
    async fn run_stream_from_file(
        &mut self,
        argv: &[String],
        _: &OwnedPaperlessRoot,
        mut f: std::fs::File,
        n: u64,
        digest: &str,
    ) -> Result<(), LifecycleError> {
        self.commands.push(argv.to_vec());
        if self.candidate_ids.iter().any(|id| self.running[id]) {
            return Err(LifecycleError::Command("copy_after_candidate_start"));
        }
        let mut b = vec![];
        f.read_to_end(&mut b).map_err(|_| LifecycleError::Io)?;
        if b.len() as u64 != n || restore_digest(&b) != digest {
            return Err(LifecycleError::Receipt);
        }
        if self.lose_copy {
            return Err(LifecycleError::Command("copy_outcome_ambiguous"));
        }
        Ok(())
    }
    async fn run_retained(
        &mut self,
        argv: &[String],
        root: &OwnedPaperlessRoot,
        binding: &EnvBinding,
    ) -> Result<CommandOutput, LifecycleError> {
        self.run_retained_with_compose(
            argv,
            root,
            binding,
            paperless_staging::render_compose_with_volume_set_id(
                binding
                    .volume_set_id
                    .as_deref()
                    .ok_or(LifecycleError::Receipt)?,
            )
            .ok_or(LifecycleError::Receipt)?,
        )
        .await
    }
    async fn run_retained_with_compose(
        &mut self,
        argv: &[String],
        _: &OwnedPaperlessRoot,
        _: &EnvBinding,
        input: Vec<u8>,
    ) -> Result<CommandOutput, LifecycleError> {
        self.commands.push(argv.to_vec());
        self.project = argv
            .iter()
            .position(|x| x == "--project-name")
            .and_then(|i| argv.get(i + 1))
            .cloned()
            .ok_or(LifecycleError::Receipt)?;
        let s = String::from_utf8(input).map_err(|_| LifecycleError::Receipt)?;
        self.volume_set = s
            .lines()
            .find_map(|l| l.trim().strip_prefix("io.neoth.paperless.volume-set-id: "))
            .unwrap_or_default()
            .into();
        if argv.iter().any(|x| x == "create") {
            self.generation += 1;
            self.candidate = true;
            self.active = false;
            self.project_sets
                .insert(self.project.clone(), self.volume_set.clone());
            let chars = if self.generation == 1 {
                ['d', 'e', 'f']
            } else {
                ['4', '5', '6']
            };
            self.candidate_ids = chars
                .into_iter()
                .map(|p| p.to_string().repeat(64))
                .collect();
            for id in &self.candidate_ids {
                self.running.insert(id.clone(), false);
                self.removed.retain(|gone| gone != id);
                self.id_projects.insert(id.clone(), self.project.clone());
            }
        }
        if argv.iter().any(|x| x == "up") {
            if s.contains("127.0.0.1:") {
                self.active = true;
                let chars = if self.generation == 1 {
                    ['1', '2', '3']
                } else {
                    ['7', '8', '9']
                };
                self.active_ids = chars
                    .into_iter()
                    .map(|p| p.to_string().repeat(64))
                    .collect();
                for id in &self.active_ids {
                    self.running.insert(id.clone(), true);
                    self.id_projects.insert(id.clone(), self.project.clone());
                }
            } else {
                for id in &self.candidate_ids {
                    self.running.insert(id.clone(), true);
                }
            }
        }
        if argv.iter().any(|x| x == "ps") {
            if self.fail_ps {
                return Err(LifecycleError::Command("fake_candidate_discovery_failed"));
            }
            return Ok(CommandOutput {
                stdout: format!("{}\n", self.id(argv.last().ok_or(LifecycleError::Receipt)?)),
            });
        }
        Ok(CommandOutput {
            stdout: String::new(),
        })
    }
}
fn restore_state(home: &Path) -> std::path::PathBuf {
    crate::config::InstancePaths::for_home(home)
        .paperless_root
        .join("state")
}
async fn restore_fixture(
    home: &Path,
    c: &Credentials,
    f: &mut RestoreFake,
) -> paperless_backup::PaperlessBackupReceipt {
    paperless_backup::backup_at_with(home, c, f, &RestoreReady(AtomicBool::new(true)))
        .await
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn restore_stateful_full_backup_orders_six_stopped_copies_before_no_port_candidate_start() {
    let (home, c, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut f = RestoreFake::new(true);
    let b = restore_fixture(home.path(), &c, &mut f).await;
    let start = f.commands.len();
    f.stdin_failures = 4;
    let readiness_started = tokio::time::Instant::now();
    restore_at_with(
        home.path(),
        &c,
        &b.job_id,
        &mut f,
        &RestoreReady(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let run = &f.commands[start..];
    let cps: Vec<_> = run
        .iter()
        .enumerate()
        .filter(|(_, x)| x.iter().any(|p| p == "cp"))
        .collect();
    assert_eq!(cps.len(), 6);
    let up = run
        .iter()
        .position(|x| x.iter().any(|p| p == "up"))
        .unwrap();
    assert!(cps.iter().all(|(i, _)| *i < up));
    let broker_candidate = f.candidate_ids[1].clone();
    let mut saw_broker_copy = false;
    for (_, cp) in cps {
        let archived = cp.iter().position(|part| part == "-a").unwrap();
        let stream = cp.iter().position(|part| part == "-").unwrap();
        assert!(archived < stream);
        assert!(
            cp.last()
                .is_some_and(|destination| !destination.ends_with("/data")
                    && !destination.ends_with("/media")),
            "restore targets the parent mount so Docker does not nest the archived basename"
        );
        if cp
            .last()
            .is_some_and(|destination| destination.starts_with(&format!("{broker_candidate}:")))
        {
            saw_broker_copy = true;
            assert_eq!(
                cp.last(),
                Some(&format!("{broker_candidate}:/")),
                "the archived broker /data must be copied into container root, never /data/data"
            );
        }
    }
    assert!(
        saw_broker_copy,
        "all six restores include the broker archive"
    );
    assert_eq!(
        f.stdin_calls, 5,
        "four transient failures exceed the obsolete three-attempt loop"
    );
    assert!(
        tokio::time::Instant::now().duration_since(readiness_started) >= READINESS_RETRY * 4,
        "each transient candidate probe failure consumes the bounded retry delay"
    );
}

#[tokio::test]
async fn restore_stateful_local_auth_loopback_cutover_and_known_failure_compensation() {
    let (home, c, prior) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut f = RestoreFake::new(true);
    let b = restore_fixture(home.path(), &c, &mut f).await;
    let old = f.source_state();
    assert!(matches!(
        restore_at_with(
            home.path(),
            &c,
            &b.job_id,
            &mut f,
            &RestoreReady(AtomicBool::new(false))
        )
        .await,
        Err(LifecycleError::Command(
            "paperless_restore_active_not_ready"
        ))
    ));
    assert_eq!(f.source_state(), old);
    assert_eq!(
        std::fs::read(
            crate::config::InstancePaths::for_home(home.path())
                .paperless_root
                .join("state")
                .join(RECEIPT_NAME)
        )
        .unwrap(),
        prior
    );
}

#[tokio::test]
async fn restore_stateful_failed_generation_retirement_is_immutable_and_names_exactly_six_volumes()
{
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = RestoreFake::new(false);
    let backup = restore_fixture(home.path(), &credentials, &mut fake).await;
    assert!(matches!(
        restore_at_with(
            home.path(),
            &credentials,
            &backup.job_id,
            &mut fake,
            &RestoreReady(AtomicBool::new(false))
        )
        .await,
        Err(LifecycleError::Command(
            "paperless_restore_active_not_ready"
        ))
    ));
    let journal: serde_json::Value = serde_json::from_slice(
        &std::fs::read(restore_state(home.path()).join(RESTORE_JOURNAL_NAME)).unwrap(),
    )
    .unwrap();
    let job = journal["restore_job_id"].as_str().unwrap();
    let retired = restore_state(home.path()).join(retired_generation_name(job).unwrap());
    let original = std::fs::read(&retired).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(record["outcome"], "source_restored_after_failed_generation");
    let names = record["volume_names"].as_array().unwrap();
    assert_eq!(names.len(), paperless_staging::PAPERLESS_VOLUMES.len());
    let project = record["restore_project"].as_str().unwrap();
    for volume in paperless_staging::PAPERLESS_VOLUMES {
        assert!(
            names
                .iter()
                .any(|name| name == &volume_name(project, volume.logical_name))
        );
    }
    // A fresh journal is permitted after known compensation; the immutable
    // failed-generation record remains evidence and is never replaced.
    let creates = fake.count("create");
    let _ = restore_at_with(
        home.path(),
        &credentials,
        &backup.job_id,
        &mut fake,
        &RestoreReady(AtomicBool::new(true)),
    )
    .await;
    assert_eq!(
        fake.count("create"),
        creates + 1,
        "fresh Restore really allocated its own candidate generation"
    );
    assert_eq!(std::fs::read(retired).unwrap(), original);
}

#[tokio::test]
async fn restore_stateful_tampered_retired_custody_blocks_recovery_before_fresh_create() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = RestoreFake::new(false);
    let backup = restore_fixture(home.path(), &credentials, &mut fake).await;
    let _ = restore_at_with(
        home.path(),
        &credentials,
        &backup.job_id,
        &mut fake,
        &RestoreReady(AtomicBool::new(false)),
    )
    .await;
    let journal_path = restore_state(home.path()).join(RESTORE_JOURNAL_NAME);
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
    let retired = restore_state(home.path())
        .join(retired_generation_name(journal["restore_job_id"].as_str().unwrap()).unwrap());
    std::fs::write(&retired, b"{}\n").unwrap();
    let typed: RestoreCustody = serde_json::from_value(journal.clone()).unwrap();
    let root_path = crate::config::InstancePaths::for_home(home.path()).paperless_root;
    let owned = paperless_staging::open_owned_root_at(&root_path).unwrap();
    assert!(matches!(
        write_retired_generation_new(&owned, &typed, "source_restored_after_failed_generation"),
        Err(LifecycleError::Receipt)
    ));
    assert_eq!(
        std::fs::read(&retired).unwrap(),
        b"{}\n",
        "tampered bytes are never overwritten"
    );
    let creates = fake.count("create");
    // Replay the same durable pre-compensation phase: retirement must validate
    // its create-new evidence rather than overwrite the hostile record.
    let mut replay = journal;
    replay["phase"] = serde_json::Value::String("candidate_ready".into());
    std::fs::write(&journal_path, serde_json::to_vec(&replay).unwrap()).unwrap();
    assert!(
        restore_at_with(
            home.path(),
            &credentials,
            &backup.job_id,
            &mut fake,
            &RestoreReady(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(fake.count("create"), creates);
}

#[tokio::test(start_paused = true)]
async fn restore_stateful_ambiguous_effect_never_replays_and_corrupt_inputs_have_no_effect() {
    for pointer_kind in ["malformed", "nonfile"] {
        let (home, c, _) = super::super::tests::installed_home_for_uninstall_test().await;
        let mut pointer_fake = RestoreFake::new(false);
        let backup = restore_fixture(home.path(), &c, &mut pointer_fake).await;
        let pointer_path = restore_state(home.path()).join(RESTORE_ACTIVE_POINTER_NAME);
        match pointer_kind {
            "malformed" => std::fs::write(&pointer_path, b"{}\n").unwrap(),
            "nonfile" => std::fs::create_dir(&pointer_path).unwrap(),
            _ => unreachable!(),
        }
        let commands = pointer_fake.commands.len();
        let effects = pointer_fake.effects();
        assert!(
            matches!(
                restore_at_with(
                    home.path(),
                    &c,
                    &backup.job_id,
                    &mut pointer_fake,
                    &RestoreReady(AtomicBool::new(true))
                )
                .await,
                Err(LifecycleError::Command(
                    "paperless_restore_active_authority_invalid"
                ))
            ),
            "{pointer_kind}"
        );
        assert_eq!(
            pointer_fake.commands.len(),
            commands,
            "{pointer_kind} blocks before engine selection"
        );
        assert_eq!(pointer_fake.effects(), effects, "{pointer_kind}");
    }
    {
        let (home, c, _) = super::super::tests::installed_home_for_uninstall_test().await;
        let mut mismatch_fake = RestoreFake::new(false);
        let backup = restore_fixture(home.path(), &c, &mut mismatch_fake).await;
        let source_path = restore_state(home.path())
            .join("backups")
            .join(&backup.job_id)
            .join("source.v1.json");
        let original_source = std::fs::read(&source_path).unwrap();
        let mut source: serde_json::Value = serde_json::from_slice(&original_source).unwrap();
        let current = source["restore_binding"]["environment_fingerprint"]
            .as_str()
            .unwrap();
        let replacement = if current == "b".repeat(64) {
            "c".repeat(64)
        } else {
            "b".repeat(64)
        };
        source["restore_binding"]["environment_fingerprint"] =
            serde_json::Value::String(replacement);
        std::fs::write(&source_path, serde_json::to_vec(&source).unwrap()).unwrap();
        let commands = mismatch_fake.commands.len();
        let effects = mismatch_fake.effects();
        assert!(matches!(
            restore_at_with(
                home.path(),
                &c,
                &backup.job_id,
                &mut mismatch_fake,
                &RestoreReady(AtomicBool::new(true))
            )
            .await,
            Err(LifecycleError::Receipt)
        ));
        assert_eq!(mismatch_fake.commands.len(), commands);
        assert_eq!(mismatch_fake.effects(), effects);

        // Keep the immutable historical source/custody pair coherent. Changing
        // the current token reaches the actual same-instance compatibility gate.
        std::fs::write(&source_path, &original_source).unwrap();
        let mut changed_credentials = c.clone();
        changed_credentials.paperless_token =
            Some(SecretString::from("different-current-restore-token"));
        assert!(matches!(
            restore_at_with(
                home.path(),
                &changed_credentials,
                &backup.job_id,
                &mut mismatch_fake,
                &RestoreReady(AtomicBool::new(true))
            )
            .await,
            Err(LifecycleError::Command(
                "paperless_restore_config_fingerprint_mismatch"
            ))
        ));
        assert_eq!(
            mismatch_fake.commands.len(),
            commands,
            "config mismatch blocks before engine selection"
        );
        assert_eq!(mismatch_fake.effects(), effects);
        assert_eq!(std::fs::read(&source_path).unwrap(), original_source);
    }
    {
        let (home, c, _) = super::super::tests::installed_home_for_uninstall_test().await;
        let mut fatal_fake = RestoreFake::new(false);
        let backup = restore_fixture(home.path(), &c, &mut fatal_fake).await;
        let original = fatal_fake.source_state();
        let stops = fatal_fake.count("stop");
        fatal_fake.stdin_fatal = true;
        assert!(matches!(
            restore_at_with(
                home.path(),
                &c,
                &backup.job_id,
                &mut fatal_fake,
                &RestoreReady(AtomicBool::new(true))
            )
            .await,
            Err(LifecycleError::Command("paperless_stdin_spawn_failed"))
        ));
        assert_eq!(
            fatal_fake.stdin_calls, 1,
            "fatal probe errors are never retried"
        );
        assert_eq!(fatal_fake.source_state(), original);
        assert_eq!(
            fatal_fake.count("stop"),
            stops,
            "fatal candidate probe cannot cut over source"
        );
    }
    {
        let (home, c, _) = super::super::tests::installed_home_for_uninstall_test().await;
        let mut deadline_fake = RestoreFake::new(false);
        let backup = restore_fixture(home.path(), &c, &mut deadline_fake).await;
        let original = deadline_fake.source_state();
        let stops = deadline_fake.count("stop");
        deadline_fake.stdin_failures = 100;
        assert!(matches!(
            restore_at_with(
                home.path(),
                &c,
                &backup.job_id,
                &mut deadline_fake,
                &RestoreReady(AtomicBool::new(true))
            )
            .await,
            Err(LifecycleError::Command(
                "paperless_restore_candidate_probe_not_ready"
            ))
        ));
        assert!(
            (45..=46).contains(&deadline_fake.stdin_calls),
            "deadline uses bounded one-second retries"
        );
        assert_eq!(
            deadline_fake.source_state(),
            original,
            "candidate deadline cannot cut over source"
        );
        assert_eq!(
            deadline_fake.count("stop"),
            stops,
            "no source stop before authenticated candidate readiness"
        );
    }
    let (home, c, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut f = RestoreFake::new(false);
    let b = restore_fixture(home.path(), &c, &mut f).await;
    f.lose_copy = true;
    assert!(
        restore_at_with(
            home.path(),
            &c,
            &b.job_id,
            &mut f,
            &RestoreReady(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    let copies = f.count("cp");
    assert!(
        restore_at_with(
            home.path(),
            &c,
            &b.job_id,
            &mut f,
            &RestoreReady(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(f.count("cp"), copies);
    let root = crate::config::InstancePaths::for_home(home.path()).paperless_root;
    assert!(blocks_peer_operation(&paperless_staging::open_owned_root_at(&root).unwrap()).unwrap());
    let journal_path = restore_state(home.path()).join(RESTORE_JOURNAL_NAME);
    let mut journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
    journal["phase"] = serde_json::Value::String("archive_copy_dispatched".into());
    std::fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
    let effects = f.effects();
    assert!(matches!(
        restore_at_with(
            home.path(),
            &c,
            &b.job_id,
            &mut f,
            &RestoreReady(AtomicBool::new(true))
        )
        .await,
        Err(LifecycleError::Command(
            "paperless_restore_archive_copy_outcome_ambiguous"
        ))
    ));
    assert_eq!(
        f.effects(),
        effects,
        "persisted ArchiveCopyDispatched is observed, never replayed"
    );
    let (home, c, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut f = RestoreFake::new(false);
    let b = restore_fixture(home.path(), &c, &mut f).await;
    std::fs::write(
        restore_state(home.path()).join(RESTORE_JOURNAL_NAME),
        b"{}\n",
    )
    .unwrap();
    let effects = f.effects();
    assert!(
        restore_at_with(
            home.path(),
            &c,
            &b.job_id,
            &mut f,
            &RestoreReady(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(f.effects(), effects);
}

#[tokio::test]
async fn restore_stateful_second_restore_uses_new_generation_and_keeps_first_generation_history() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = RestoreFake::new(false);
    let first_backup = restore_fixture(home.path(), &credentials, &mut fake).await;
    let first = restore_at_with(
        home.path(),
        &credentials,
        &first_backup.job_id,
        &mut fake,
        &RestoreReady(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let first_custody: serde_json::Value = serde_json::from_slice(
        &std::fs::read(restore_state(home.path()).join(&first.rollback_custody_ref)).unwrap(),
    )
    .unwrap();
    assert_eq!(first_custody["schema_version"], 2);
    assert_eq!(first_custody["prior_active_pointer"]["state"], "absent");
    assert_eq!(
        first_custody["prior_active_pointer"]["absence"],
        "not_found"
    );
    assert!(first_custody["rollback_restore_binding"].is_object());
    let root = crate::config::InstancePaths::for_home(home.path()).paperless_root;
    let owned = paperless_staging::open_owned_root_at(&root).unwrap();
    let successor = "00000000-0000-0000-0000-000000000001";
    authorize_restore_successor_volume_set_at(&owned, &first.restore_project, successor).unwrap();
    let original_pointer_bytes =
        std::fs::read(restore_state(home.path()).join(RESTORE_ACTIVE_POINTER_NAME)).unwrap();
    let creates = fake.count("create");
    let second_backup = restore_fixture(home.path(), &credentials, &mut fake).await;
    let second = restore_at_with(
        home.path(),
        &credentials,
        &second_backup.job_id,
        &mut fake,
        &RestoreReady(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    assert_ne!(first.restore_job_id, second.restore_job_id);
    assert_eq!(fake.count("create"), creates + 1);
    let second_custody: serde_json::Value = serde_json::from_slice(
        &std::fs::read(restore_state(home.path()).join(&second.rollback_custody_ref)).unwrap(),
    )
    .unwrap();
    assert_eq!(second_custody["schema_version"], 2);
    assert_eq!(second_custody["prior_active_pointer"]["state"], "present");
    let captured = second_custody["prior_active_pointer"]["bytes"]
        .as_array()
        .unwrap();
    assert!(!captured.is_empty());
    assert_eq!(
        second_custody["prior_active_pointer"]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let captured_bytes: Vec<u8> = captured
        .iter()
        .map(|item| item.as_u64().unwrap() as u8)
        .collect();
    let captured_pointer: RestoreActivePointer = serde_json::from_slice(&captured_bytes).unwrap();
    assert!(
        captured_pointer
            .authorized_volume_set_ids
            .iter()
            .any(|known| known == successor)
    );
    assert_eq!(captured_bytes, original_pointer_bytes);
    assert_eq!(
        second_custody["prior_active_pointer"]["sha256"],
        restore_digest(&original_pointer_bytes)
    );
    let mut legacy = first_custody.clone();
    legacy["schema_version"] = serde_json::Value::from(1);
    legacy
        .as_object_mut()
        .unwrap()
        .remove("prior_active_pointer");
    legacy
        .as_object_mut()
        .unwrap()
        .remove("rollback_restore_binding");
    let legacy: RestoreCustody = serde_json::from_value(legacy).unwrap();
    assert!(
        validate_restore_custody(&legacy).is_ok(),
        "v1 historical custody stays verifiable"
    );
    let mut absent_project_mismatch = first_custody.clone();
    let mismatched_project = "neoth-paperless-abcdef123456";
    let prior_bytes: Vec<u8> =
        serde_json::from_value(absent_project_mismatch["prior_install_receipt_bytes"].clone())
            .unwrap();
    let mut prior: serde_json::Value = serde_json::from_slice(&prior_bytes).unwrap();
    prior["project"] = serde_json::Value::String(mismatched_project.to_owned());
    absent_project_mismatch["prior_install_receipt_bytes"] =
        serde_json::to_value(serde_json::to_vec(&prior).unwrap()).unwrap();
    let rollback_snapshot_bytes: Vec<u8> =
        serde_json::from_value(absent_project_mismatch["prior_volume_set_snapshot_bytes"].clone())
            .unwrap();
    let mut rollback_snapshot: serde_json::Value =
        serde_json::from_slice(&rollback_snapshot_bytes).unwrap();
    rollback_snapshot["project"] = serde_json::Value::String(mismatched_project.to_owned());
    absent_project_mismatch["prior_volume_set_snapshot_bytes"] =
        serde_json::to_value(serde_json::to_vec(&rollback_snapshot).unwrap()).unwrap();
    absent_project_mismatch["rollback_project"] =
        serde_json::Value::String(mismatched_project.to_owned());
    let absent_project_mismatch: RestoreCustody =
        serde_json::from_value(absent_project_mismatch).unwrap();
    assert!(matches!(
        validate_restore_custody(&absent_project_mismatch),
        Err(LifecycleError::Receipt)
    ));
    for mutation in [
        "missing_pointer",
        "missing_binding",
        "bad_absence",
        "absent_schema3",
        "bad_binding",
    ] {
        let mut invalid = second_custody.clone();
        match mutation {
            "missing_pointer" => {
                invalid
                    .as_object_mut()
                    .unwrap()
                    .remove("prior_active_pointer");
            }
            "missing_binding" => {
                invalid
                    .as_object_mut()
                    .unwrap()
                    .remove("rollback_restore_binding");
            }
            "bad_absence" => {
                invalid["prior_active_pointer"] =
                    serde_json::json!({"state":"absent","absence":"missing"});
            }
            "absent_schema3" => {
                invalid["prior_active_pointer"] =
                    serde_json::json!({"state":"absent","absence":"not_found"});
            }
            "bad_binding" => {
                invalid["rollback_restore_binding"]["environment_fingerprint"] =
                    serde_json::Value::String("g".repeat(64));
            }
            _ => unreachable!(),
        };
        let parsed: RestoreCustody = serde_json::from_value(invalid).unwrap();
        assert!(
            matches!(
                validate_restore_custody(&parsed),
                Err(LifecycleError::Receipt)
            ),
            "{mutation}"
        );
    }
    let mut missing_rollback_authorization = second_custody.clone();
    let captured_bytes: Vec<u8> = serde_json::from_value(
        missing_rollback_authorization["prior_active_pointer"]["bytes"].clone(),
    )
    .unwrap();
    let mut captured_pointer: serde_json::Value = serde_json::from_slice(&captured_bytes).unwrap();
    let rollback_volume_set_id = missing_rollback_authorization["rollback_volume_set_id"]
        .as_str()
        .unwrap();
    captured_pointer["authorized_volume_set_ids"]
        .as_array_mut()
        .unwrap()
        .retain(|id| id.as_str() != Some(rollback_volume_set_id));
    let captured_bytes = serde_json::to_vec(&captured_pointer).unwrap();
    missing_rollback_authorization["prior_active_pointer"]["bytes"] =
        serde_json::to_value(&captured_bytes).unwrap();
    missing_rollback_authorization["prior_active_pointer"]["sha256"] =
        serde_json::Value::String(restore_digest(&captured_bytes));
    let missing_rollback_authorization: RestoreCustody =
        serde_json::from_value(missing_rollback_authorization).unwrap();
    assert!(matches!(
        validate_restore_custody(&missing_rollback_authorization),
        Err(LifecycleError::Receipt)
    ));
    let history: serde_json::Value = serde_json::from_slice(
        &std::fs::read(restore_state(home.path()).join(RESTORE_HISTORY_NAME)).unwrap(),
    )
    .unwrap();
    assert_eq!(history["custody_names"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn restore_stateful_committed_pointer_reentry_survives_missing_mutable_journal_without_new_effect()
 {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = RestoreFake::new(false);
    let backup = restore_fixture(home.path(), &credentials, &mut fake).await;
    let first = restore_at_with(
        home.path(),
        &credentials,
        &backup.job_id,
        &mut fake,
        &RestoreReady(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let effects = fake.effects();
    std::fs::remove_file(restore_state(home.path()).join(RESTORE_JOURNAL_NAME)).unwrap();
    let resumed = restore_at_with(
        home.path(),
        &credentials,
        &backup.job_id,
        &mut fake,
        &RestoreReady(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    assert_eq!(resumed.restore_job_id, first.restore_job_id);
    assert_eq!(
        fake.effects(),
        effects,
        "active immutable pointer makes journal publication recoverable"
    );
}

#[tokio::test]
async fn restore_stateful_create_dispatched_discovery_failure_holds_without_second_create() {
    let (home, credentials, _) = super::super::tests::installed_home_for_uninstall_test().await;
    let mut fake = RestoreFake::new(false);
    let backup = restore_fixture(home.path(), &credentials, &mut fake).await;
    fake.fail_ps = true;
    assert!(
        restore_at_with(
            home.path(),
            &credentials,
            &backup.job_id,
            &mut fake,
            &RestoreReady(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(fake.count("create"), 1);
    assert!(
        restore_at_with(
            home.path(),
            &credentials,
            &backup.job_id,
            &mut fake,
            &RestoreReady(AtomicBool::new(true))
        )
        .await
        .is_err()
    );
    assert_eq!(
        fake.count("create"),
        1,
        "R10 recovery must discover or hold, never issue a second create"
    );
    let journal: serde_json::Value = serde_json::from_slice(
        &std::fs::read(restore_state(home.path()).join(RESTORE_JOURNAL_NAME)).unwrap(),
    )
    .unwrap();
    assert_eq!(journal["phase"], "held");
}
