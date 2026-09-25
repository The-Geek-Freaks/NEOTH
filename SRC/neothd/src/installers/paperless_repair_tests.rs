//! Behavioural retained-compose repair coverage; no Docker daemon is used.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
#[derive(Clone)]
struct C {
    service: String,
    image: String,
    running: bool,
    foreign: bool,
    bad_image: bool,
    bad_mount: bool,
}
struct Fake {
    commands: Vec<Vec<String>>,
    retained: Vec<Vec<String>>,
    cs: BTreeMap<String, C>,
    volumes: BTreeSet<String>,
    generation: String,
    created: bool,
    unknown: bool,
}
impl Fake {
    fn from(b: &[u8]) -> Self {
        let v: serde_json::Value = serde_json::from_slice(b).unwrap();
        let p = v["project"].as_str().unwrap();
        Self {
            commands: vec![],
            retained: vec![],
            cs: v["containers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| {
                    (
                        x["id"].as_str().unwrap().into(),
                        C {
                            service: x["service"].as_str().unwrap().into(),
                            image: x["image_id"].as_str().unwrap().into(),
                            running: true,
                            foreign: false,
                            bad_image: false,
                            bad_mount: false,
                        },
                    )
                })
                .collect(),
            volumes: paperless_staging::PAPERLESS_VOLUMES
                .iter()
                .map(|x| volume_name(p, x.logical_name))
                .collect(),
            generation: v["volume_set_id"].as_str().unwrap().into(),
            created: false,
            unknown: false,
        }
    }
    fn id(&self, s: &str) -> String {
        self.cs
            .iter()
            .find_map(|(id, c)| (c.service == s).then(|| id.clone()))
            .unwrap()
    }
    fn effects(&self) -> usize {
        self.commands
            .iter()
            .chain(&self.retained)
            .filter(|a| a.iter().any(|x| x == "start" || x == "up"))
            .count()
    }
    fn inspect(&self, id: &str, cwd: &Path) -> Result<String, LifecycleError> {
        let c = self.cs.get(id).ok_or(LifecycleError::Command("fake_id"))?;
        let service = if c.foreign { "foreign" } else { &c.service };
        let image = if c.bad_image {
            "sha256:foreign"
        } else {
            &c.image
        };
        let mounts = if c.bad_mount {
            String::new()
        } else {
            paperless_staging::PAPERLESS_VOLUMES
                .iter()
                .filter(|v| v.service == c.service)
                .map(|v| {
                    format!(
                        r#"{{"Type":"volume","Name":"{}","Destination":"{}"}}"#,
                        volume_name(&project_name(cwd), v.logical_name),
                        v.destination
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        let ports = if c.service == "webserver" {
            r#"{"8000/tcp":[{"HostIp":"127.0.0.1","HostPort":"18000"}]}"#
        } else {
            "{}"
        };
        Ok(format!(
            r#"{{"Id":"{id}","Image":"{image}","State":{{"Running":{}}},"Config":{{"Labels":{{"com.docker.compose.project":"{}","com.docker.compose.service":"{service}"}}}},"NetworkSettings":{{"Ports":{ports}}},"Mounts":[{mounts}]}}"#,
            c.running,
            project_name(cwd)
        ))
    }
}
#[async_trait]
impl ComposeExecutor for Fake {
    async fn run(&mut self, a: &[String], cwd: &Path) -> Result<CommandOutput, LifecycleError> {
        self.commands.push(a.to_vec());
        if a.windows(2).any(|x| x == ["context", "show"]) {
            return Ok(CommandOutput {
                stdout: "desktop-linux\n".into(),
            });
        }
        if a.windows(2).any(|x| x == ["context", "inspect"]) {
            return Ok(CommandOutput {
                stdout: "\"npipe:////./pipe/docker_engine\"".into(),
            });
        }
        if a.iter().any(|x| x == "version") {
            return Ok(CommandOutput {
                stdout: r#"{"Os":"linux","Arch":"amd64"}"#.into(),
            });
        }
        if a.iter().any(|x| x == "image") {
            let r = a.iter().skip_while(|x| *x != "inspect").nth(1).unwrap();
            let e = expected_images()?
                .into_iter()
                .find(|x| x.reference == r)
                .unwrap();
            return Ok(CommandOutput {
                stdout: format!(
                    r#"{{"Id":"{}","RepoDigests":["{}"],"Os":"linux","Architecture":"amd64"}}"#,
                    e.configs["linux/amd64"], e.repo_digest
                ),
            });
        }
        if a.iter().any(|x| x == "volume") {
            if a.iter().any(|x| x == "ls") {
                let n = a.iter().find_map(|x| x.strip_prefix("name=")).unwrap();
                return Ok(CommandOutput {
                    stdout: self
                        .volumes
                        .contains(n)
                        .then(|| format!("{n}\n"))
                        .unwrap_or_default(),
                });
            }
            let n = a.iter().skip_while(|x| *x != "inspect").nth(1).unwrap();
            let v = paperless_staging::PAPERLESS_VOLUMES
                .iter()
                .find(|v| n.ends_with(v.logical_name))
                .unwrap();
            return Ok(CommandOutput {
                stdout: format!(
                    r#"{{"Name":"{n}","Labels":{{"com.docker.compose.project":"{}","com.docker.compose.volume":"{}","io.neoth.paperless.volume-set-id":"{}"}}}}"#,
                    project_name(cwd),
                    v.logical_name,
                    self.generation
                ),
            });
        }
        if a.iter().any(|x| x == "container") && a.iter().any(|x| x == "ls") {
            let out = if let Some(id) = a.iter().find_map(|x| x.strip_prefix("id=")) {
                self.cs
                    .contains_key(id)
                    .then(|| format!("{id}\n"))
                    .unwrap_or_default()
            } else {
                let s = a
                    .iter()
                    .find_map(|x| x.strip_prefix("label=com.docker.compose.service="))
                    .unwrap();
                self.cs
                    .iter()
                    .find_map(|(id, c)| (c.service == s).then(|| format!("{id}\n")))
                    .unwrap_or_default()
            };
            return Ok(CommandOutput { stdout: out });
        }
        if let Some(i) = a.iter().position(|x| x == "start") {
            let id = &a[i + 1];
            self.cs.get_mut(id).unwrap().running = true;
            return Ok(CommandOutput {
                stdout: String::new(),
            });
        }
        if a.iter().any(|x| x == "container") && a.iter().any(|x| x == "inspect") {
            let id = a
                .iter()
                .skip_while(|x| *x != "inspect")
                .nth(1)
                .unwrap()
                .clone();
            return Ok(CommandOutput {
                stdout: self.inspect(&id, cwd)?,
            });
        }
        Err(LifecycleError::Command("fake_command"))
    }
}
#[async_trait]
impl RetainedComposeExecutor for Fake {
    async fn run_retained(
        &mut self,
        a: &[String],
        root: &OwnedPaperlessRoot,
        _: &EnvBinding,
    ) -> Result<CommandOutput, LifecycleError> {
        self.retained.push(a.to_vec());
        if a.iter().any(|x| x == "up") {
            if self.unknown {
                return Err(LifecycleError::Command("unknown"));
            }
            let s = a.last().unwrap();
            if !self.cs.values().any(|c| c.service == *s) {
                let id = match s.as_str() {
                    "webserver" => "d".repeat(64),
                    "broker" => "e".repeat(64),
                    _ => "f".repeat(64),
                };
                let e = expected_images()?
                    .into_iter()
                    .find(|e| e.service == s)
                    .unwrap();
                self.cs.insert(
                    id,
                    C {
                        service: s.clone(),
                        image: e.configs["linux/amd64"].clone(),
                        running: true,
                        foreign: false,
                        bad_image: false,
                        bad_mount: false,
                    },
                );
                self.created = true
            }
            return Ok(CommandOutput {
                stdout: String::new(),
            });
        }
        if a.iter().any(|x| x == "ps") {
            let s = a.last().unwrap();
            let id = self.id(s);
            return Ok(CommandOutput {
                stdout: format!("{id}\n"),
            });
        }
        Err(LifecycleError::Command("fake_retained"))
    }
}
struct Ready;
#[async_trait]
impl ReadinessVerifier for Ready {
    async fn ready(&self, _: &Path, _: &Credentials) -> bool {
        true
    }
}
async fn fix() -> (tempfile::TempDir, Credentials, Vec<u8>, Fake) {
    let (h, c, b) = installed_home_for_uninstall_test().await;
    let f = Fake::from(&b);
    (h, c, b, f)
}
fn rp(h: &Path) -> std::path::PathBuf {
    crate::config::InstancePaths::for_home(h)
        .paperless_root
        .join(RECEIPT_DIR)
        .join(RECEIPT_NAME)
}
fn sp(h: &Path, n: &str) -> std::path::PathBuf {
    crate::config::InstancePaths::for_home(h)
        .paperless_root
        .join(RECEIPT_DIR)
        .join(n)
}
#[tokio::test]
async fn healthy_auth_is_three_service_noop_and_keeps_bytes() {
    let (h, c, b, mut f) = fix().await;
    let r = repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
        .await
        .unwrap();
    assert_eq!(r.services.len(), 3);
    assert!(
        r.services
            .iter()
            .all(|x| x.action == PaperlessRepairAction::Healthy && x.prior_id == x.current_id)
    );
    assert_eq!(std::fs::read(rp(h.path())).unwrap(), b);
    assert_eq!(f.effects(), 0)
}
#[tokio::test]
async fn stopped_exact_id_is_started_and_reconciled() {
    let (h, c, _, mut f) = fix().await;
    let id = f.id("broker");
    f.cs.get_mut(&id).unwrap().running = false;
    let r = repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
        .await
        .unwrap();
    assert_eq!(
        r.services
            .iter()
            .find(|x| x.service == "broker")
            .unwrap()
            .action,
        PaperlessRepairAction::Started
    );
    assert!(
        f.commands
            .iter()
            .any(|a| a.windows(2).any(|x| x[0] == "start" && x[1] == id))
    )
}
#[tokio::test]
async fn missing_owned_recreates_with_six_volumes_and_credentials() {
    let (h, c, _, mut f) = fix().await;
    let old = f.id("webserver");
    f.cs.remove(&old);
    let r = repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
        .await
        .unwrap();
    let x = r
        .services
        .iter()
        .find(|x| x.service == "webserver")
        .unwrap();
    assert_eq!(x.action, PaperlessRepairAction::Recreated);
    assert_eq!(x.prior_id, old);
    assert_eq!(x.current_id, "d".repeat(64));
    assert_eq!(f.volumes.len(), 6);
    assert!(c.paperless_token.is_some())
}
#[tokio::test]
async fn foreign_image_or_mount_refuse_pre_effect() {
    for mode in 0..3 {
        let (h, c, b, mut f) = fix().await;
        let id = f.id("webserver");
        if mode == 0 {
            f.cs.get_mut(&id).unwrap().foreign = true
        } else if mode == 1 {
            f.cs.get_mut(&id).unwrap().bad_image = true
        } else {
            f.cs.get_mut(&id).unwrap().bad_mount = true
        };
        assert!(
            repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
                .await
                .is_err()
        );
        assert_eq!(f.effects(), 0);
        assert_eq!(std::fs::read(rp(h.path())).unwrap(), b)
    }
}
#[tokio::test]
async fn custody_or_missing_token_refuses_before_docker() {
    for n in [
        UNINSTALL_RECEIPT_NAME,
        paperless_purge::PURGE_CUSTODY_NAME,
        ROTATION_JOURNAL_NAME,
    ] {
        let (h, c, _, mut f) = fix().await;
        std::fs::write(sp(h.path(), n), b"x").unwrap();
        assert!(
            repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
                .await
                .is_err()
        );
        assert!(f.commands.is_empty())
    }
    let (h, mut c, _, mut f) = fix().await;
    c.paperless_token = None;
    assert!(
        repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
            .await
            .is_err()
    );
    assert!(f.commands.is_empty())
}
#[tokio::test]
async fn unknown_create_is_held_without_redispatch_or_adoption() {
    let (h, c, _, mut f) = fix().await;
    let id = f.id("webserver");
    f.cs.remove(&id);
    f.unknown = true;
    assert!(
        repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
            .await
            .is_err()
    );
    assert_eq!(f.retained.len(), 1);
    assert!(sp(h.path(), REPAIR_JOURNAL_NAME).is_file());
    assert!(
        repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
            .await
            .is_err()
    );
    assert_eq!(f.retained.len(), 1);
    assert!(!f.created)
}

#[tokio::test]
async fn captured_complete_journal_recovers_exact_receipt_write_once() {
    let (h, c, b, mut f) = fix().await;
    let old = f.id("webserver");
    let mut replacement = f.cs[&old].clone();
    replacement.running = true;
    f.cs.remove(&old);
    f.cs.insert("d".repeat(64), replacement);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let members = v["containers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            let s = x["service"].as_str().unwrap();
            RepairMember {
                service: s.into(),
                prior_id: x["id"].as_str().unwrap().into(),
                image_id: x["image_id"].as_str().unwrap().into(),
                action: if s == "webserver" {
                    PaperlessRepairAction::Recreated
                } else {
                    PaperlessRepairAction::Healthy
                },
                current_id: Some(if s == "webserver" {
                    "d".repeat(64)
                } else {
                    x["id"].as_str().unwrap().into()
                }),
            }
        })
        .collect::<Vec<_>>();
    let mut j = PaperlessRepairJournal {
        schema_version: 1,
        operation: "paperless.repair".into(),
        phase: RepairPhase::Complete,
        project: v["project"].as_str().unwrap().into(),
        volume_set_id: v["volume_set_id"].as_str().unwrap().into(),
        install_receipt_sha256: digest(&b),
        before_receipt_bytes: b.clone(),
        after_receipt_bytes: None,
        members,
        effect_service: None,
    };
    j.after_receipt_bytes = Some(replacement_receipt_bytes(&j).unwrap());
    std::fs::write(
        sp(h.path(), REPAIR_JOURNAL_NAME),
        serde_json::to_vec(&j).unwrap(),
    )
    .unwrap();
    let r = repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
        .await
        .unwrap();
    let committed = std::fs::read(rp(h.path())).unwrap();
    assert_ne!(committed, b);
    assert_eq!(r.services.len(), 3);
    assert!(!sp(h.path(), REPAIR_JOURNAL_NAME).exists());
    let again = repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
        .await
        .unwrap();
    assert_eq!(std::fs::read(rp(h.path())).unwrap(), committed);
    assert_eq!(again.services.len(), 3)
}

#[tokio::test]
async fn journal_mismatch_refuses_without_effect() {
    let (h, c, b, mut f) = fix().await;
    let j = PaperlessRepairJournal {
        schema_version: 1,
        operation: "paperless.repair".into(),
        phase: RepairPhase::Held,
        project: "foreign".into(),
        volume_set_id: "foreign".into(),
        install_receipt_sha256: digest(&b),
        before_receipt_bytes: b.clone(),
        after_receipt_bytes: None,
        members: vec![],
        effect_service: None,
    };
    std::fs::write(
        sp(h.path(), REPAIR_JOURNAL_NAME),
        serde_json::to_vec(&j).unwrap(),
    )
    .unwrap();
    assert!(
        repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
            .await
            .is_err()
    );
    assert_eq!(f.effects(), 0);
    assert_eq!(std::fs::read(rp(h.path())).unwrap(), b)
}

#[tokio::test]
async fn generation_authority_marker_refuses_before_effect() {
    let (h, c, _, mut f) = fix().await;
    std::fs::write(
        sp(h.path(), GENERATION_AUTH_NAME),
        b"generation transition active",
    )
    .unwrap();
    assert!(
        repair_at_with_readiness(h.path(), &c, &mut f, &Ready)
            .await
            .is_err()
    );
    assert!(f.commands.is_empty());
    assert!(f.retained.is_empty())
}

fn completed_recreate_journal(before: &[u8], phase: RepairPhase) -> PaperlessRepairJournal {
    let receipt: serde_json::Value = serde_json::from_slice(before).unwrap();
    let members = receipt["containers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|container| {
            let service = container["service"].as_str().unwrap();
            RepairMember {
                service: service.to_owned(),
                prior_id: container["id"].as_str().unwrap().to_owned(),
                image_id: container["image_id"].as_str().unwrap().to_owned(),
                action: if service == "webserver" {
                    PaperlessRepairAction::Recreated
                } else {
                    PaperlessRepairAction::Healthy
                },
                current_id: Some(if service == "webserver" {
                    "d".repeat(64)
                } else {
                    container["id"].as_str().unwrap().to_owned()
                }),
            }
        })
        .collect();
    let mut journal = PaperlessRepairJournal {
        schema_version: 1,
        operation: "paperless.repair".into(),
        phase,
        project: receipt["project"].as_str().unwrap().into(),
        volume_set_id: receipt["volume_set_id"].as_str().unwrap().into(),
        install_receipt_sha256: digest(before),
        before_receipt_bytes: before.to_vec(),
        after_receipt_bytes: None,
        members,
        effect_service: None,
    };
    if phase != RepairPhase::Bound {
        journal.after_receipt_bytes = Some(replacement_receipt_bytes(&journal).unwrap());
    }
    journal
}

fn seed_recreated_webserver(fake: &mut Fake) {
    let prior = fake.id("webserver");
    let container = fake.cs.remove(&prior).unwrap();
    fake.cs.insert("d".repeat(64), container);
}

#[tokio::test]
async fn bound_before_receipt_write_replays_without_redispatch() {
    let (home, credentials, before, mut fake) = fix().await;
    seed_recreated_webserver(&mut fake);
    let journal = completed_recreate_journal(&before, RepairPhase::Bound);
    std::fs::write(
        sp(home.path(), REPAIR_JOURNAL_NAME),
        serde_json::to_vec(&journal).unwrap(),
    )
    .unwrap();
    let receipt = repair_at_with_readiness(home.path(), &credentials, &mut fake, &Ready)
        .await
        .unwrap();
    assert_eq!(receipt.services.len(), 3);
    assert_ne!(std::fs::read(rp(home.path())).unwrap(), before);
    assert_eq!(fake.effects(), 0);
    assert!(!sp(home.path(), REPAIR_JOURNAL_NAME).exists());
}

#[tokio::test]
async fn commit_dispatched_before_write_replays_the_cas_without_redispatch() {
    let (home, credentials, before, mut fake) = fix().await;
    seed_recreated_webserver(&mut fake);
    let journal = completed_recreate_journal(&before, RepairPhase::ReceiptCommitDispatched);
    std::fs::write(
        sp(home.path(), REPAIR_JOURNAL_NAME),
        serde_json::to_vec(&journal).unwrap(),
    )
    .unwrap();
    repair_at_with_readiness(home.path(), &credentials, &mut fake, &Ready)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(rp(home.path())).unwrap(),
        journal.after_receipt_bytes.unwrap()
    );
    assert_eq!(fake.effects(), 0);
}

#[tokio::test]
async fn commit_dispatched_after_write_and_complete_are_idempotent() {
    for phase in [RepairPhase::ReceiptCommitDispatched, RepairPhase::Complete] {
        let (home, credentials, before, mut fake) = fix().await;
        seed_recreated_webserver(&mut fake);
        let journal = completed_recreate_journal(&before, phase);
        let after = journal.after_receipt_bytes.clone().unwrap();
        std::fs::write(rp(home.path()), &after).unwrap();
        std::fs::write(
            sp(home.path(), REPAIR_JOURNAL_NAME),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        let receipt = repair_at_with_readiness(home.path(), &credentials, &mut fake, &Ready)
            .await
            .unwrap();
        assert_eq!(receipt.services.len(), 3, "{phase:?}");
        assert_eq!(std::fs::read(rp(home.path())).unwrap(), after, "{phase:?}");
        assert_eq!(fake.effects(), 0, "{phase:?}");
        assert!(!sp(home.path(), REPAIR_JOURNAL_NAME).exists(), "{phase:?}");
    }
}
