use super::*;
use crate::installers::paperless_lifecycle::paperless_purge::{
    PURGE_CUSTODY_NAME, PURGE_RECEIPT_NAME, PaperlessCompletedPurgeAuthority,
    PaperlessPurgeAuthoritySource,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const NAMES: [(&str, &str); 5] = [
    ("install", RECEIPT_NAME),
    ("uninstall", UNINSTALL_RECEIPT_NAME),
    ("volume-set", VOLUME_SET_NAME),
    ("purge-custody", PURGE_CUSTODY_NAME),
    ("purge-receipt", PURGE_RECEIPT_NAME),
];

struct Fake {
    present: BTreeSet<String>,
    ids: BTreeMap<String, (String, String)>,
    volumes: BTreeSet<String>,
    generation: String,
}
impl Fake {
    fn receipt(bytes: &[u8]) -> Self {
        let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let mut present = BTreeSet::new();
        let mut ids = BTreeMap::new();
        for c in v["containers"].as_array().unwrap() {
            let id = c["id"].as_str().unwrap().to_owned();
            present.insert(id.clone());
            ids.insert(
                id,
                (
                    c["service"].as_str().unwrap().to_owned(),
                    c["image_id"].as_str().unwrap().to_owned(),
                ),
            );
        }
        let p = v["project"].as_str().unwrap();
        Self {
            present,
            ids,
            volumes: paperless_staging::PAPERLESS_VOLUMES
                .iter()
                .map(|x| volume_name(p, x.logical_name))
                .collect(),
            generation: v["volume_set_id"].as_str().unwrap().to_owned(),
        }
    }
}
#[async_trait]
impl ComposeExecutor for Fake {
    async fn run(&mut self, a: &[String], cwd: &Path) -> Result<CommandOutput, LifecycleError> {
        if a.windows(2).any(|p| p == ["context", "show"]) {
            return Ok(CommandOutput {
                stdout: "desktop-linux\n".into(),
            });
        }
        if a.windows(2).any(|p| p == ["context", "inspect"]) {
            return Ok(CommandOutput {
                stdout: "\"npipe:////./pipe/docker_engine\"".into(),
            });
        }
        if a.iter().any(|x| x == "version") {
            return Ok(CommandOutput {
                stdout: r#"{"Os":"linux","Arch":"amd64"}"#.into(),
            });
        }
        if a.iter().any(|x| x == "volume") {
            if a.iter().any(|x| x == "ls") {
                let n = a
                    .iter()
                    .find_map(|x| x.strip_prefix("name=^").and_then(|x| x.strip_suffix('$')))
                    .unwrap();
                return Ok(CommandOutput {
                    stdout: if self.volumes.contains(n) {
                        format!("{n}\n")
                    } else {
                        String::new()
                    },
                });
            }
            if a.iter().any(|x| x == "rm") {
                self.volumes.remove(a.last().unwrap());
                return Ok(CommandOutput {
                    stdout: String::new(),
                });
            }
            let n = a.iter().skip_while(|x| *x != "inspect").nth(1).unwrap();
            let l = paperless_staging::PAPERLESS_VOLUMES
                .iter()
                .find(|x| n.ends_with(x.logical_name))
                .unwrap();
            return Ok(CommandOutput {
                stdout: format!(
                    r#"{{"Name":"{n}","Labels":{{"com.docker.compose.project":"{}","com.docker.compose.volume":"{}","io.neoth.paperless.volume-set-id":"{}"}}}}"#,
                    project_name(cwd),
                    l.logical_name,
                    self.generation
                ),
            });
        }
        if a.iter().any(|x| x == "container") && a.iter().any(|x| x == "ls") {
            let s = a
                .iter()
                .find_map(|x| x.strip_prefix("id="))
                .map(|id| {
                    if self.present.contains(id) {
                        format!("{id}\n")
                    } else {
                        String::new()
                    }
                })
                .unwrap_or_default();
            return Ok(CommandOutput { stdout: s });
        }
        if let Some(i) = a.iter().position(|x| x == "rm") {
            if a.get(i + 1) != Some(&"-f".into()) {
                return Err(LifecycleError::Command("fake_rm"));
            };
            self.present.remove(a.last().unwrap());
            return Ok(CommandOutput {
                stdout: String::new(),
            });
        }
        if a.iter().any(|x| x == "container") {
            let id = a.iter().skip_while(|x| *x != "inspect").nth(1).unwrap();
            let (s, img) = self.ids.get(id).unwrap();
            let mounts = paperless_staging::PAPERLESS_VOLUMES
                .iter()
                .filter(|x| x.service == s)
                .map(|x| {
                    format!(
                        r#"{{"Type":"volume","Name":"{}","Destination":"{}"}}"#,
                        volume_name(&project_name(cwd), x.logical_name),
                        x.destination
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let ports = if s == "webserver" {
                r#"{"8000/tcp":[{"HostIp":"127.0.0.1","HostPort":"18000"}]}"#
            } else {
                "{}"
            };
            return Ok(CommandOutput {
                stdout: format!(
                    r#"{{"Id":"{id}","Image":"{img}","State":{{"Running":false}},"Config":{{"Labels":{{"com.docker.compose.project":"{}","com.docker.compose.service":"{s}"}}}},"NetworkSettings":{{"Ports":{ports}}},"Mounts":[{mounts}]}}"#,
                    project_name(cwd)
                ),
            });
        }
        Err(LifecycleError::Command("fake"))
    }
}
fn dir(h: &Path) -> std::path::PathBuf {
    crate::config::InstancePaths::for_home(h)
        .paperless_root
        .join(RECEIPT_DIR)
}
async fn purged() -> (tempfile::TempDir, Credentials, Fake) {
    let (h, c, b) = installed_home_for_uninstall_test().await;
    let mut f = Fake::receipt(&b);
    uninstall_at_with(h.path(), &c, &mut f).await.unwrap();
    let p = paperless_purge::preview_at(h.path()).unwrap();
    paperless_purge::purge_at_with(h.path(), &p.confirmation, &mut f)
        .await
        .unwrap();
    (h, c, f)
}
async fn rotate(h: &Path, f: &mut Fake) -> Result<(), LifecycleError> {
    let p = crate::config::InstancePaths::for_home(h).paperless_root;
    let r = paperless_staging::open_owned_root_at(&p).unwrap();
    let b = read_binding(&r)?;
    let e = select_local_engine(f, &r).await?;
    rotate_completed_purge_generation_at(f, &e, &r, &b).await
}
fn make_journal(h: &Path) -> RotationJournal {
    let s = NAMES
        .iter()
        .map(|(role, n)| {
            let b = std::fs::read(dir(h).join(n)).unwrap();
            PaperlessPurgeAuthoritySource {
                role,
                live_name: (*n).into(),
                sha256: sha256(&b),
                bytes: b,
            }
        })
        .collect();
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir(h).join(RECEIPT_NAME)).unwrap()).unwrap();
    journal_from_authority(PaperlessCompletedPurgeAuthority {
        project: v["project"].as_str().unwrap().into(),
        volume_set_id: v["volume_set_id"].as_str().unwrap().into(),
        sources,
    })
    .unwrap()
}
fn seed_archives(h: &Path, j: &RotationJournal) {
    for a in &j.archives {
        std::fs::write(
            dir(h).join(archive_name(j, a)),
            std::fs::read(dir(h).join(a.role.live_name())).unwrap(),
        )
        .unwrap()
    }
}

#[tokio::test]
async fn install_uninstall_purge_fresh_install_rotates_and_archives_exact_old_receipts() {
    let (home, credentials, mut fake) = purged().await;
    let old_journal = make_journal(home.path());
    let old: Vec<_> = NAMES
        .iter()
        .map(|(_, name)| {
            (
                (*name).to_string(),
                std::fs::read(dir(home.path()).join(name)).unwrap(),
            )
        })
        .collect();
    rotate(home.path(), &mut fake).await.unwrap();
    assert!(!dir(home.path()).join(ROTATION_NAME).exists());
    let snapshot: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(&std::fs::read(dir(home.path()).join(VOLUME_SET_NAME)).unwrap())
            .unwrap();
    assert_ne!(snapshot.volume_set_id, old_journal.retired_volume_set_id);
    for (name, bytes) in old {
        if name == VOLUME_SET_NAME {
            assert_ne!(std::fs::read(dir(home.path()).join(&name)).unwrap(), bytes);
        } else {
            assert!(!dir(home.path()).join(&name).exists());
        }
        let archive = old_journal
            .archives
            .iter()
            .find(|a| a.role.live_name() == name)
            .unwrap();
        assert_eq!(
            std::fs::read(dir(home.path()).join(archive_name(&old_journal, archive))).unwrap(),
            bytes
        );
    }
    let fresh = reinstall_for_uninstall_test(home.path(), &credentials)
        .await
        .unwrap();
    assert_eq!(
        fresh.volume_set_id.as_deref(),
        Some(snapshot.volume_set_id.as_str())
    );
}
#[tokio::test]
async fn resumes_all_phases_and_every_archive_or_removal_prefix() {
    for phase in [
        RotationPhase::Prepared,
        RotationPhase::Archived,
        RotationPhase::LiveAuthorityCleared,
        RotationPhase::NewSnapshotWritten,
        RotationPhase::Complete,
    ] {
        for prefix in 0..=5 {
            let (h, _c, mut f) = purged().await;
            let mut j = make_journal(h.path());
            if phase == RotationPhase::Prepared {
                for a in j.archives.iter().take(prefix) {
                    std::fs::write(
                        dir(h.path()).join(archive_name(&j, a)),
                        std::fs::read(dir(h.path()).join(a.role.live_name())).unwrap(),
                    )
                    .unwrap()
                }
            } else {
                seed_archives(h.path(), &j);
                for a in j.archives.iter().take(if phase == RotationPhase::Archived {
                    prefix
                } else {
                    5
                }) {
                    std::fs::remove_file(dir(h.path()).join(a.role.live_name())).unwrap()
                }
                if phase == RotationPhase::NewSnapshotWritten || phase == RotationPhase::Complete {
                    std::fs::write(dir(h.path()).join(VOLUME_SET_NAME), &j.new_snapshot_bytes)
                        .unwrap()
                }
            }
            j.phase = phase;
            std::fs::write(
                dir(h.path()).join(ROTATION_NAME),
                serde_json::to_vec(&j).unwrap(),
            )
            .unwrap();
            rotate(h.path(), &mut f).await.unwrap();
            assert!(
                !dir(h.path()).join(ROTATION_NAME).exists(),
                "{phase:?}/{prefix}"
            )
        }
    }
}

#[tokio::test]
async fn archive_snapshot_and_terminal_absence_substitutions_reject() {
    let (h, _c, mut f) = purged().await;
    let j = make_journal(h.path());
    std::fs::write(
        dir(h.path()).join(archive_name(&j, &j.archives[0])),
        b"other",
    )
    .unwrap();
    std::fs::write(
        dir(h.path()).join(ROTATION_NAME),
        serde_json::to_vec(&j).unwrap(),
    )
    .unwrap();
    assert!(rotate(h.path(), &mut f).await.is_err());
    assert!(dir(h.path()).join(RECEIPT_NAME).exists());
    let (h, _c, mut f) = purged().await;
    f.present.insert(f.ids.keys().next().unwrap().clone());
    assert!(rotate(h.path(), &mut f).await.is_err());
    let (h, _c, mut f) = purged().await;
    let p = project_name(&crate::config::InstancePaths::for_home(h.path()).paperless_root);
    f.volumes.insert(volume_name(
        &p,
        paperless_staging::PAPERLESS_VOLUMES[0].logical_name,
    ));
    assert!(rotate(h.path(), &mut f).await.is_err());
}

#[tokio::test]
async fn substituted_new_snapshot_rejects_at_written_and_complete_crash_cuts() {
    for phase in [RotationPhase::NewSnapshotWritten, RotationPhase::Complete] {
        let (h, _c, mut f) = purged().await;
        let mut j = make_journal(h.path());
        seed_archives(h.path(), &j);
        for a in &j.archives {
            std::fs::remove_file(dir(h.path()).join(a.role.live_name())).unwrap()
        }
        j.phase = phase;
        std::fs::write(
            dir(h.path()).join(VOLUME_SET_NAME),
            b"substituted new snapshot",
        )
        .unwrap();
        std::fs::write(
            dir(h.path()).join(ROTATION_NAME),
            serde_json::to_vec(&j).unwrap(),
        )
        .unwrap();
        assert!(rotate(h.path(), &mut f).await.is_err(), "{phase:?}");
    }
}

#[tokio::test]
async fn archived_partial_live_removal_rechecks_old_container_and_volume_absence() {
    for container in [true, false] {
        let (h, _c, mut f) = purged().await;
        let mut j = make_journal(h.path());
        seed_archives(h.path(), &j);
        std::fs::remove_file(dir(h.path()).join(j.archives[0].role.live_name())).unwrap();
        j.phase = RotationPhase::Archived;
        std::fs::write(
            dir(h.path()).join(ROTATION_NAME),
            serde_json::to_vec(&j).unwrap(),
        )
        .unwrap();
        if container {
            f.present.insert(f.ids.keys().next().unwrap().clone())
        } else {
            let p = project_name(&crate::config::InstancePaths::for_home(h.path()).paperless_root);
            f.volumes.insert(volume_name(
                &p,
                paperless_staging::PAPERLESS_VOLUMES[0].logical_name,
            ))
        };
        assert!(
            rotate(h.path(), &mut f).await.is_err(),
            "container={container}"
        );
        assert!(!dir(h.path()).join(j.archives[0].role.live_name()).exists());
    }
}

#[tokio::test]
async fn normal_missing_volume_refuses_and_second_generation_can_rotate() {
    let (h, _c, b) = installed_home_for_uninstall_test().await;
    let mut f = Fake::receipt(&b);
    let p = crate::config::InstancePaths::for_home(h.path()).paperless_root;
    let r = paperless_staging::open_owned_root_at(&p).unwrap();
    let bind = read_binding(&r).unwrap();
    let e = select_local_engine(&mut f, &r).await.unwrap();
    f.volumes.pop_first();
    assert!(matches!(
        preflight_existing_volumes(&mut f, &e, &project_name(&p), &r, &bind).await,
        Err(LifecycleError::UnownedOrMismatch)
    ));
    let (h, c, mut f) = purged().await;
    rotate(h.path(), &mut f).await.unwrap();
    reinstall_for_uninstall_test(h.path(), &c).await.unwrap();
    let b = std::fs::read(lifecycle_receipt_path(h.path())).unwrap();
    let mut f = Fake::receipt(&b);
    uninstall_at_with(h.path(), &c, &mut f).await.unwrap();
    let p = paperless_purge::preview_at(h.path()).unwrap();
    paperless_purge::purge_at_with(h.path(), &p.confirmation, &mut f)
        .await
        .unwrap();
    rotate(h.path(), &mut f).await.unwrap();
}
