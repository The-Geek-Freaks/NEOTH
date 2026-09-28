use super::*;

use crate::channels::registry::ChannelAccountId;
use crate::config::FreedomConfig;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn write_home(home: &Path, backend: &str) {
    let mut freedom = FreedomConfig::default();
    if backend == "keychain" {
        freedom.secrets_backend = crate::config::SecretsBackend::Keychain;
    }
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&freedom).unwrap(),
    )
    .unwrap();
    std::fs::write(
        home.join("credentials.yaml"),
        "private_extension: retained\n",
    )
    .unwrap();
}

fn write_encrypted_home(home: &Path) {
    let mut public = serde_yaml::to_value(FreedomConfig::default()).unwrap();
    public.as_mapping_mut().unwrap().insert(
        serde_yaml::Value::String("wal".into()),
        serde_yaml::from_str("encryption: aes256_gcm_siv\n").unwrap(),
    );
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&public).unwrap(),
    )
    .unwrap();
    crate::wal::master_key::load_or_init_master_key(&crate::wal::master_key::master_key_path(home))
        .unwrap();
    std::fs::write(
        home.join("credentials.yaml"),
        "private_extension: retained\n",
    )
    .unwrap();
}

fn write_source(root: &Path, include: bool) -> PathBuf {
    let source = root.join("openclaw.json");
    if include {
        std::fs::write(root.join("slack.json5"), "{ slack: { accounts: { work: { botToken: 'xoxb-test-source-token', appToken: 'xapp-test-source-token' } } } }").unwrap();
        std::fs::write(&source, "{ channels: { $include: './slack.json5' } }").unwrap();
    } else {
        std::fs::write(&source, "{ channels: { slack: { accounts: { work: { botToken: 'xoxb-test-source-token', appToken: 'xapp-test-source-token' } } } } }").unwrap();
    }
    source
}

fn write_request(root: &Path, allowed: &str) -> PathBuf {
    let request = root.join("request.json");
    std::fs::write(&request, format!(r#"{{"schema_version":1,"channel":"slack","source_account":"work","account":"work","allowed_user_id":"{allowed}"}}"#)).unwrap();
    request
}

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    source: PathBuf,
    request: PathBuf,
}

fn new_fixture(include: bool) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_home(&home, "file");
    let source = write_source(root.path(), include);
    let request = write_request(root.path(), "U0123456789");
    Fixture {
        _root: root,
        home,
        source,
        request,
    }
}

fn encrypted_fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_encrypted_home(&home);
    let source = write_source(root.path(), false);
    let request = write_request(root.path(), "U0123456789");
    Fixture {
        _root: root,
        home,
        source,
        request,
    }
}

fn plan(fixture: &Fixture) -> Status {
    plan_at(&fixture.home, &fixture.source, &fixture.request).unwrap()
}

fn ok_outcome() -> SlackProbeOutcome {
    SlackProbeOutcome {
        report: crate::cli::channel::ChannelTestResult {
            channel: "slack".into(),
            account: None,
            status: "ok",
            detail: "fixture auth.test accepted".into(),
        },
        verified_team_id: Some("TTEST123".into()),
    }
}

async fn ok_probe(_: SlackProbeBinding) -> Result<SlackProbeOutcome> {
    Ok(ok_outcome())
}

fn pair(home: &Path) -> (Vec<u8>, Vec<u8>) {
    (
        std::fs::read(home.join("freedom.yaml")).unwrap(),
        std::fs::read(home.join("credentials.yaml")).unwrap(),
    )
}

#[tokio::test]
async fn slack_migration_happy_path_keeps_one_postimage_and_restores_exact_before() {
    let fixture = encrypted_fixture();
    let before = pair(&fixture.home);
    let id = plan(&fixture).id;
    let committed = apply_at_with(
        &fixture.home,
        &id,
        &fixture.source,
        &fixture.request,
        ok_probe,
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(committed.phase, Phase::Committed);
    let after = pair(&fixture.home);
    assert_ne!(after, before);
    assert!(crate::config::credentials::credentials_blob_is_encrypted(
        &after.1
    ));
    let loaded =
        crate::config::load_runtime_config_pair_from_path(&fixture.home.join("freedom.yaml"))
            .unwrap();
    let work = loaded
        .credentials
        .channel_accounts
        .slack
        .get(&ChannelAccountId::new("work").unwrap())
        .unwrap();
    assert_eq!(
        work.bot_token.as_ref().unwrap().expose(),
        "xoxb-test-source-token"
    );
    assert_eq!(
        work.app_token.as_ref().unwrap().expose(),
        "xapp-test-source-token"
    );
    let resumed = apply_at_with(
        &fixture.home,
        &id,
        &fixture.source,
        &fixture.request,
        |_| async { panic!("terminal apply must never re-probe") },
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(resumed.phase, Phase::Committed);
    assert_eq!(
        pair(&fixture.home),
        after,
        "terminal retry must retain exact generated ciphertext"
    );
    std::fs::write(&fixture.source, "{ channels: { slack: { accounts: { work: { botToken: 'xoxb-stale', appToken: 'xapp-stale' } } } } }").unwrap();
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            |_| async { panic!("a stale terminal retry must not probe") },
            |_| Ok(())
        )
        .await
        .is_err()
    );
    assert_eq!(
        pair(&fixture.home),
        after,
        "stale terminal retry cannot change the owned generation"
    );
    let rolled_back = rollback_at_with(&fixture.home, &id, |_| Ok(())).unwrap();
    assert_eq!(rolled_back.phase, Phase::RolledBack);
    assert_eq!(
        pair(&fixture.home),
        before,
        "rollback restores the original raw pair exactly"
    );
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            |_| async { panic!("rolled-back operation must reject forward retry") },
            |_| Ok(())
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn every_forward_checkpoint_reopens_to_committed_without_reprobing_after_publication() {
    let points = [
        Checkpoint::CustodySaved,
        Checkpoint::ApplyingRecorded,
        Checkpoint::PairPublished,
        Checkpoint::ForwardReceiptSaved,
        Checkpoint::CommittedRecorded,
        Checkpoint::ForwardReloadRecorded,
    ];
    for point in points {
        let fixture = new_fixture(false);
        let before = pair(&fixture.home);
        let id = plan(&fixture).id;
        let probes = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&probes);
        assert!(
            apply_at_with(
                &fixture.home,
                &id,
                &fixture.source,
                &fixture.request,
                move |_| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    async { Ok(ok_outcome()) }
                },
                |at| if at == point {
                    anyhow::bail!("crash at {at:?}")
                } else {
                    Ok(())
                }
            )
            .await
            .is_err(),
            "{point:?} must interrupt"
        );
        let before_resume_probes = probes.load(Ordering::SeqCst);
        let retry = Arc::clone(&probes);
        assert!(
            apply_at_with(
                &fixture.home,
                &id,
                &fixture.source,
                &fixture.request,
                move |_| {
                    retry.fetch_add(1, Ordering::SeqCst);
                    async { Ok(ok_outcome()) }
                },
                |_| Ok(())
            )
            .await
            .is_ok(),
            "{point:?} must reopen"
        );
        let expected_probes = if matches!(
            point,
            Checkpoint::PairPublished
                | Checkpoint::ForwardReceiptSaved
                | Checkpoint::CommittedRecorded
                | Checkpoint::ForwardReloadRecorded
        ) {
            before_resume_probes
        } else {
            before_resume_probes + 1
        };
        assert_eq!(
            probes.load(Ordering::SeqCst),
            expected_probes,
            "{point:?} retry probe count"
        );
        assert_ne!(
            pair(&fixture.home),
            before,
            "{point:?} must converge to a published pair"
        );
        assert!(
            fixture
                .home
                .join(crate::config::reload::RELOAD_SENTINEL_NAME)
                .exists(),
            "{point:?} must retain a reload request"
        );
        let status = status_at(&fixture.home, &id).unwrap();
        assert_eq!(status.phase, Phase::Committed);
        assert!(
            status.reload_requested,
            "{point:?} final journal must record forward reload request"
        );
    }
}

#[tokio::test]
async fn every_reverse_checkpoint_reopens_to_the_exact_before_pair() {
    let points = [
        Checkpoint::RollingBackRecorded,
        Checkpoint::PairRestored,
        Checkpoint::ReverseReceiptSaved,
        Checkpoint::RolledBackRecorded,
        Checkpoint::ReverseReloadRecorded,
    ];
    for point in points {
        let fixture = new_fixture(false);
        let before = pair(&fixture.home);
        let id = plan(&fixture).id;
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            ok_probe,
            |_| Ok(()),
        )
        .await
        .unwrap();
        assert!(
            rollback_at_with(&fixture.home, &id, |at| if at == point {
                anyhow::bail!("crash at {at:?}")
            } else {
                Ok(())
            })
            .is_err()
        );
        rollback_at_with(&fixture.home, &id, |_| Ok(())).unwrap();
        assert_eq!(
            pair(&fixture.home),
            before,
            "{point:?} recovery must restore the exact initial bytes"
        );
        assert!(
            fixture
                .home
                .join(crate::config::reload::RELOAD_SENTINEL_NAME)
                .exists(),
            "{point:?} must retain reverse reload request"
        );
        let status = status_at(&fixture.home, &id).unwrap();
        assert_eq!(status.phase, Phase::RolledBack);
        assert!(
            status.reload_requested,
            "{point:?} final journal must record reverse reload request"
        );
    }
}

#[tokio::test]
async fn source_include_request_and_target_drift_hold_without_publication() {
    let fixture = new_fixture(true);
    let id = plan(&fixture).id;
    std::fs::write(
        fixture._root.path().join("slack.json5"),
        "{ slack: { accounts: { work: { botToken: 'xoxb-changed', appToken: 'xapp-changed' } } } }",
    )
    .unwrap();
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            |_| async { panic!("source drift must precede probe") },
            |_| Ok(())
        )
        .await
        .is_err()
    );
    assert_eq!(
        status_at(&fixture.home, &id).unwrap().reason,
        Some(HoldReason::SourceOrRequestChanged)
    );

    let fixture = new_fixture(false);
    let id = plan(&fixture).id;
    std::fs::write(&fixture.request, r#"{"schema_version":1,"channel":"slack","source_account":"work","account":"work","allowed_user_id":"U9999999999"}"#).unwrap();
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            |_| async { panic!("request drift must precede probe") },
            |_| Ok(())
        )
        .await
        .is_err()
    );

    let fixture = new_fixture(false);
    let id = plan(&fixture).id;
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            |_: SlackProbeBinding| {
                let home = fixture.home.clone();
                async move {
                    std::fs::write(home.join("freedom.yaml"), "raced: true\n").unwrap();
                    Ok(ok_outcome())
                }
            },
            |_| Ok(())
        )
        .await
        .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(fixture.home.join("freedom.yaml")).unwrap(),
        "raced: true\n"
    );

    let fixture = new_fixture(false);
    let id = plan(&fixture).id;
    let before = pair(&fixture.home);
    assert!(apply_at_with(&fixture.home, &id, &fixture.source, &fixture.request, |_: SlackProbeBinding| {
        let request = fixture.request.clone();
        async move {
            std::fs::write(request, r#"{"schema_version":1,"channel":"slack","source_account":"work","account":"work","allowed_user_id":"U_CHANGED_DURING_PROBE"}"#).unwrap();
            Ok(ok_outcome())
        }
    }, |_| Ok(())).await.is_err(), "request mutation during auth.test must prevent publication");
    assert_eq!(
        pair(&fixture.home),
        before,
        "request mutation during probe cannot publish a pair"
    );
}

#[tokio::test]
async fn malformed_custody_and_terminal_receipt_never_become_success() {
    let fixture = new_fixture(false);
    let id = plan(&fixture).id;
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            ok_probe,
            |at| if at == Checkpoint::ApplyingRecorded {
                anyhow::bail!("stop")
            } else {
                Ok(())
            }
        )
        .await
        .is_err()
    );
    let custody = fixture
        .home
        .join(format!(".openclaw-slack-migration-{id}.custody.yaml"));
    let original_custody = std::fs::read(&custody).unwrap();
    std::fs::remove_file(&custody).unwrap();
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            ok_probe,
            |_| Ok(())
        )
        .await
        .is_err(),
        "a recorded custody capability cannot disappear"
    );
    std::fs::write(&custody, original_custody).unwrap();
    std::fs::write(&custody, "version: broken\n").unwrap();
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            ok_probe,
            |_| Ok(())
        )
        .await
        .is_err()
    );
    assert_eq!(
        status_at(&fixture.home, &id).unwrap().pair_state,
        "custody_invalid"
    );

    let fixture = new_fixture(false);
    let id = plan(&fixture).id;
    apply_at_with(
        &fixture.home,
        &id,
        &fixture.source,
        &fixture.request,
        ok_probe,
        |_| Ok(()),
    )
    .await
    .unwrap();
    let receipt = fixture
        .home
        .join("openclaw-migrations")
        .join(format!("{id}.committed.json"));
    std::fs::write(receipt, br#"{"version":1,"plan_binding":"0","custody_binding":"0","pair_before":"0","pair_after":"0","phase":"committed"}"#).unwrap();
    let status = status_at(&fixture.home, &id).unwrap();
    assert!(
        status.held && status.reason == Some(HoldReason::ReceiptInvalid),
        "a replaced terminal receipt must become typed held status"
    );
}

#[tokio::test]
async fn missing_state_after_custody_or_rollback_direction_refuses_both_directions() {
    let fixture = new_fixture(false);
    let id = plan(&fixture).id;
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            ok_probe,
            |at| if at == Checkpoint::ApplyingRecorded {
                anyhow::bail!("stop")
            } else {
                Ok(())
            }
        )
        .await
        .is_err()
    );
    let state = fixture
        .home
        .join("openclaw-migrations")
        .join(format!("{id}.state.json"));
    std::fs::remove_file(&state).unwrap();
    let after_custody = pair(&fixture.home);
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            ok_probe,
            |_| Ok(())
        )
        .await
        .is_err()
    );
    assert!(rollback_at_with(&fixture.home, &id, |_| Ok(())).is_err());
    assert_eq!(
        pair(&fixture.home),
        after_custody,
        "lost state after custody cannot select a direction"
    );

    let fixture = new_fixture(false);
    let id = plan(&fixture).id;
    apply_at_with(
        &fixture.home,
        &id,
        &fixture.source,
        &fixture.request,
        ok_probe,
        |_| Ok(()),
    )
    .await
    .unwrap();
    let after = pair(&fixture.home);
    assert!(
        rollback_at_with(&fixture.home, &id, |at| {
            if at == Checkpoint::RollingBackRecorded {
                anyhow::bail!("stop")
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    let state = fixture
        .home
        .join("openclaw-migrations")
        .join(format!("{id}.state.json"));
    std::fs::remove_file(&state).unwrap();
    assert!(
        rollback_at_with(&fixture.home, &id, |_| Ok(())).is_err(),
        "lost rollback state cannot silently resume a direction"
    );
    assert!(
        apply_at_with(
            &fixture.home,
            &id,
            &fixture.source,
            &fixture.request,
            ok_probe,
            |_| Ok(())
        )
        .await
        .is_err(),
        "lost rollback state cannot be reinterpreted as forward apply"
    );
    assert_eq!(
        pair(&fixture.home),
        after,
        "lost rollback state keeps the exact owned after-image"
    );
}

#[test]
fn planning_refuses_keychain_and_public_status_is_redacted_and_lock_bound() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    write_home(&home, "keychain");
    let source = write_source(root.path(), false);
    let request = write_request(root.path(), "U0123456789");
    assert!(
        plan_at(&home, &source, &request).is_err(),
        "single-file migration cannot claim keychain rollback"
    );

    let fixture = new_fixture(false);
    let status = plan(&fixture);
    let rendered = serde_json::to_string(&status).unwrap();
    for private in [
        "xoxb-test-source-token",
        "xapp-test-source-token",
        "U0123456789",
        "work",
    ] {
        assert!(
            !rendered.contains(private),
            "public status leaked {private}"
        );
    }
    let first = OperationStore::open(&fixture.home, &status.id, false).unwrap();
    assert!(
        OperationStore::open(&fixture.home, &status.id, false).is_err(),
        "same operation lock must exclude concurrent coordinator"
    );
    drop(first);
}
