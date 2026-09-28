use super::*;
use super::tests::{pair, write_encrypted_home, write_home};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

struct Fixture {
    root: tempfile::TempDir,
    home: PathBuf,
    source: PathBuf,
    request: PathBuf,
}

fn fixture(include: bool, encrypted: bool) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    if encrypted { write_encrypted_home(&home); } else { write_home(&home, "file"); }
    let source = root.path().join("openclaw.json");
    let channels = "{ telegram: { accounts: { work: { botToken: '123456:test-telegram-source-token' } } } }";
    if include {
        std::fs::write(root.path().join("telegram.json5"), channels).unwrap();
        std::fs::write(&source, "{ channels: { $include: './telegram.json5' } }").unwrap();
    } else {
        std::fs::write(&source, format!("{{ channels: {channels} }}")).unwrap();
    }
    let request = root.path().join("request.json");
    std::fs::write(&request, r#"{"schema_version":1,"channel":"telegram","source_account":"work","account":"destination","allowed_user_id":1234567}"#).unwrap();
    Fixture { root, home, source, request }
}

fn outcome() -> ProbeOutcome {
    ProbeOutcome::Telegram(super::super::ChannelTestResult {
        channel: "telegram".into(), account: Some(ChannelAccountId::new("destination").unwrap()), status: "ok",
        detail: "bot @display_only_not_authority".into(),
    })
}

async fn probe(binding: ProbeBinding) -> Result<ProbeOutcome> {
    let ProbeBinding::Telegram(binding) = binding else { anyhow::bail!("wrong probe participant") };
    assert_eq!(binding.allowed_user_id, 1234567);
    assert_eq!(binding.channel_ref.account_id.as_str(), "destination");
    assert_eq!(binding.token.expose(), "123456:test-telegram-source-token");
    Ok(outcome())
}

fn custody_path(f: &Fixture, id: &str) -> PathBuf {
    f.home.join(format!(".openclaw-telegram-migration-{id}.custody.yaml"))
}
fn plan(f: &Fixture) -> String { plan_at(&f.home, &f.source, &f.request).unwrap().id }

#[tokio::test]
async fn telegram_encrypted_lifecycle_preserves_incarnation_retry_and_exact_rollback() {
    let f = fixture(true, true);
    let before = pair(&f.home);
    let id = plan(&f);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let committed = apply_participant_at_with(&f.home, &id, &f.source, &f.request, |binding| async move {
        count.fetch_add(1, Ordering::SeqCst); probe(binding).await
    }, |_| Ok(())).await.unwrap();
    assert_eq!(committed.phase, Phase::Committed);
    assert_eq!(committed.committed_steps, 1);
    let after = pair(&f.home);
    assert_ne!(after, before);
    assert!(crate::config::credentials::credentials_blob_is_encrypted(&after.1));
    let config = crate::config::load_runtime_config_pair_from_path(&f.home.join("freedom.yaml")).unwrap().config;
    let account = ChannelAccountId::new("destination").unwrap();
    let policy = config.channel_accounts.telegram.get(&account).unwrap();
    assert_eq!(policy.allowed_user_id, 1234567);
    assert!(policy.incarnation.is_some());
    assert!(!String::from_utf8_lossy(&after.0).contains("display_only_not_authority"));
    let immutable = std::fs::read(custody_path(&f, &id)).unwrap();
    let retry = apply_participant_at_with(&f.home, &id, &f.source, &f.request, |_| async {
        panic!("committed retry must not probe")
    }, |_| Ok(())).await.unwrap();
    assert_eq!(retry.phase, Phase::Committed);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(pair(&f.home), after);
    assert_eq!(std::fs::read(custody_path(&f, &id)).unwrap(), immutable);
    let reversed = rollback_at_with(&f.home, &id, |_| Ok(())).unwrap();
    assert_eq!(reversed.phase, Phase::RolledBack);
    assert_eq!(reversed.reversed_steps, 1);
    assert_eq!(pair(&f.home), before);
    rollback_at_with(&f.home, &id, |_| Ok(())).unwrap();
    assert_eq!(pair(&f.home), before);
    assert!(apply_participant_at_with(&f.home, &id, &f.source, &f.request, probe, |_| Ok(())).await.is_err());
}

#[test]
fn telegram_keychain_and_invalid_typed_requests_reject_before_publication() {
    let f = fixture(false, false);
    write_home(&f.home, "keychain");
    let before = pair(&f.home);
    assert!(plan_at(&f.home, &f.source, &f.request).is_err());
    assert_eq!(pair(&f.home), before);
    let files: Vec<_> = std::fs::read_dir(&f.home).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert!(!files.iter().any(|name| name.ends_with(".custody.yaml")));
    assert!(!f.home.join(crate::config::reload::RELOAD_SENTINEL_NAME).exists());
    for user in ["0", "-1", "1.5", "\"123\"", "null"] {
        std::fs::write(&f.request, format!(r#"{{"schema_version":1,"channel":"telegram","source_account":"work","account":"destination","allowed_user_id":{user}}}"#)).unwrap();
        assert!(load_request(&f.request).is_err(), "{user}");
    }
    for request in [
        r#"{"schema_version":1,"channel":"telegram","source_account":"work","account":"destination","allowed_user_id":123,"extra":true}"#,
        r#"{"schema_version":1,"channel":"slack","source_account":"work","account":"destination","allowed_user_id":123}"#,
        r#"{"schema_version":1,"channel":"telegram","channel":"slack","source_account":"work","account":"destination","allowed_user_id":123}"#,
    ] { std::fs::write(&f.request, request).unwrap(); assert!(load_request(&f.request).is_err()); }
}

#[tokio::test(start_paused = true)]
async fn telegram_failed_wrong_kind_and_timed_out_probes_publish_nothing() {
    for mode in 0..4 {
        let f = fixture(false, false);
        let id = plan(&f);
        let before = pair(&f.home);
        let result = apply_participant_at_with(&f.home, &id, &f.source, &f.request, |_| async move {
            match mode {
                0 => anyhow::bail!("provider failure"),
                1 => { let ProbeOutcome::Telegram(mut report) = outcome() else { unreachable!() }; report.status = "fail"; Ok(ProbeOutcome::Telegram(report)) }
                2 => { tokio::time::sleep(Duration::from_secs(61)).await; Ok(outcome()) }
                _ => Ok(ProbeOutcome::Slack(super::tests::ok_outcome())),
            }
        }, |_| Ok(())).await;
        assert!(result.is_err(), "mode {mode}");
        assert_eq!(pair(&f.home), before);
        assert!(!custody_path(&f, &id).exists());
        assert!(!f.home.join(crate::config::reload::RELOAD_SENTINEL_NAME).exists());
        assert_eq!(status_at(&f.home, &id).unwrap().committed_steps, 0);
    }
}

#[tokio::test]
async fn telegram_source_include_request_and_pair_drift_refuse_publication() {
    for mode in 0..4 {
        let f = fixture(true, false);
        let id = plan(&f);
        let before = pair(&f.home);
        let changed = match mode { 0 => f.source.clone(), 1 => f.root.path().join("telegram.json5"), 2 => f.request.clone(), _ => f.home.join("freedom.yaml") };
        let result = apply_participant_at_with(&f.home, &id, &f.source, &f.request, |_| async move {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new().append(true).open(changed).unwrap();
            if mode == 2 { file.write_all(b"invalid").unwrap(); } else { file.write_all(b"\n ").unwrap(); }
            Ok(outcome())
        }, |_| Ok(())).await;
        assert!(result.is_err());
        let observed = pair(&f.home);
        if mode != 3 { assert_eq!(observed, before); } else { assert_eq!(observed.1, before.1); }
        assert!(!custody_path(&f, &id).exists());
        assert!(status_at(&f.home, &id).unwrap().held);
    }
}

#[tokio::test]
async fn telegram_all_coordinator_checkpoints_recover_only_the_recorded_direction() {
    for checkpoint in [Checkpoint::CustodySaved, Checkpoint::ApplyingRecorded, Checkpoint::PairPublished, Checkpoint::ForwardReceiptSaved, Checkpoint::CommittedRecorded, Checkpoint::ForwardReloadRecorded] {
        let f = fixture(false, true);
        let id = plan(&f);
        let before = pair(&f.home);
        assert!(apply_participant_at_with(&f.home, &id, &f.source, &f.request, probe, |at| {
            ensure!(at != checkpoint, "fixture interrupted"); Ok(())
        }).await.is_err());
        let stored = std::fs::read(custody_path(&f, &id)).unwrap();
        let status = apply_participant_at_with(&f.home, &id, &f.source, &f.request, probe, |_| Ok(())).await.unwrap();
        assert_eq!(status.phase, Phase::Committed);
        assert_eq!(std::fs::read(custody_path(&f, &id)).unwrap(), stored);
        rollback_at_with(&f.home, &id, |_| Ok(())).unwrap();
        assert_eq!(pair(&f.home), before);
    }
    for checkpoint in [Checkpoint::RollingBackRecorded, Checkpoint::PairRestored, Checkpoint::ReverseReceiptSaved, Checkpoint::RolledBackRecorded, Checkpoint::ReverseReloadRecorded] {
        let f = fixture(false, true);
        let id = plan(&f);
        let before = pair(&f.home);
        apply_participant_at_with(&f.home, &id, &f.source, &f.request, probe, |_| Ok(())).await.unwrap();
        assert!(rollback_at_with(&f.home, &id, |at| { ensure!(at != checkpoint, "fixture interrupted"); Ok(()) }).is_err());
        assert!(apply_participant_at_with(&f.home, &id, &f.source, &f.request, probe, |_| Ok(())).await.is_err());
        assert_eq!(rollback_at_with(&f.home, &id, |_| Ok(())).unwrap().phase, Phase::RolledBack);
        assert_eq!(pair(&f.home), before);
    }
}

#[tokio::test]
async fn telegram_missing_or_changed_custody_state_receipt_and_target_never_report_success() {
    for mode in 0..6 {
        let f = fixture(false, false);
        let id = plan(&f);
        apply_participant_at_with(&f.home, &id, &f.source, &f.request, probe, |_| Ok(())).await.unwrap();
        let after = pair(&f.home);
        match mode {
            0 => std::fs::remove_file(custody_path(&f, &id)).unwrap(),
            1 => std::fs::write(custody_path(&f, &id), b"version: broken\n").unwrap(),
            2 => std::fs::remove_file(f.home.join("openclaw-migrations").join(format!("{id}.state.json"))).unwrap(),
            3 => std::fs::remove_file(f.home.join("openclaw-migrations").join(format!("{id}.committed.json"))).unwrap(),
            4 => std::fs::write(f.home.join("openclaw-migrations").join(format!("{id}.committed.json")), b"{}").unwrap(),
            _ => { use std::io::Write as _; std::fs::OpenOptions::new().append(true).open(f.home.join("credentials.yaml")).unwrap().write_all(b"\nforeign: true\n").unwrap(); }
        }
        let status = status_at(&f.home, &id);
        assert!(status.as_ref().map_or(true, |value| value.held || value.committed_steps == 0));
        assert!(apply_participant_at_with(&f.home, &id, &f.source, &f.request, probe, |_| Ok(())).await.is_err());
        // Missing terminal proof can still be safely reversed from exact custody;
        // missing custody/direction or foreign raw bytes cannot.
        if matches!(mode, 0 | 1 | 2 | 5) { assert!(rollback_at_with(&f.home, &id, |_| Ok(())).is_err()); }
        if mode != 5 { assert_eq!(pair(&f.home), after); }
    }
}

#[tokio::test]
async fn slack_v1_plan_request_and_custody_keep_their_original_serialization() {
    let raw = r#"{"version":1,"id":"01900000-0000-7000-8000-000000000001","source_binding":"source","request_binding":"request","pair_before":"pair"}"#;
    let legacy: Plan = serde_json::from_str(raw).unwrap();
    assert!(legacy.valid_version());
    assert_eq!(legacy.kind(), ParticipantKind::Slack);
    assert_eq!(serde_json::to_string(&legacy).unwrap(), raw);
    assert_eq!(plan_binding(&legacy).unwrap(), hash(b"neoth-openclaw-migration-plan-v1\0", raw.as_bytes()));
    let f = super::tests::new_fixture(false);
    let request = load_request(&f.request).unwrap();
    let expected = serde_json::to_vec(&(1u8, "slack", "work", "work", "U0123456789")).unwrap();
    assert_eq!(request_binding(&request).unwrap(), hash(b"neoth-openclaw-migration-request-v1\0", &expected));
    let id = plan_at(&f.home, &f.source, &f.request).unwrap().id;
    let before = pair(&f.home);
    apply_participant_at_with(&f.home, &id, &f.source, &f.request, |binding| async move {
        let ProbeBinding::Slack(binding) = binding else { anyhow::bail!("wrong participant") };
        Ok(ProbeOutcome::Slack(super::tests::ok_probe(binding).await?))
    }, |_| Ok(())).await.unwrap();
    let store = OperationStore::open(&f.home, &id, false).unwrap();
    let (legacy, _) = store.load().unwrap();
    assert_eq!(legacy.version, 1);
    assert!(legacy.participant.is_none());
    let old_reader = crate::config::credentials::SlackMigrationCustody::load_at(&f.home.join("freedom.yaml"), &id, &plan_binding(&legacy).unwrap()).unwrap();
    assert_eq!(old_reader.inspect_at(&f.home.join("freedom.yaml"), &f.home.join("credentials.yaml"), &id, &plan_binding(&legacy).unwrap()).unwrap(), crate::config::credentials::SlackMigrationState::After);
    drop(store);
    assert_eq!(status_at(&f.home, &id).unwrap().phase, Phase::Committed);
    rollback_at_with(&f.home, &id, |_| Ok(())).unwrap();
    assert_eq!(pair(&f.home), before);
    for invalid in [(1, Some(ParticipantKind::Telegram)), (2, None), (2, Some(ParticipantKind::Slack))] {
        let mut invalid_plan = legacy.clone(); invalid_plan.version = invalid.0; invalid_plan.participant = invalid.1;
        assert!(!invalid_plan.valid_version());
    }
}
