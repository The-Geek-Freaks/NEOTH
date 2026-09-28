use super::tests::{pair, write_encrypted_home, write_home};
use super::*;
use crate::channels::registry::ChannelAccountId;
use anyhow::{Result, ensure};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    source: PathBuf,
    include: PathBuf,
    request: PathBuf,
}

fn batch_request() -> &'static str {
    r#"{"schema_version":3,"channel":"batch","participants":[{"schema_version":1,"channel":"slack","source_account":"s1","account":"s1","allowed_user_id":"U100"},{"schema_version":1,"channel":"telegram","source_account":"t1","account":"t1","allowed_user_id":101},{"schema_version":1,"channel":"slack","source_account":"s2","account":"s2","allowed_user_id":"U200"},{"schema_version":1,"channel":"telegram","source_account":"t2","account":"t2","allowed_user_id":202}]}"#
}

fn fixture(encrypted: bool) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    if encrypted { write_encrypted_home(&home) } else { write_home(&home, "file") }
    let source = root.path().join("openclaw.json");
    let include = root.path().join("accounts.json5");
    std::fs::write(&source, "{ channels: { $include: './accounts.json5' } }").unwrap();
    std::fs::write(&include, r#"{ slack: { accounts: { s1: { botToken: 'xoxb-s1', appToken: 'xapp-s1' }, s2: { botToken: 'xoxb-s2', appToken: 'xapp-s2' } } }, telegram: { accounts: { t1: { botToken: '111:t1-token' }, t2: { botToken: '222:t2-token' } } } }"#).unwrap();
    let request = root.path().join("request.json");
    std::fs::write(&request, batch_request()).unwrap();
    Fixture { _root: root, home, source, include, request }
}

fn plan(f: &Fixture) -> String { plan_at(&f.home, &f.source, &f.request).unwrap().id }
fn custody_path(f: &Fixture, id: &str) -> PathBuf { f.home.join(format!(".openclaw-file-batch-migration-{id}.custody.yaml")) }
fn state_path(f: &Fixture, id: &str) -> PathBuf { f.home.join("openclaw-migrations").join(format!("{id}.state.json")) }
fn terminal_path(f: &Fixture, id: &str, phase: &str) -> PathBuf { f.home.join("openclaw-migrations").join(format!("{id}.{phase}.json")) }

fn slack_outcome(account: &str, team: &str) -> ProbeOutcome {
    ProbeOutcome::Slack(SlackProbeOutcome { report: crate::cli::channel::ChannelTestResult { channel: "slack".into(), account: Some(ChannelAccountId::new(account).unwrap()), status: "ok", detail: "fixture Slack auth accepted".into() }, verified_team_id: Some(team.into()) })
}
fn telegram_outcome(account: &str) -> ProbeOutcome {
    ProbeOutcome::Telegram(crate::cli::channel::ChannelTestResult { channel: "telegram".into(), account: Some(ChannelAccountId::new(account).unwrap()), status: "ok", detail: "fixture Telegram validate accepted".into() })
}
fn outcome_for(binding: &ProbeBinding) -> Result<ProbeOutcome> {
    match binding {
        ProbeBinding::Slack(binding) => {
            let account = binding.channel_ref.account_id.as_str();
            match account {
                "s1" => { ensure!(binding.bot_token.expose() == "xoxb-s1"); Ok(slack_outcome("s1", "TS1")) }
                "s2" => { ensure!(binding.bot_token.expose() == "xoxb-s2"); Ok(slack_outcome("s2", "TS2")) }
                _ => anyhow::bail!("unexpected Slack account {account}"),
            }
        }
        ProbeBinding::Telegram(binding) => {
            let account = binding.channel_ref.account_id.as_str();
            match account {
                "t1" => { ensure!(binding.allowed_user_id == 101 && binding.token.expose() == "111:t1-token"); Ok(telegram_outcome("t1")) }
                "t2" => { ensure!(binding.allowed_user_id == 202 && binding.token.expose() == "222:t2-token"); Ok(telegram_outcome("t2")) }
                _ => anyhow::bail!("unexpected Telegram account {account}"),
            }
        }
    }
}

#[tokio::test]
async fn batch_encrypted_mixed_slack_and_telegram_lifecycle_retries_without_reprobe_and_rolls_back_exactly() {
    let f = fixture(true);
    let before = pair(&f.home);
    let id = plan(&f);
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let committed = apply_many_at_with(&f.home, &id, &f.source, &f.request, move |binding| {
        seen.fetch_add(1, Ordering::SeqCst);
        async move { outcome_for(&binding) }
    }, |_| Ok(())).await.unwrap();
    assert_eq!(committed.phase, Phase::Committed);
    assert_eq!(committed.committed_steps, 4);
    assert_eq!(committed.participants, 4);
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    let after = pair(&f.home);
    assert_ne!(after, before);
    assert!(crate::config::credentials::credentials_blob_is_encrypted(&after.1));
    let loaded = crate::config::load_runtime_config_pair_from_path(&f.home.join("freedom.yaml")).unwrap();
    for (account, bot, app) in [("s1", "xoxb-s1", "xapp-s1"), ("s2", "xoxb-s2", "xapp-s2")] {
        let value = loaded.credentials.channel_accounts.slack.get(&ChannelAccountId::new(account).unwrap()).unwrap();
        assert_eq!(value.bot_token.as_ref().unwrap().expose(), bot);
        assert_eq!(value.app_token.as_ref().unwrap().expose(), app);
    }
    for (account, user) in [("t1", 101), ("t2", 202)] {
        let value = loaded.config.channel_accounts.telegram.get(&ChannelAccountId::new(account).unwrap()).unwrap();
        assert_eq!(value.allowed_user_id, user);
        assert!(value.incarnation.is_some());
    }
    let raw_custody = std::fs::read(custody_path(&f, &id)).unwrap();
    let retry = apply_many_at_with(&f.home, &id, &f.source, &f.request, |_| async { panic!("committed retry must not probe") }, |_| Ok(())).await.unwrap();
    assert_eq!(retry.phase, Phase::Committed);
    assert_eq!(pair(&f.home), after);
    assert_eq!(std::fs::read(custody_path(&f, &id)).unwrap(), raw_custody);
    assert_eq!(rollback_at_with(&f.home, &id, |_| Ok(())).unwrap().phase, Phase::RolledBack);
    assert_eq!(pair(&f.home), before);
}

#[test]
fn batch_rejects_malformed_nested_empty_oversize_duplicate_or_keychain_request_before_pair_or_custody_write() {
    let f = fixture(false);
    let before = pair(&f.home);
    let invalid = [
        r#"{"schema_version":3,"channel":"batch","participants":[]}"#,
        r#"{"schema_version":3,"channel":"batch","participants":[{"schema_version":3,"channel":"batch","participants":[]}]}"#,
        r#"{"schema_version":3,"channel":"batch","participants":[{"schema_version":1,"channel":"slack","source_account":"s1","account":"x","allowed_user_id":"U1"},{"schema_version":1,"channel":"slack","source_account":"s1","account":"y","allowed_user_id":"U2"}]}"#,
        r#"{"schema_version":3,"channel":"batch","participants":[{"schema_version":1,"channel":"telegram","source_account":"t1","account":"x","allowed_user_id":1},{"schema_version":1,"channel":"telegram","source_account":"t2","account":"x","allowed_user_id":2}]}"#,
        r#"{"schema_version":3,"channel":"batch","participants":[{"schema_version":1,"channel":"slack","source_account":"s1","account":"s1","allowed_user_id":"U1"}],"extra":true}"#,
    ];
    for raw in invalid { std::fs::write(&f.request, raw).unwrap(); assert!(plan_at(&f.home, &f.source, &f.request).is_err()); assert_eq!(pair(&f.home), before); }
    let participants = (0..33).map(|n| format!(r#"{{"schema_version":1,"channel":"slack","source_account":"s{n}","account":"d{n}","allowed_user_id":"U{n}"}}"#)).collect::<Vec<_>>().join(",");
    std::fs::write(&f.request, format!(r#"{{"schema_version":3,"channel":"batch","participants":[{participants}]}}"#)).unwrap();
    assert!(plan_at(&f.home, &f.source, &f.request).is_err());
    write_home(&f.home, "keychain");
    let keychain_before = pair(&f.home);
    std::fs::write(&f.request, batch_request()).unwrap();
    assert!(plan_at(&f.home, &f.source, &f.request).is_err());
    assert_eq!(pair(&f.home), keychain_before);
    assert!(!std::fs::read_dir(&f.home).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().contains("batch-migration")));
}

#[tokio::test(start_paused = true)]
async fn batch_provider_wrong_kind_and_timeout_at_each_position_leave_pair_and_custody_untouched() {
    for position in 0..4 {
        for mode in 0..3 {
            let f = fixture(false); let id = plan(&f); let before = pair(&f.home); let calls = Arc::new(AtomicUsize::new(0)); let count = Arc::clone(&calls);
            let result = apply_many_at_with(&f.home, &id, &f.source, &f.request, move |binding| {
                let call = count.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call == position { match mode { 0 => anyhow::bail!("provider failure at {position}"), 1 => Ok(match binding { ProbeBinding::Slack(_) => telegram_outcome("t1"), ProbeBinding::Telegram(_) => slack_outcome("s1", "TS1") }), _ => { tokio::time::sleep(Duration::from_secs(61)).await; outcome_for(&binding) } } } else { outcome_for(&binding) }
                }
            }, |_| Ok(())).await;
            assert!(result.is_err(), "position {position} mode {mode}");
            assert_eq!(pair(&f.home), before); assert!(!custody_path(&f, &id).exists()); assert_eq!(calls.load(Ordering::SeqCst), position + 1);
        }
    }
}

#[tokio::test]
async fn batch_source_include_or_request_mutation_after_each_probe_holds_before_the_next_probe() {
    for mutate_request in [false, true] {
        for position in 0..4 {
            let f = fixture(false); let id = plan(&f); let before = pair(&f.home); let target = if mutate_request { f.request.clone() } else { f.include.clone() }; let calls = Arc::new(AtomicUsize::new(0)); let count = Arc::clone(&calls);
            let result = apply_many_at_with(&f.home, &id, &f.source, &f.request, move |binding| { let call = count.fetch_add(1, Ordering::SeqCst); let target = target.clone(); async move { let outcome = outcome_for(&binding)?; if call == position { std::fs::write(target, if mutate_request { b"invalid request" } else { b"{ slack: { accounts: {} } }" }).unwrap(); } Ok(outcome) } }, |_| Ok(())).await;
            assert!(result.is_err()); assert!(status_at(&f.home, &id).unwrap().held); assert_eq!(calls.load(Ordering::SeqCst), position + 1); assert_eq!(pair(&f.home), before); assert!(!custody_path(&f, &id).exists());
        }
    }
}

#[tokio::test]
async fn batch_target_pair_drift_refuses_and_never_publishes_a_mixed_generation() {
    let f = fixture(false); let id = plan(&f); let before = pair(&f.home); let drift = f.home.join("freedom.yaml");
    let result = apply_many_at_with(&f.home, &id, &f.source, &f.request, move |binding| { let drift = drift.clone(); async move { let outcome = outcome_for(&binding)?; std::fs::OpenOptions::new().append(true).open(drift).unwrap().write_all(b"\nforeign: true\n").unwrap(); Ok(outcome) } }, |_| Ok(())).await;
    assert!(result.is_err()); assert!(status_at(&f.home, &id).unwrap().held); assert_eq!(pair(&f.home).1, before.1); assert!(!custody_path(&f, &id).exists());
}

#[tokio::test]
async fn batch_all_forward_and_reverse_checkpoints_recover_only_the_recorded_direction_with_immutable_raw_custody() {
    let forward = [Checkpoint::CustodySaved, Checkpoint::ApplyingRecorded, Checkpoint::PairPublished, Checkpoint::ForwardReceiptSaved, Checkpoint::CommittedRecorded, Checkpoint::ForwardReloadRecorded];
    for checkpoint in forward { let f = fixture(true); let id = plan(&f); let before = pair(&f.home); assert!(apply_many_at_with(&f.home, &id, &f.source, &f.request, |binding| async move { outcome_for(&binding) }, |at| if at == checkpoint { anyhow::bail!("interrupt") } else { Ok(()) }).await.is_err()); let custody = std::fs::read(custody_path(&f, &id)).unwrap(); assert_eq!(apply_many_at_with(&f.home, &id, &f.source, &f.request, |binding| async move { outcome_for(&binding) }, |_| Ok(())).await.unwrap().phase, Phase::Committed); assert_eq!(std::fs::read(custody_path(&f, &id)).unwrap(), custody); rollback_at_with(&f.home, &id, |_| Ok(())).unwrap(); assert_eq!(pair(&f.home), before); }
    let reverse = [Checkpoint::RollingBackRecorded, Checkpoint::PairRestored, Checkpoint::ReverseReceiptSaved, Checkpoint::RolledBackRecorded, Checkpoint::ReverseReloadRecorded];
    for checkpoint in reverse { let f = fixture(true); let id = plan(&f); let before = pair(&f.home); apply_many_at_with(&f.home, &id, &f.source, &f.request, |binding| async move { outcome_for(&binding) }, |_| Ok(())).await.unwrap(); assert!(rollback_at_with(&f.home, &id, |at| if at == checkpoint { anyhow::bail!("interrupt") } else { Ok(()) }).is_err()); assert_eq!(rollback_at_with(&f.home, &id, |_| Ok(())).unwrap().phase, Phase::RolledBack); assert_eq!(pair(&f.home), before); }
}

#[tokio::test]
async fn batch_stale_lost_or_malformed_custody_state_and_terminals_refuse_success() {
    for mode in 0..5 { let f = fixture(false); let id = plan(&f); apply_many_at_with(&f.home, &id, &f.source, &f.request, |binding| async move { outcome_for(&binding) }, |_| Ok(())).await.unwrap(); let after = pair(&f.home); match mode { 0 => std::fs::remove_file(custody_path(&f, &id)).unwrap(), 1 => std::fs::write(custody_path(&f, &id), b"bad\n").unwrap(), 2 => std::fs::remove_file(state_path(&f, &id)).unwrap(), 3 => std::fs::write(terminal_path(&f, &id, "committed"), b"{}").unwrap(), _ => std::fs::OpenOptions::new().append(true).open(f.home.join("credentials.yaml")).unwrap().write_all(b"\nforeign: true\n").unwrap() }; assert!(status_at(&f.home, &id).as_ref().map_or(true, |status| status.held || status.committed_steps == 0)); assert!(apply_many_at_with(&f.home, &id, &f.source, &f.request, |binding| async move { outcome_for(&binding) }, |_| Ok(())).await.is_err()); if mode != 4 { assert_eq!(pair(&f.home), after); } }
}

#[test]
fn batch_slack_v1_and_telegram_v2_plans_remain_readable_while_v3_batch_is_distinct() {
    let slack: Plan = serde_json::from_str(r#"{"version":1,"id":"01900000-0000-7000-8000-000000000001","source_binding":"source","request_binding":"request","pair_before":"pair"}"#).unwrap();
    let telegram: Plan = serde_json::from_str(r#"{"version":2,"id":"01900000-0000-7000-8000-000000000002","source_binding":"source","request_binding":"request","pair_before":"pair","participant":"telegram"}"#).unwrap();
    assert!(slack.valid_version() && telegram.valid_version()); assert_eq!(slack.kind(), ParticipantKind::Slack); assert_eq!(telegram.kind(), ParticipantKind::Telegram);
    let f = fixture(false); let id = plan(&f); let store = OperationStore::open(&f.home, &id, false).unwrap(); let (batch, _) = store.load().unwrap(); assert!(batch.valid_version()); assert_eq!(batch.version, 3); assert_eq!(batch.kind(), ParticipantKind::Batch); assert_ne!(plan_binding(&batch).unwrap(), plan_binding(&telegram).unwrap());
}
