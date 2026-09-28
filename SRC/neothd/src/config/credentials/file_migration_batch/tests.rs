use super::*;

fn account(name: &str) -> ChannelAccountId { ChannelAccountId::new(name).unwrap() }
fn binding() -> &'static str { "d1b3f484403613af2ec1c6761975edc7d69ad0ac53e269d53f4a7bc829bf9852" }
fn id() -> &'static str { "db290af9-0cb1-4271-aecd-dc45272a71a3" }
fn seed() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir=tempfile::tempdir().unwrap(); let freedom=dir.path().join("freedom.yaml"); let credentials=dir.path().join("credentials.yaml");
    std::fs::write(&freedom,"secrets_backend: file\nfuture_public: retained\n").unwrap();
    std::fs::write(&credentials,"future_private: retained\n").unwrap(); (dir,freedom,credentials)
}
fn inputs() -> Vec<FileMigrationInput> { vec![
    FileMigrationInput::Slack { account:account("one"),allowed_user_id:"UONE".into(),bot_token:SecretString::from("xoxb-one"),app_token:SecretString::from("xapp-one") },
    FileMigrationInput::Telegram { account:account("two"),allowed_user_id:2,token:SecretString::from("2:two") },
    FileMigrationInput::Slack { account:account("three"),allowed_user_id:"UTHREE".into(),bot_token:SecretString::from("xoxb-three"),app_token:SecretString::from("xapp-three") },
    FileMigrationInput::Telegram { account:account("four"),allowed_user_id:4,token:SecretString::from("4:four") },
] }

#[test]
fn aggregate_four_participants_publishes_one_unknown_preserving_pair_and_reverses() {
    let (_dir, freedom, credentials)=seed(); let before=(std::fs::read(&freedom).unwrap(),std::fs::read(&credentials).unwrap());
    let prepared=Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).unwrap();
    assert_eq!(prepared.participants().len(),4);
    let custody=prepared.persist_custody(&[Some("TONE".into()),None,Some("TTHREE".into()),None]).unwrap();
    assert_eq!(custody.inspect_at(&freedom,&credentials,id(),binding()).unwrap(),FileMigrationBatchState::Before);
    let first=custody.commit_if_before_at(&freedom,&credentials,id(),binding()).unwrap();
    assert_eq!(custody.commit_if_before_at(&freedom,&credentials,id(),binding()).unwrap(),first);
    let after=(std::fs::read(&freedom).unwrap(),std::fs::read(&credentials).unwrap()); assert_ne!(after,before);
    assert!(String::from_utf8_lossy(&after.0).contains("future_public")); assert!(String::from_utf8_lossy(&after.1).contains("future_private"));
    custody.rollback_if_exact_at(&freedom,&credentials,id(),binding()).unwrap(); assert_eq!((std::fs::read(&freedom).unwrap(),std::fs::read(&credentials).unwrap()),before);
}

#[test]
fn aggregate_batch_publishes_the_complete_runtime_configuration() {
    let (_dir, freedom, credentials) = seed();
    let custody = Credentials::prepare_file_migration_batch_at(&freedom, &credentials, inputs(), id(), binding()).unwrap()
        .persist_custody(&[Some("TONE".into()), None, Some("TTHREE".into()), None]).unwrap();
    custody.commit_if_before_at(&freedom, &credentials, id(), binding()).unwrap();
    let published = crate::config::load_runtime_config_pair_from_path(&freedom).unwrap();
    for (name, user, team, bot, app) in [
        ("one", "UONE", "TONE", "xoxb-one", "xapp-one"),
        ("three", "UTHREE", "TTHREE", "xoxb-three", "xapp-three"),
    ] {
        let policy = published.config.channel_accounts.slack.get(&account(name)).unwrap();
        assert_eq!(policy.allowed_user_id, user);
        assert_eq!(policy.team_id.as_deref(), Some(team));
        let secret = published.credentials.channel_accounts.slack.get(&account(name)).unwrap();
        assert_eq!(secret.bot_token.as_ref().unwrap().expose(), bot);
        assert_eq!(secret.app_token.as_ref().unwrap().expose(), app);
    }
    for (name, user, token) in [("two", 2, "2:two"), ("four", 4, "4:four")] {
        assert_eq!(published.config.channel_accounts.telegram.get(&account(name)).unwrap().allowed_user_id, user);
        assert_eq!(published.credentials.channel_accounts.telegram.get(&account(name)).unwrap().token.as_ref().unwrap().expose(), token);
    }
}

fn encrypted_seed() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let freedom = directory.path().join("freedom.yaml");
    let credentials = directory.path().join("credentials.yaml");
    let mut public = serde_yaml::to_value(crate::config::FreedomConfig::default()).unwrap();
    public.as_mapping_mut().unwrap().insert(serde_yaml::Value::String("wal".into()), serde_yaml::from_str("encryption: aes256_gcm_siv\nfuture_wal: retained\n").unwrap());
    std::fs::write(&freedom, serde_yaml::to_string(&public).unwrap()).unwrap();
    let key_path = crate::wal::master_key::master_key_path(directory.path());
    crate::wal::master_key::load_or_init_master_key(&key_path).unwrap();
    let key = crate::wal::master_key::config_subkey_at(directory.path()).unwrap();
    crate::util::atomic_write::atomic_write_private(&credentials, &super::super::encrypt_credentials_body(&key, "future_private: retained\n").unwrap()).unwrap();
    (directory, freedom, credentials)
}

#[test]
fn encrypted_postimage_is_immutable_across_reopen_resume_and_exact_rollback() {
    let (_dir, freedom, credentials) = encrypted_seed();
    let before = (std::fs::read(&freedom).unwrap(), std::fs::read(&credentials).unwrap());
    let custody = Credentials::prepare_file_migration_batch_at(&freedom, &credentials, inputs(), id(), binding()).unwrap()
        .persist_custody(&[Some("TONE".into()), None, Some("TTHREE".into()), None]).unwrap();
    custody.commit_if_before_at(&freedom, &credentials, id(), binding()).unwrap();
    let encrypted_after = std::fs::read(&credentials).unwrap();
    assert!(super::super::credentials_blob_is_encrypted(&encrypted_after));
    let reopened = FileMigrationBatchCustody::load_at(&freedom, id(), binding()).unwrap();
    reopened.commit_if_before_at(&freedom, &credentials, id(), binding()).unwrap();
    assert_eq!(std::fs::read(&credentials).unwrap(), encrypted_after, "resume must not mint another nonce");
    reopened.rollback_if_exact_at(&freedom, &credentials, id(), binding()).unwrap();
    assert_eq!((std::fs::read(&freedom).unwrap(), std::fs::read(&credentials).unwrap()), before);
}

#[test]
fn batch_preserves_telegram_and_same_team_slack_incarnations_but_rotates_changed_team_slack() {
    let (_dir, freedom, credentials)=seed();
    let one=Credentials::prepare_slack_account_upsert_at(&freedom,&credentials,account("one"),"OLDONE".into(),SecretString::from("xoxb-old-one"),SecretString::from("xapp-old-one")).unwrap();
    Credentials::commit_prepared_slack_account_upsert_at(one,"TONE").unwrap();
    let three=Credentials::prepare_slack_account_upsert_at(&freedom,&credentials,account("three"),"OLDTHREE".into(),SecretString::from("xoxb-old-three"),SecretString::from("xapp-old-three")).unwrap();
    Credentials::commit_prepared_slack_account_upsert_at(three,"TOLD").unwrap();
    let two=Credentials::prepare_telegram_account_upsert_at(&freedom,&credentials,account("two"),22,SecretString::from("2:old")).unwrap();
    Credentials::commit_prepared_telegram_account_upsert_at(two).unwrap();
    let old=crate::config::load_runtime_config_pair_from_path(&freedom).unwrap();
    let one_incarnation=old.config.channel_accounts.slack.get(&account("one")).unwrap().incarnation.clone();
    let three_incarnation=old.config.channel_accounts.slack.get(&account("three")).unwrap().incarnation.clone();
    let two_incarnation=old.config.channel_accounts.telegram.get(&account("two")).unwrap().incarnation.clone();
    let prepared=Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).unwrap();
    let custody=prepared.persist_custody(&[Some("TONE".into()),None,Some("TTHREE".into()),None]).unwrap();
    custody.commit_if_before_at(&freedom,&credentials,id(),binding()).unwrap();
    let published=crate::config::load_runtime_config_pair_from_path(&freedom).unwrap();
    assert_eq!(published.config.channel_accounts.slack.get(&account("one")).unwrap().incarnation,one_incarnation);
    assert_ne!(published.config.channel_accounts.slack.get(&account("three")).unwrap().incarnation,three_incarnation);
    assert_eq!(published.config.channel_accounts.telegram.get(&account("two")).unwrap().incarnation,two_incarnation);
}

#[test]
fn rejects_duplicate_keychain_and_wrong_team_vector_before_custody() {
    let (_dir, freedom, credentials)=seed();
    let duplicate=vec![FileMigrationInput::Telegram { account:account("same"),allowed_user_id:1,token:SecretString::from("1:a") },FileMigrationInput::Telegram { account:account("same"),allowed_user_id:2,token:SecretString::from("2:b") }];
    assert!(Credentials::prepare_file_migration_batch_at(&freedom,&credentials,duplicate,id(),binding()).is_err());
    let wrong = Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).unwrap();
    assert!(wrong.persist_custody(&[None,None,None,None]).is_err());
    std::fs::write(&freedom,"secrets_backend: keychain\n").unwrap();
    assert!(Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).is_err());
}

#[test]
fn custody_tamper_and_raw_drift_hold_without_overwrite() {
    let (_dir, freedom, credentials)=seed();
    let custody=Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).unwrap().persist_custody(&[Some("TONE".into()),None,Some("TTHREE".into()),None]).unwrap();
    custody.commit_if_before_at(&freedom,&credentials,id(),binding()).unwrap();
    std::fs::write(&credentials,"foreign: drift\n").unwrap();
    assert!(custody.rollback_if_exact_at(&freedom,&credentials,id(),binding()).is_err());
}

#[test]
fn optional_custody_is_absent_only_when_the_exact_capability_is_missing_and_collision_keeps_bytes() {
    let (_dir, freedom, credentials)=seed();
    assert!(matches!(FileMigrationBatchCustody::load_optional_at(&freedom,id(),binding()).unwrap(),FileMigrationBatchCustodyLoad::Absent));
    let custody=Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).unwrap()
        .persist_custody(&[Some("TONE".into()),None,Some("TTHREE".into()),None]).unwrap();
    let path=custody_path(&freedom,id()).unwrap();
    let original=std::fs::read(&path).unwrap();
    let digest=custody.custody_sha256();
    assert!(Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).unwrap()
        .persist_custody(&[Some("TONE".into()),None,Some("TTHREE".into()),None]).is_err());
    assert_eq!(std::fs::read(&path).unwrap(),original);
    assert_eq!(FileMigrationBatchCustody::load_at(&freedom,id(),binding()).unwrap().custody_sha256(),digest);
    std::fs::write(&path,"version: nope\n").unwrap();
    assert!(FileMigrationBatchCustody::load_optional_at(&freedom,id(),binding()).is_err());
    std::fs::write(&path,original).unwrap();
    assert!(custody.inspect_at(&freedom,&credentials,"9cb290af9-0cb1-4271-aecd-dc45272a71a3",binding()).is_err());
    assert!(custody.commit_if_before_at(&freedom,&credentials,id(),"e1b3f484403613af2ec1c6761975edc7d69ad0ac53e269d53f4a7bc829bf9852").is_err());
    assert!(custody.rollback_if_exact_at(&freedom,&credentials,"9cb290af9-0cb1-4271-aecd-dc45272a71a3",binding()).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_pair_is_rejected() {
    use std::os::unix::fs::symlink;
    let (dir, freedom, credentials)=seed(); let outside=dir.path().join("outside"); std::fs::write(&outside,"x").unwrap();
    std::fs::remove_file(&credentials).unwrap(); symlink(&outside,&credentials).unwrap();
    assert!(Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).is_err());
}

#[test]
fn absent_credentials_member_and_foreign_home_are_handled_safely() {
    let (dir, freedom, credentials)=seed();
    std::fs::remove_file(&credentials).unwrap();
    let custody=Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).unwrap()
        .persist_custody(&[Some("TONE".into()),None,Some("TTHREE".into()),None]).unwrap();
    custody.commit_if_before_at(&freedom,&credentials,id(),binding()).unwrap();
    assert!(credentials.exists());
    custody.rollback_if_exact_at(&freedom,&credentials,id(),binding()).unwrap();
    assert!(!credentials.exists(), "rollback must restore an absent credentials image");
    std::fs::write(&credentials,"future_private: retained\n").unwrap();
    let custody=Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).unwrap()
        .persist_custody(&[Some("TONE".into()),None,Some("TTHREE".into()),None]).unwrap();
    let other=dir.path().join("other"); std::fs::create_dir(&other).unwrap();
    let foreign_freedom=other.join("freedom.yaml"); let foreign_credentials=other.join("credentials.yaml");
    std::fs::write(&foreign_freedom,"secrets_backend: file\n").unwrap(); std::fs::write(&foreign_credentials,"\n").unwrap();
    assert!(custody.inspect_at(&foreign_freedom,&foreign_credentials,id(),binding()).is_err());
}
#[test]
fn every_dual_file_faultpoint_is_recoverable_in_forward_and_reverse_direction() {
    use super::super::DualFileFaultPoint;
    for point in [
        DualFileFaultPoint::JournalPrepared,
        DualFileFaultPoint::CredentialsPublished,
        DualFileFaultPoint::FreedomPublished,
        DualFileFaultPoint::DirectorySynced,
    ] {
        let (_dir, freedom, credentials)=seed();
        let custody=Credentials::prepare_file_migration_batch_at(&freedom,&credentials,inputs(),id(),binding()).unwrap()
            .persist_custody(&[Some("TONE".into()),None,Some("TTHREE".into()),None]).unwrap();
        let before=(std::fs::read(&freedom).unwrap(),std::fs::read(&credentials).unwrap());
        let mut forward_seen=false;
        assert!(custody.publish_with_test_fault(&freedom,&credentials,id(),binding(),true,|seen| {
            if seen == point { forward_seen=true; anyhow::bail!("injected forward fault") } else { Ok(()) }
        }).is_err());
        assert!(forward_seen, "forward hook was not reached for {point:?}");
        let reopened=FileMigrationBatchCustody::load_at(&freedom,id(),binding()).unwrap();
        let forward_after=matches!(point,DualFileFaultPoint::FreedomPublished|DualFileFaultPoint::DirectorySynced);
        assert_eq!(reopened.inspect_at(&freedom,&credentials,id(),binding()).unwrap(),if forward_after { FileMigrationBatchState::After } else { FileMigrationBatchState::Before },"forward {point:?}");
        assert_ne!(reopened.inspect_at(&freedom,&credentials,id(),binding()).unwrap(),FileMigrationBatchState::Mixed);
        reopened.commit_if_before_at(&freedom,&credentials,id(),binding()).unwrap();
        let after=(std::fs::read(&freedom).unwrap(),std::fs::read(&credentials).unwrap());
        let mut reverse_seen=false;
        assert!(reopened.publish_with_test_fault(&freedom,&credentials,id(),binding(),false,|seen| {
            if seen == point { reverse_seen=true; anyhow::bail!("injected reverse fault") } else { Ok(()) }
        }).is_err());
        assert!(reverse_seen, "reverse hook was not reached for {point:?}");
        let reopened=FileMigrationBatchCustody::load_at(&freedom,id(),binding()).unwrap();
        let reverse_before=forward_after;
        assert_eq!(reopened.inspect_at(&freedom,&credentials,id(),binding()).unwrap(),if reverse_before { FileMigrationBatchState::Before } else { FileMigrationBatchState::After },"reverse {point:?}");
        assert_ne!(reopened.inspect_at(&freedom,&credentials,id(),binding()).unwrap(),FileMigrationBatchState::Mixed);
        assert_eq!((std::fs::read(&freedom).unwrap(),std::fs::read(&credentials).unwrap()),if reverse_before { before } else { after },"reverse {point:?} exact stored image");
        reopened.rollback_if_exact_at(&freedom,&credentials,id(),binding()).unwrap();
    }
}
