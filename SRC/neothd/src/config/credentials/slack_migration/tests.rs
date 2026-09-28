use super::*;
use super::super::DualFileFaultPoint;

fn account(name: &str) -> ChannelAccountId {
    ChannelAccountId::new(name).unwrap()
}

fn commitment() -> &'static str {
    "d1b3f484403613af2ec1c6761975edc7d69ad0ac53e269d53f4a7bc829bf9852"
}

#[test]
fn snapshot_capture_preserves_missing_parent_as_absent_without_creating_it() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("not-created");
    let snapshot = FileSnapshot::capture(&parent.join("credentials.yaml")).unwrap();
    assert!(matches!(snapshot, FileSnapshot::Missing));
    assert!(!parent.exists());
}

fn seed() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let freedom = directory.path().join("freedom.yaml");
    let credentials = directory.path().join("credentials.yaml");
    std::fs::write(&freedom, "secrets_backend: file\nfuture_public: retained\n").unwrap();
    std::fs::write(&credentials, "future_private: retained\n").unwrap();
    (directory, freedom, credentials)
}

fn encrypted_seed() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let freedom = directory.path().join("freedom.yaml");
    let credentials = directory.path().join("credentials.yaml");
    let mut public = serde_yaml::to_value(crate::config::FreedomConfig::default()).unwrap();
    public.as_mapping_mut().unwrap().insert(
        serde_yaml::Value::String("wal".to_owned()),
        serde_yaml::from_str("encryption: aes256_gcm_siv\nfuture_wal: retained\n").unwrap(),
    );
    std::fs::write(&freedom, serde_yaml::to_string(&public).unwrap()).unwrap();
    let key_path = crate::wal::master_key::master_key_path(directory.path());
    crate::wal::master_key::load_or_init_master_key(&key_path).unwrap();
    let key = crate::wal::master_key::config_subkey_at(directory.path()).unwrap();
    crate::util::atomic_write::atomic_write_private(
        &credentials,
        &super::super::encrypt_credentials_body(&key, "future_private: retained\n").unwrap(),
    ).unwrap();
    (directory, freedom, credentials)
}

fn prepared(freedom: &Path, credentials: &Path) -> PreparedSlackMigration {
    Credentials::prepare_slack_migration_upsert_at(
        freedom,
        credentials,
        account("ops"),
        "U123ABC".into(),
        SecretString::from("xoxb-migration-fixture"),
        SecretString::from("xapp-migration-fixture"),
        "db290af9-0cb1-4271-aecd-dc45272a71a3",
        commitment(),
    )
    .unwrap()
}

#[test]
fn custody_commits_the_immutable_team_bound_pair_and_reverses_it_exactly() {
    let (_directory, freedom, credentials) = seed();
    let before = (std::fs::read(&freedom).unwrap(), std::fs::read(&credentials).unwrap());
    let custody = prepared(&freedom, &credentials)
        .persist_slack_migration_custody_at("TTEAM1")
        .unwrap();
    assert_eq!(custody.inspect_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap(), SlackMigrationState::Before);
    let first = custody.commit_if_before_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap();
    let after = (std::fs::read(&freedom).unwrap(), std::fs::read(&credentials).unwrap());
    assert_ne!(after, before);
    assert_eq!(custody.inspect_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap(), SlackMigrationState::After);
    assert_eq!(first, custody.commit_if_before_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap());
    assert_eq!(custody.rollback_if_exact_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap(), SlackMigrationState::Before);
    assert_eq!((std::fs::read(&freedom).unwrap(), std::fs::read(&credentials).unwrap()), before);
}

#[test]
fn custody_refuses_tampering_and_never_overwrites_a_mixed_pair() {
    let (_directory, freedom, credentials) = seed();
    let custody = prepared(&freedom, &credentials)
        .persist_slack_migration_custody_at("TTEAM1")
        .unwrap();
    let path = custody_path(&freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3").unwrap();
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, "version: 9\n").unwrap();
    assert!(SlackMigrationCustody::load_at(&freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).is_err());
    assert!(custody.inspect_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).is_err());
    std::fs::write(&path, original).unwrap();
    std::fs::write(&freedom, "secrets_backend: file\nconcurrent: drift\n").unwrap();
    assert_eq!(custody.inspect_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap(), SlackMigrationState::Mixed);
    assert!(custody.commit_if_before_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).is_err());
    assert!(custody.rollback_if_exact_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).is_err());
    assert!(std::fs::read_to_string(&freedom).unwrap().contains("concurrent: drift"));
}

#[test]
fn every_forward_and_reverse_pair_journal_boundary_recovers_to_one_exact_image() {
    let points = [
        DualFileFaultPoint::JournalPrepared,
        DualFileFaultPoint::CredentialsPublished,
        DualFileFaultPoint::FreedomPublished,
        DualFileFaultPoint::DirectorySynced,
    ];
    for point in points {
        let (_directory, freedom, credentials) = seed();
        let before = (std::fs::read(&freedom).unwrap(), std::fs::read(&credentials).unwrap());
        let custody = prepared(&freedom, &credentials)
            .persist_slack_migration_custody_at("TTEAM1")
            .unwrap();
        let _ = custody.commit_if_before_at_using_test_fault(
            &freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment(),
            |seen| if seen == point { anyhow::bail!("stop at {seen:?}") } else { Ok(()) },
        );
        let reopened = SlackMigrationCustody::load_at(
            &freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment(),
        ).unwrap();
        let state = reopened.inspect_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap();
        let forward_after = matches!(point, DualFileFaultPoint::FreedomPublished | DualFileFaultPoint::DirectorySynced);
        assert_eq!(state, if forward_after { SlackMigrationState::After } else { SlackMigrationState::Before }, "forward {point:?}");
        reopened.commit_if_before_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap();
        let after = (std::fs::read(&freedom).unwrap(), std::fs::read(&credentials).unwrap());
        let _ = reopened.rollback_if_exact_at_using_test_fault(
            &freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment(),
            |seen| if seen == point { anyhow::bail!("stop at {seen:?}") } else { Ok(()) },
        );
        let reopened = SlackMigrationCustody::load_at(
            &freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment(),
        ).unwrap();
        let state = reopened.inspect_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap();
        let reverse_before = matches!(point, DualFileFaultPoint::FreedomPublished | DualFileFaultPoint::DirectorySynced);
        assert_eq!(state, if reverse_before { SlackMigrationState::Before } else { SlackMigrationState::After }, "reverse {point:?}");
        assert_eq!(
            (std::fs::read(&freedom).unwrap(), std::fs::read(&credentials).unwrap()),
            if reverse_before { before.clone() } else { after.clone() },
            "reverse {point:?} must recover one exact stored image"
        );
        reopened.rollback_if_exact_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap();
    }
}

#[test]
fn optional_custody_is_absent_only_for_the_exact_missing_capability() {
    let (_directory, freedom, _credentials) = seed();
    assert!(matches!(
        SlackMigrationCustody::load_optional_at(&freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap(),
        SlackMigrationCustodyLoad::Absent
    ));
    let path = custody_path(&freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3").unwrap();
    std::fs::write(&path, "version: nope\n").unwrap();
    assert!(SlackMigrationCustody::load_optional_at(&freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).is_err());
}

#[test]
fn custody_create_new_refuses_a_second_capability_without_replacing_it() {
    let (_directory, freedom, credentials) = seed();
    let first = prepared(&freedom, &credentials).persist_slack_migration_custody_at("TTEAM1").unwrap();
    let digest = first.custody_sha256();
    assert!(prepared(&freedom, &credentials).persist_slack_migration_custody_at("TTEAM1").is_err());
    let reopened = SlackMigrationCustody::load_at(&freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap();
    assert_eq!(reopened.custody_sha256(), digest);
}

#[cfg(unix)]
#[test]
fn nofollow_pair_capture_rejects_a_symlinked_credentials_leaf() {
    use std::os::unix::fs::symlink;

    let (_directory, freedom, credentials) = seed();
    let outside = freedom.with_file_name("outside-secret.yaml");
    std::fs::write(&outside, "outside: must-not-be-read\n").unwrap();
    std::fs::remove_file(&credentials).unwrap();
    symlink(&outside, &credentials).unwrap();
    assert!(Credentials::prepare_slack_migration_upsert_at(
        &freedom, &credentials, account("ops"), "U123ABC".into(),
        SecretString::from("xoxb-fixture"), SecretString::from("xapp-fixture"),
        "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment(),
    ).is_err());
}

#[test]
fn bounded_pair_capture_refuses_an_oversized_credentials_leaf_before_loading_it() {
    let (_directory, freedom, credentials) = seed();
    let file = std::fs::OpenOptions::new().write(true).open(&credentials).unwrap();
    file.set_len(super::super::MAX_DUAL_FILE_JOURNAL_BYTES + 1).unwrap();
    assert!(Credentials::prepare_slack_migration_upsert_at(
        &freedom, &credentials, account("ops"), "U123ABC".into(),
        SecretString::from("xoxb-fixture"), SecretString::from("xapp-fixture"),
        "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment(),
    ).is_err());
}

#[test]
fn custody_handle_rejects_a_foreign_home_even_if_the_pair_shape_matches() {
    let (_one, freedom, credentials) = seed();
    let custody = prepared(&freedom, &credentials)
        .persist_slack_migration_custody_at("TTEAM1")
        .unwrap();
    let (_two, foreign_freedom, foreign_credentials) = seed();
    assert!(custody.inspect_at(&foreign_freedom, &foreign_credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).is_err());
}

#[test]
fn encrypted_credentials_postimage_is_immutable_across_resume_and_exact_rollback() {
    let (_directory, freedom, credentials) = encrypted_seed();
    let before = (std::fs::read(&freedom).unwrap(), std::fs::read(&credentials).unwrap());
    let custody = prepared(&freedom, &credentials)
        .persist_slack_migration_custody_at("TTEAM1")
        .unwrap();
    custody.commit_if_before_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap();
    let after = std::fs::read(&credentials).unwrap();
    assert!(super::super::credentials_blob_is_encrypted(&after));
    let reopened = SlackMigrationCustody::load_at(&freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap();
    reopened.commit_if_before_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap();
    assert_eq!(std::fs::read(&credentials).unwrap(), after, "resume must not mint another encrypted nonce");
    reopened.rollback_if_exact_at(&freedom, &credentials, "db290af9-0cb1-4271-aecd-dc45272a71a3", commitment()).unwrap();
    assert_eq!((std::fs::read(&freedom).unwrap(), std::fs::read(&credentials).unwrap()), before);
}
