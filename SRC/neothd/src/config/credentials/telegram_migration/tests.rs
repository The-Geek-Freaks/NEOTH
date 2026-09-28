use super::super::DualFileFaultPoint;
use super::*;

fn account(name: &str) -> ChannelAccountId {
    ChannelAccountId::new(name).unwrap()
}

fn commitment() -> &'static str {
    "d1b3f484403613af2ec1c6761975edc7d69ad0ac53e269d53f4a7bc829bf9852"
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
    )
    .unwrap();
    (directory, freedom, credentials)
}

fn prepared(freedom: &Path, credentials: &Path) -> PreparedTelegramMigration {
    Credentials::prepare_telegram_migration_upsert_at(
        freedom,
        credentials,
        account("ops"),
        42,
        SecretString::from("123456789:telegram-migration-fixture"),
        "db290af9-0cb1-4271-aecd-dc45272a71a3",
        commitment(),
    )
    .unwrap()
}

#[test]
fn custody_commits_the_immutable_allowed_user_bound_pair_and_reverses_it_exactly() {
    let (_directory, freedom, credentials) = seed();
    let before = (
        std::fs::read(&freedom).unwrap(),
        std::fs::read(&credentials).unwrap(),
    );
    let custody = prepared(&freedom, &credentials)
        .persist_telegram_migration_custody_at()
        .unwrap();
    assert_eq!(
        custody
            .inspect_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment()
            )
            .unwrap(),
        TelegramMigrationState::Before
    );
    let first = custody
        .commit_if_before_at(
            &freedom,
            &credentials,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
        )
        .unwrap();
    let after = (
        std::fs::read(&freedom).unwrap(),
        std::fs::read(&credentials).unwrap(),
    );
    assert_ne!(after, before);
    assert_eq!(
        custody
            .inspect_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment()
            )
            .unwrap(),
        TelegramMigrationState::After
    );
    assert_eq!(
        first,
        custody
            .commit_if_before_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment()
            )
            .unwrap()
    );
    assert_eq!(
        custody
            .rollback_if_exact_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment()
            )
            .unwrap(),
        TelegramMigrationState::Before
    );
    assert_eq!(
        (
            std::fs::read(&freedom).unwrap(),
            std::fs::read(&credentials).unwrap()
        ),
        before
    );
}

#[test]
fn custody_refuses_tampering_and_never_overwrites_a_mixed_pair() {
    let (_directory, freedom, credentials) = seed();
    let custody = prepared(&freedom, &credentials)
        .persist_telegram_migration_custody_at()
        .unwrap();
    let path = custody_path(&freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3").unwrap();
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, "version: 9\n").unwrap();
    assert!(
        TelegramMigrationCustody::load_at(
            &freedom,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment()
        )
        .is_err()
    );
    assert!(
        custody
            .inspect_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment()
            )
            .is_err()
    );
    std::fs::write(&path, original).unwrap();
    std::fs::write(&freedom, "secrets_backend: file\nconcurrent: drift\n").unwrap();
    assert_eq!(
        custody
            .inspect_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment()
            )
            .unwrap(),
        TelegramMigrationState::Mixed
    );
    assert!(
        custody
            .commit_if_before_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment()
            )
            .is_err()
    );
    assert!(
        custody
            .rollback_if_exact_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment()
            )
            .is_err()
    );
    assert!(
        std::fs::read_to_string(&freedom)
            .unwrap()
            .contains("concurrent: drift")
    );
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
        let before = (
            std::fs::read(&freedom).unwrap(),
            std::fs::read(&credentials).unwrap(),
        );
        let custody = prepared(&freedom, &credentials)
            .persist_telegram_migration_custody_at()
            .unwrap();
        let _ = custody.commit_if_before_at_using_test_fault(
            &freedom,
            &credentials,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
            |seen| {
                if seen == point {
                    anyhow::bail!("stop at {seen:?}")
                } else {
                    Ok(())
                }
            },
        );
        let reopened = TelegramMigrationCustody::load_at(
            &freedom,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
        )
        .unwrap();
        let state = reopened
            .inspect_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment(),
            )
            .unwrap();
        let forward_after = matches!(
            point,
            DualFileFaultPoint::FreedomPublished | DualFileFaultPoint::DirectorySynced
        );
        assert_eq!(
            state,
            if forward_after {
                TelegramMigrationState::After
            } else {
                TelegramMigrationState::Before
            },
            "forward {point:?}"
        );
        reopened
            .commit_if_before_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment(),
            )
            .unwrap();
        let after = (
            std::fs::read(&freedom).unwrap(),
            std::fs::read(&credentials).unwrap(),
        );
        let _ = reopened.rollback_if_exact_at_using_test_fault(
            &freedom,
            &credentials,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
            |seen| {
                if seen == point {
                    anyhow::bail!("stop at {seen:?}")
                } else {
                    Ok(())
                }
            },
        );
        let reopened = TelegramMigrationCustody::load_at(
            &freedom,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
        )
        .unwrap();
        let state = reopened
            .inspect_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment(),
            )
            .unwrap();
        let reverse_before = matches!(
            point,
            DualFileFaultPoint::FreedomPublished | DualFileFaultPoint::DirectorySynced
        );
        assert_eq!(
            state,
            if reverse_before {
                TelegramMigrationState::Before
            } else {
                TelegramMigrationState::After
            },
            "reverse {point:?}"
        );
        assert_eq!(
            (
                std::fs::read(&freedom).unwrap(),
                std::fs::read(&credentials).unwrap()
            ),
            if reverse_before {
                before.clone()
            } else {
                after.clone()
            },
            "reverse {point:?} must recover one exact stored image"
        );
        reopened
            .rollback_if_exact_at(
                &freedom,
                &credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment(),
            )
            .unwrap();
    }
}

#[test]
fn optional_custody_is_absent_only_for_the_exact_missing_capability() {
    let (_directory, freedom, _credentials) = seed();
    assert!(matches!(
        TelegramMigrationCustody::load_optional_at(
            &freedom,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment()
        )
        .unwrap(),
        TelegramMigrationCustodyLoad::Absent
    ));
    let path = custody_path(&freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3").unwrap();
    std::fs::write(&path, "version: nope\n").unwrap();
    assert!(
        TelegramMigrationCustody::load_optional_at(
            &freedom,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment()
        )
        .is_err()
    );
}

#[test]
fn custody_create_new_refuses_a_second_capability_without_replacing_it() {
    let (_directory, freedom, credentials) = seed();
    let first = prepared(&freedom, &credentials)
        .persist_telegram_migration_custody_at()
        .unwrap();
    let digest = first.custody_sha256();
    assert!(
        prepared(&freedom, &credentials)
            .persist_telegram_migration_custody_at()
            .is_err()
    );
    let reopened = TelegramMigrationCustody::load_at(
        &freedom,
        "db290af9-0cb1-4271-aecd-dc45272a71a3",
        commitment(),
    )
    .unwrap();
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
    assert!(
        Credentials::prepare_telegram_migration_upsert_at(
            &freedom,
            &credentials,
            account("ops"),
            42,
            SecretString::from("123456789:telegram-fixture"),
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
        )
        .is_err()
    );
}

#[test]
fn bounded_pair_capture_refuses_an_oversized_credentials_leaf_before_loading_it() {
    let (_directory, freedom, credentials) = seed();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&credentials)
        .unwrap();
    file.set_len(super::super::MAX_DUAL_FILE_JOURNAL_BYTES + 1)
        .unwrap();
    assert!(
        Credentials::prepare_telegram_migration_upsert_at(
            &freedom,
            &credentials,
            account("ops"),
            42,
            SecretString::from("123456789:telegram-fixture"),
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
        )
        .is_err()
    );
}

#[test]
fn custody_handle_rejects_a_foreign_home_even_if_the_pair_shape_matches() {
    let (_one, freedom, credentials) = seed();
    let custody = prepared(&freedom, &credentials)
        .persist_telegram_migration_custody_at()
        .unwrap();
    let (_two, foreign_freedom, foreign_credentials) = seed();
    assert!(
        custody
            .inspect_at(
                &foreign_freedom,
                &foreign_credentials,
                "db290af9-0cb1-4271-aecd-dc45272a71a3",
                commitment()
            )
            .is_err()
    );
}

#[test]
fn encrypted_credentials_postimage_is_immutable_across_resume_and_exact_rollback() {
    let (_directory, freedom, credentials) = encrypted_seed();
    let before = (
        std::fs::read(&freedom).unwrap(),
        std::fs::read(&credentials).unwrap(),
    );
    let custody = prepared(&freedom, &credentials)
        .persist_telegram_migration_custody_at()
        .unwrap();
    custody
        .commit_if_before_at(
            &freedom,
            &credentials,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
        )
        .unwrap();
    let after = std::fs::read(&credentials).unwrap();
    assert!(super::super::credentials_blob_is_encrypted(&after));
    let reopened = TelegramMigrationCustody::load_at(
        &freedom,
        "db290af9-0cb1-4271-aecd-dc45272a71a3",
        commitment(),
    )
    .unwrap();
    reopened
        .commit_if_before_at(
            &freedom,
            &credentials,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
        )
        .unwrap();
    assert_eq!(
        std::fs::read(&credentials).unwrap(),
        after,
        "resume must not mint another encrypted nonce"
    );
    reopened
        .rollback_if_exact_at(
            &freedom,
            &credentials,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
        )
        .unwrap();
    assert_eq!(
        (
            std::fs::read(&freedom).unwrap(),
            std::fs::read(&credentials).unwrap()
        ),
        before
    );
}
#[test]
fn keychain_migration_refuses_before_preparation_without_mutating_pair_or_custody() {
    let (directory, freedom, credentials) = seed();
    std::fs::write(&freedom, "secrets_backend: keychain\n").unwrap();
    let before = (
        std::fs::read(&freedom).unwrap(),
        std::fs::read(&credentials).unwrap(),
    );
    let result = Credentials::prepare_telegram_migration_upsert_at(
        &freedom,
        &credentials,
        account("ops"),
        42,
        SecretString::from("123456789:telegram-fixture"),
        "db290af9-0cb1-4271-aecd-dc45272a71a3",
        commitment(),
    );
    let error = match result {
        Ok(_) => panic!("keychain must be rejected before candidate preparation"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("requires a file-backed secrets backend")
    );
    assert_eq!(
        (
            std::fs::read(&freedom).unwrap(),
            std::fs::read(&credentials).unwrap()
        ),
        before
    );
    assert!(
        !custody_path(&freedom, "db290af9-0cb1-4271-aecd-dc45272a71a3")
            .unwrap()
            .exists()
    );
    assert!(
        !directory
            .path()
            .join(crate::config::reload::RELOAD_SENTINEL_NAME)
            .exists()
    );
}

#[test]
fn existing_account_incarnation_and_unselected_account_survive_migration_and_rollback() {
    let (_directory, freedom, credentials) = seed();
    for (name, user, token) in [
        ("ops", 41, "123456789:old-token"),
        ("personal", 99, "987654321:untouched-token"),
    ] {
        let candidate = Credentials::prepare_telegram_account_upsert_at(
            &freedom,
            &credentials,
            account(name),
            user,
            SecretString::from(token),
        )
        .unwrap();
        Credentials::commit_prepared_telegram_account_upsert_at(candidate).unwrap();
    }
    let before = (
        std::fs::read(&freedom).unwrap(),
        std::fs::read(&credentials).unwrap(),
    );
    let original = crate::config::load_runtime_config_pair_from_path(&freedom).unwrap();
    let incarnation = original
        .config
        .channel_accounts
        .telegram
        .get(&account("ops"))
        .unwrap()
        .incarnation
        .clone();
    assert!(incarnation.is_some());
    let candidate = prepared(&freedom, &credentials);
    assert_eq!(
        candidate
            .candidate_pair()
            .config
            .channel_accounts
            .telegram
            .get(&account("ops"))
            .unwrap()
            .incarnation,
        incarnation
    );
    let custody = candidate.persist_telegram_migration_custody_at().unwrap();
    assert_eq!(custody.allowed_user_id(), 42);
    custody
        .commit_if_before_at(
            &freedom,
            &credentials,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
        )
        .unwrap();
    let published = crate::config::load_runtime_config_pair_from_path(&freedom).unwrap();
    let selected = published
        .config
        .channel_accounts
        .telegram
        .get(&account("ops"))
        .unwrap();
    assert_eq!(selected.allowed_user_id, 42);
    assert_eq!(selected.incarnation, incarnation);
    assert_eq!(
        published
            .config
            .channel_accounts
            .telegram
            .get(&account("personal"))
            .unwrap()
            .allowed_user_id,
        99
    );
    assert_eq!(
        published
            .credentials
            .channel_accounts
            .telegram
            .get(&account("personal"))
            .unwrap()
            .token
            .as_ref()
            .unwrap()
            .expose(),
        "987654321:untouched-token"
    );
    custody
        .rollback_if_exact_at(
            &freedom,
            &credentials,
            "db290af9-0cb1-4271-aecd-dc45272a71a3",
            commitment(),
        )
        .unwrap();
    assert_eq!(
        (
            std::fs::read(&freedom).unwrap(),
            std::fs::read(&credentials).unwrap()
        ),
        before
    );
}
