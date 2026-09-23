//! Behavioral fixtures for the Daily-only v2 retention state machine.
//!
//! These deliberately build real private home/vault namespaces and use Daily
//! settlement for every happy-path archive/note.  Journal fixtures model only
//! the crash boundary after that admitted effect has persisted its intent.

use super::*;
use crate::reflection::hygiene::{
    HYGIENE_PLAN_SCHEMA_VERSION, TOPIC_SYNONYM_MAP_VERSION, TopicSynonymMap, VersionedHygieneInput,
};
use crate::reflection::hygiene_store::apply_hygiene_plan;
use crate::reflection::retention_authority::DailyRetentionExecutionConfig;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const NOW: i64 = 1_787_788_800;

/// A retention fixture must acquire the same private, capability-bound Daily
/// settlement gate as production. A plain `TempDir` is intentionally not a
/// valid home authority on every platform.
struct PrivateRetentionHome {
    _root: crate::test_env::CanonicalTempDir,
    path: PathBuf,
}

impl PrivateRetentionHome {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn private_retention_home() -> PrivateRetentionHome {
    let root = crate::test_env::canonical_tempdir().expect("private retention test root");
    #[cfg(unix)]
    let path = {
        use std::os::unix::fs::DirBuilderExt as _;

        let path = root.path().join("private-retention-home");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("create private Unix retention home");
        path
    };
    #[cfg(windows)]
    let path = {
        let path = root.path().join("private-retention-home");
        crate::wal::win_native::create_private_directory_new(&path)
            .expect("create private Windows retention home");
        path
    };
    PrivateRetentionHome { _root: root, path }
}

fn enabled() -> DailyRetentionExecutionConfig {
    DailyRetentionExecutionConfig {
        version: 2,
        enabled: true,
        quarantine_grace_days: 1,
    }
}

fn daily(age: i64, topic: &str) -> PeriodReflection {
    let tag = date_tag_from_unix(NOW - age * 86_400);
    build_reflection(PeriodKind::Daily, &tag, &[topic.into()], NOW - age * 86_400).unwrap()
}

fn preserve_period_inputs(home: &std::path::Path, periods: Vec<PeriodReflection>) {
    apply_hygiene_plan(
        home,
        0,
        VersionedHygieneInput {
            schema_version: HYGIENE_PLAN_SCHEMA_VERSION,
            now_unix: NOW,
            raw_reflections: Vec::new(),
            period_reflections: periods,
            topic_synonyms: TopicSynonymMap {
                version: TOPIC_SYNONYM_MAP_VERSION,
                entries: BTreeMap::new(),
            },
        },
    )
    .unwrap();
}

fn settled_expired_pair() -> (PrivateRetentionHome, PrivateRetentionHome, PeriodReflection) {
    let home = private_retention_home();
    let vault = private_retention_home();
    let stale = daily(90, "v2-stale");
    let current = daily(0, "v2-current");
    settle_daily_admission(home.path(), &stale, None, Some((vault.path(), "NEOTH"))).unwrap();
    settle_daily_admission(home.path(), &current, None, Some((vault.path(), "NEOTH"))).unwrap();
    preserve_period_inputs(home.path(), vec![stale.clone(), current]);
    (home, vault, stale)
}

fn execute_retention(home: &std::path::Path, vault: &std::path::Path, now: i64) {
    enforce_daily_retention_with_execution(
        home,
        now,
        &DailyRetentionConfig::default(),
        &enabled(),
        Some((vault, "NEOTH")),
    )
    .unwrap();
}

fn effect_journal(
    home: &std::path::Path,
    tag: &str,
) -> crate::reflection::retention_authority::RetentionEffectJournalV2 {
    crate::reflection::retention_authority::load_effect_journal(home, tag)
        .unwrap()
        .expect("retention journal")
}

fn effect_receipt(
    home: &std::path::Path,
    tag: &str,
) -> crate::reflection::retention_authority::RetentionEffectReceiptV2 {
    crate::reflection::retention_authority::list_effect_receipts(home)
        .unwrap()
        .into_iter()
        .find(|receipt| receipt.tag == tag)
        .expect("retention receipt")
}

fn remove_retention_record(home: &std::path::Path, child: &str, tag: &str) {
    let path = home
        .join("reflections")
        .join("retention-v2")
        .join(child)
        .join(format!("{tag}.json"));
    std::fs::remove_file(path).unwrap();
}

fn archive_quarantine_leaf(
    home: &std::path::Path,
    journal: &crate::reflection::retention_authority::RetentionEffectJournalV2,
) -> std::path::PathBuf {
    home.join("reflections")
        .join("daily")
        .join(".retention-v2")
        .join(&journal.archive_quarantine_run)
        .join(format!("{}.jsonl", journal.tag))
}

fn note_quarantine_leaf(
    vault: &std::path::Path,
    journal: &crate::reflection::retention_authority::RetentionEffectJournalV2,
) -> std::path::PathBuf {
    vault
        .join("NEOTH")
        .join("Daily")
        .join(".neoth-retention-v2")
        .join(
            journal
                .note_quarantine_run
                .as_deref()
                .expect("owned note run"),
        )
        .join(format!("{}.md", journal.tag))
}

fn save_journal(
    home: &std::path::Path,
    journal: &crate::reflection::retention_authority::RetentionEffectJournalV2,
) {
    crate::reflection::retention_authority::save_effect_journal(home, journal).unwrap();
}

#[test]
fn v2_default_off_leaves_real_archive_and_settlement_note_unchanged() {
    let (home, vault, stale) = settled_expired_pair();
    let archive = jsonl_file(home.path(), PeriodKind::Daily, &stale.tag);
    let note = vault
        .path()
        .join("NEOTH/Daily")
        .join(format!("{}.md", stale.tag));
    let before_archive = std::fs::read(&archive).unwrap();
    let before_note = std::fs::read(&note).unwrap();
    let outcome = enforce_daily_retention_with_execution(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        &DailyRetentionExecutionConfig::default(),
        Some((vault.path(), "NEOTH")),
    )
    .unwrap();
    assert_eq!(
        outcome.execution,
        DailyRetentionExecution::AwaitingRetentionAuthority
    );
    assert_eq!(std::fs::read(archive).unwrap(), before_archive);
    assert_eq!(std::fs::read(note).unwrap(), before_note);
}

#[test]
fn v2_reserved_note_quarantine_directory_is_accepted_by_inventory() {
    let (home, vault, _stale) = settled_expired_pair();
    std::fs::create_dir(vault.path().join("NEOTH/Daily/.neoth-retention-v2")).unwrap();

    let outcome = enforce_daily_retention(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        Some((vault.path(), "NEOTH")),
    )
    .unwrap();
    assert_eq!(
        outcome.execution,
        DailyRetentionExecution::AwaitingRetentionAuthority
    );
}

#[test]
fn v2_reserved_note_quarantine_regular_file_is_inventory_error() {
    let (home, vault, stale) = settled_expired_pair();
    let reserved = vault.path().join("NEOTH/Daily/.neoth-retention-v2");
    std::fs::write(&reserved, b"foreign regular file").unwrap();

    let error = enforce_daily_retention(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        Some((vault.path(), "NEOTH")),
    )
    .unwrap_err();
    assert_eq!(
        error,
        DailyRetentionError {
            reason: "managed note inventory is invalid",
        }
    );
    assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale.tag).exists());
}

#[cfg(unix)]
#[test]
fn v2_reserved_note_quarantine_symlink_is_inventory_error() {
    use std::os::unix::fs::symlink;

    let (home, vault, stale) = settled_expired_pair();
    let outside = private_retention_home();
    let reserved = vault.path().join("NEOTH/Daily/.neoth-retention-v2");
    symlink(outside.path(), &reserved).unwrap();

    let error = enforce_daily_retention(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        Some((vault.path(), "NEOTH")),
    )
    .unwrap_err();
    assert_eq!(
        error,
        DailyRetentionError {
            reason: "managed note inventory is invalid",
        }
    );
    assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale.tag).exists());
    assert!(outside.path().exists());
}

#[test]
fn v2_enabled_quarantines_real_archive_and_receipt_owned_note_without_losing_period_input() {
    let (home, vault, stale) = settled_expired_pair();
    let outcome = enforce_daily_retention_with_execution(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        &enabled(),
        Some((vault.path(), "NEOTH")),
    )
    .unwrap();
    assert_eq!(outcome.execution, DailyRetentionExecution::Quarantined);
    assert!(!jsonl_file(home.path(), PeriodKind::Daily, &stale.tag).exists());
    assert!(
        !vault
            .path()
            .join("NEOTH/Daily")
            .join(format!("{}.md", stale.tag))
            .exists()
    );
    let state = crate::reflection::hygiene_store::load_hygiene_state(home.path())
        .unwrap()
        .unwrap();
    assert!(
        state
            .period_reflections
            .iter()
            .any(|period| period == &stale)
    );
}

#[test]
fn v2_identical_byte_note_replacement_refuses_receipt_owned_quarantine() {
    let (home, vault, stale) = settled_expired_pair();
    let note = vault
        .path()
        .join("NEOTH/Daily")
        .join(format!("{}.md", stale.tag));
    let displaced = vault
        .path()
        .join("NEOTH/Daily")
        .join(format!("{}.original", stale.tag));
    let bytes = std::fs::read(&note).unwrap();
    std::fs::rename(&note, &displaced).unwrap();
    std::fs::write(&note, &bytes).unwrap();
    assert!(
        enforce_daily_retention_with_execution(
            home.path(),
            NOW,
            &DailyRetentionConfig::default(),
            &enabled(),
            Some((vault.path(), "NEOTH"))
        )
        .is_err()
    );
    assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale.tag).exists());
    assert_eq!(
        std::fs::read(&displaced).unwrap(),
        bytes,
        "the receipt-bound original must remain recoverable under its displaced name"
    );
    assert_eq!(
        std::fs::read(&note).unwrap(),
        std::fs::read(&displaced).unwrap()
    );
}

#[test]
fn v2_yearly_synthesis_provenance_is_exact_before_hygiene_after_overlap_and_after_purge() {
    let home = private_retention_home();
    let stale = daily(90, "yearly-historical");
    let current = daily(0, "yearly-current");
    settle_daily_admission(home.path(), &stale, None, None).unwrap();
    settle_daily_admission(home.path(), &current, None, None).unwrap();
    let synonyms = TopicSynonymMap {
        version: TOPIC_SYNONYM_MAP_VERSION,
        entries: BTreeMap::new(),
    };
    let before_hygiene = compose_yearly_synthesis(home.path(), NOW, "2026", synonyms.clone())
        .unwrap()
        .expect("active Daily archive composes yearly synthesis");

    let yearly =
        build_reflection(PeriodKind::Yearly, "2026", &["existing-yearly".into()], NOW).unwrap();
    preserve_period_inputs(home.path(), vec![stale.clone(), current.clone(), yearly]);
    let after_overlap = compose_yearly_synthesis(home.path(), NOW, "2026", synonyms.clone())
        .unwrap()
        .expect("valid non-Daily hygiene input must not block Daily synthesis");
    assert_eq!(
        after_overlap.tags, before_hygiene.tags,
        "hygiene overlap must retain active JSONL source digests exactly"
    );

    enforce_daily_retention_with_execution(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        &enabled(),
        None,
    )
    .unwrap();
    let after_quarantine = compose_yearly_synthesis(home.path(), NOW, "2026", synonyms.clone())
        .unwrap()
        .expect("quarantined Daily input remains a yearly source");
    assert_eq!(after_quarantine.tags, before_hygiene.tags);

    enforce_daily_retention_with_execution(
        home.path(),
        NOW + 2 * 86_400,
        &DailyRetentionConfig::default(),
        &enabled(),
        None,
    )
    .unwrap();
    let after_purge = compose_yearly_synthesis(home.path(), NOW, "2026", synonyms)
        .unwrap()
        .expect("purged archive leaves retain exact yearly provenance through hygiene");
    assert_eq!(after_purge.tags, before_hygiene.tags);
    assert!(
        after_purge
            .tags
            .iter()
            .any(|tag| tag.starts_with(&format!("source:{}:", stale.tag)))
    );
}

#[test]
fn v2_legacy_matching_note_is_not_adopted() {
    let home = private_retention_home();
    let vault = private_retention_home();
    let stale = daily(90, "legacy-note");
    let current = daily(0, "current");
    settle_daily_admission(home.path(), &stale, None, None).unwrap();
    settle_daily_admission(home.path(), &current, None, None).unwrap();
    preserve_period_inputs(home.path(), vec![stale.clone(), current]);
    let note = vault
        .path()
        .join("NEOTH/Daily")
        .join(format!("{}.md", stale.tag));
    std::fs::create_dir_all(note.parent().unwrap()).unwrap();
    std::fs::write(&note, stale.to_obsidian_md()).unwrap();
    enforce_daily_retention_with_execution(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        &enabled(),
        Some((vault.path(), "NEOTH")),
    )
    .unwrap();
    assert!(note.exists());
}

// Crash fixtures below begin with a real settlement and normal durable state.
// Each test mutates only the journal phase that a crash could leave behind;
// the next execution must reconcile the exact namespace rather than begin a
// different effect.

#[test]
fn v2_prepared_before_rename_is_abandoned_then_next_batch_is_safe() {
    let (home, vault, stale) = settled_expired_pair();
    execute_retention(home.path(), vault.path(), NOW);
    let mut journal = effect_journal(home.path(), &stale.tag);
    std::fs::rename(
        archive_quarantine_leaf(home.path(), &journal),
        jsonl_file(home.path(), PeriodKind::Daily, &stale.tag),
    )
    .unwrap();
    std::fs::rename(
        note_quarantine_leaf(vault.path(), &journal),
        vault
            .path()
            .join("NEOTH/Daily")
            .join(format!("{}.md", stale.tag)),
    )
    .unwrap();
    remove_retention_record(home.path(), "receipts", &stale.tag);
    journal.phase = crate::reflection::retention_authority::RetentionEffectPhaseV2::Prepared;
    journal.archive_quarantine_identity = None;
    journal.note_quarantine_identity = None;
    save_journal(home.path(), &journal);

    execute_retention(home.path(), vault.path(), NOW);
    let terminal = effect_journal(home.path(), &stale.tag);
    assert_eq!(
        terminal.phase,
        crate::reflection::retention_authority::RetentionEffectPhaseV2::Committed
    );
    assert!(!jsonl_file(home.path(), PeriodKind::Daily, &stale.tag).exists());
    assert!(archive_quarantine_leaf(home.path(), &terminal).exists());
    assert!(
        effect_receipt(home.path(), &stale.tag)
            .purged_at_unix
            .is_none()
    );
}
#[test]
fn v2_post_archive_rename_before_transition_reconciles_source_identity() {
    let (home, vault, stale) = settled_expired_pair();
    execute_retention(home.path(), vault.path(), NOW);
    let mut journal = effect_journal(home.path(), &stale.tag);
    std::fs::rename(
        note_quarantine_leaf(vault.path(), &journal),
        vault
            .path()
            .join("NEOTH/Daily")
            .join(format!("{}.md", stale.tag)),
    )
    .unwrap();
    remove_retention_record(home.path(), "receipts", &stale.tag);
    journal.phase = crate::reflection::retention_authority::RetentionEffectPhaseV2::Prepared;
    journal.archive_quarantine_identity = None;
    journal.note_quarantine_identity = None;
    save_journal(home.path(), &journal);

    assert!(archive_quarantine_leaf(home.path(), &journal).exists());
    assert!(
        vault
            .path()
            .join("NEOTH/Daily")
            .join(format!("{}.md", stale.tag))
            .exists()
    );
    execute_retention(home.path(), vault.path(), NOW);
    let recovered = effect_journal(home.path(), &stale.tag);
    assert_eq!(
        recovered.phase,
        crate::reflection::retention_authority::RetentionEffectPhaseV2::Committed
    );
    assert_eq!(
        recovered.archive_quarantine_identity.as_deref(),
        Some(recovered.archive_source_identity.as_str())
    );
    assert!(!jsonl_file(home.path(), PeriodKind::Daily, &stale.tag).exists());
    assert!(archive_quarantine_leaf(home.path(), &recovered).exists());
}

#[test]
fn v2_committed_journal_rejects_a_mismatched_immutable_receipt() {
    let (home, vault, stale) = settled_expired_pair();
    execute_retention(home.path(), vault.path(), NOW);
    let journal = effect_journal(home.path(), &stale.tag);
    let mut receipt = effect_receipt(home.path(), &stale.tag);
    receipt.quarantine_sha256 = "f".repeat(64);
    crate::reflection::retention_authority::save_effect_receipt(home.path(), &receipt).unwrap();
    let receipt_path = home
        .path()
        .join("reflections/retention-v2/receipts")
        .join(format!("{}.json", stale.tag));
    let mismatched_bytes = std::fs::read(&receipt_path).unwrap();

    assert!(
        enforce_daily_retention_with_execution(
            home.path(),
            NOW,
            &DailyRetentionConfig::default(),
            &enabled(),
            Some((vault.path(), "NEOTH")),
        )
        .is_err()
    );
    assert!(archive_quarantine_leaf(home.path(), &journal).exists());
    assert_eq!(std::fs::read(receipt_path).unwrap(), mismatched_bytes);
}

#[test]
fn v2_receipt_owned_missing_note_still_quarantines_the_exact_archive() {
    let (home, vault, stale) = settled_expired_pair();
    let note = vault
        .path()
        .join("NEOTH/Daily")
        .join(format!("{}.md", stale.tag));
    std::fs::remove_file(note).unwrap();

    let outcome = enforce_daily_retention_with_execution(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        &enabled(),
        Some((vault.path(), "NEOTH")),
    )
    .unwrap();
    let journal = effect_journal(home.path(), &stale.tag);
    assert_eq!(outcome.execution, DailyRetentionExecution::Quarantined);
    assert!(!jsonl_file(home.path(), PeriodKind::Daily, &stale.tag).exists());
    assert!(archive_quarantine_leaf(home.path(), &journal).exists());
    assert!(journal.note_sha256.is_none());
    assert!(journal.note_quarantine_run.is_none());
}
#[test]
fn v2_post_note_rename_before_transition_reconciles_deterministic_destination() {
    let (home, vault, stale) = settled_expired_pair();
    execute_retention(home.path(), vault.path(), NOW);
    let mut journal = effect_journal(home.path(), &stale.tag);
    remove_retention_record(home.path(), "receipts", &stale.tag);
    journal.phase =
        crate::reflection::retention_authority::RetentionEffectPhaseV2::ArchiveQuarantined;
    journal.note_quarantine_identity = None;
    save_journal(home.path(), &journal);

    execute_retention(home.path(), vault.path(), NOW);
    let recovered = effect_journal(home.path(), &stale.tag);
    assert_eq!(
        recovered.phase,
        crate::reflection::retention_authority::RetentionEffectPhaseV2::Committed
    );
    assert!(recovered.note_quarantine_run.is_some());
    assert!(note_quarantine_leaf(vault.path(), &recovered).exists());
    assert!(
        !vault
            .path()
            .join("NEOTH/Daily")
            .join(format!("{}.md", stale.tag))
            .exists()
    );
}
#[test]
fn v2_receipt_before_committed_ordering_is_idempotent_after_restart() {
    let (home, vault, stale) = settled_expired_pair();
    execute_retention(home.path(), vault.path(), NOW);
    let receipt_path = home
        .path()
        .join("reflections/retention-v2/receipts")
        .join(format!("{}.json", stale.tag));
    let receipt_bytes = std::fs::read(&receipt_path).unwrap();
    let mut journal = effect_journal(home.path(), &stale.tag);
    journal.phase = crate::reflection::retention_authority::RetentionEffectPhaseV2::NoteQuarantined;
    save_journal(home.path(), &journal);

    execute_retention(home.path(), vault.path(), NOW);
    assert_eq!(
        effect_journal(home.path(), &stale.tag).phase,
        crate::reflection::retention_authority::RetentionEffectPhaseV2::Committed
    );
    assert_eq!(std::fs::read(receipt_path).unwrap(), receipt_bytes);
    assert_eq!(
        crate::reflection::retention_authority::list_effect_receipts(home.path())
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn v2_purge_prepared_before_unlink_restarts_from_both_quarantined_leaves() {
    let (home, vault, stale) = settled_expired_pair();
    execute_retention(home.path(), vault.path(), NOW);
    let journal = effect_journal(home.path(), &stale.tag);
    let receipt = effect_receipt(home.path(), &stale.tag);
    let receipt_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&receipt).unwrap()));
    crate::reflection::retention_authority::save_purge_journal(
        home.path(),
        &stale.tag,
        &crate::reflection::retention_authority::RetentionPurgeJournalV2 {
            schema_version: 2,
            receipt_sha256,
            phase: crate::reflection::retention_authority::RetentionPurgePhaseV2::PurgePrepared,
        },
    )
    .unwrap();

    assert!(archive_quarantine_leaf(home.path(), &journal).exists());
    assert!(note_quarantine_leaf(vault.path(), &journal).exists());

    execute_retention(home.path(), vault.path(), NOW + 2 * 86_400);
    assert_eq!(
        crate::reflection::retention_authority::load_purge_journal(home.path(), &stale.tag)
            .unwrap()
            .expect("purge journal")
            .phase,
        crate::reflection::retention_authority::RetentionPurgePhaseV2::PurgedCompleted,
    );
    assert!(
        effect_receipt(home.path(), &stale.tag)
            .purged_at_unix
            .is_some()
    );
    assert!(!archive_quarantine_leaf(home.path(), &journal).exists());
    assert!(!note_quarantine_leaf(vault.path(), &journal).exists());
}

#[test]
fn v2_unlink_attempted_after_partial_unlink_is_reconciled_truthfully() {
    let (home, vault, stale) = settled_expired_pair();
    execute_retention(home.path(), vault.path(), NOW);
    let journal = effect_journal(home.path(), &stale.tag);
    let receipt = effect_receipt(home.path(), &stale.tag);
    let receipt_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&receipt).unwrap()));
    crate::reflection::retention_authority::save_purge_journal(
        home.path(),
        &stale.tag,
        &crate::reflection::retention_authority::RetentionPurgeJournalV2 {
            schema_version: 2,
            receipt_sha256,
            phase: crate::reflection::retention_authority::RetentionPurgePhaseV2::UnlinkAttempted,
        },
    )
    .unwrap();
    std::fs::remove_file(archive_quarantine_leaf(home.path(), &journal)).unwrap();

    execute_retention(home.path(), vault.path(), NOW + 2 * 86_400);
    assert_eq!(
        crate::reflection::retention_authority::load_purge_journal(home.path(), &stale.tag)
            .unwrap()
            .expect("purge journal")
            .phase,
        crate::reflection::retention_authority::RetentionPurgePhaseV2::PurgedCompleted,
    );
    assert!(
        effect_receipt(home.path(), &stale.tag)
            .purged_at_unix
            .is_some()
    );
    assert!(!note_quarantine_leaf(vault.path(), &journal).exists());
}

#[test]
fn v2_completed_purge_is_idempotent_after_the_effect_receipt_is_timestamped() {
    let (home, vault, stale) = settled_expired_pair();
    execute_retention(home.path(), vault.path(), NOW);
    let journal = effect_journal(home.path(), &stale.tag);
    execute_retention(home.path(), vault.path(), NOW + 2 * 86_400);
    let terminal_receipt = effect_receipt(home.path(), &stale.tag);
    assert!(terminal_receipt.purged_at_unix.is_some());
    assert!(!archive_quarantine_leaf(home.path(), &journal).exists());
    assert!(!note_quarantine_leaf(vault.path(), &journal).exists());

    execute_retention(home.path(), vault.path(), NOW + 3 * 86_400);
    assert_eq!(effect_receipt(home.path(), &stale.tag), terminal_receipt);
    assert!(!archive_quarantine_leaf(home.path(), &journal).exists());
    assert!(!note_quarantine_leaf(vault.path(), &journal).exists());
}

#[test]
fn v2_purged_completed_journal_finalizes_a_missing_effect_receipt_timestamp() {
    let (home, vault, stale) = settled_expired_pair();
    execute_retention(home.path(), vault.path(), NOW);
    let journal = effect_journal(home.path(), &stale.tag);
    let receipt = effect_receipt(home.path(), &stale.tag);
    let receipt_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&receipt).unwrap()));
    crate::reflection::retention_authority::save_purge_journal(
        home.path(),
        &stale.tag,
        &crate::reflection::retention_authority::RetentionPurgeJournalV2 {
            schema_version: 2,
            receipt_sha256,
            phase: crate::reflection::retention_authority::RetentionPurgePhaseV2::PurgedCompleted,
        },
    )
    .unwrap();
    std::fs::remove_file(archive_quarantine_leaf(home.path(), &journal)).unwrap();
    std::fs::remove_file(note_quarantine_leaf(vault.path(), &journal)).unwrap();

    execute_retention(home.path(), vault.path(), NOW + 2 * 86_400);
    assert_eq!(
        effect_receipt(home.path(), &stale.tag).purged_at_unix,
        Some(NOW + 2 * 86_400)
    );
    assert!(!archive_quarantine_leaf(home.path(), &journal).exists());
    assert!(!note_quarantine_leaf(vault.path(), &journal).exists());
    assert!(!jsonl_file(home.path(), PeriodKind::Daily, &stale.tag).exists());
}

#[test]
fn v2_completed_purge_rejects_a_foreign_receipt_binding_without_changing_evidence() {
    let (home, vault, stale) = settled_expired_pair();
    execute_retention(home.path(), vault.path(), NOW);
    execute_retention(home.path(), vault.path(), NOW + 2 * 86_400);
    let receipt = effect_receipt(home.path(), &stale.tag);
    let mut purge =
        crate::reflection::retention_authority::load_purge_journal(home.path(), &stale.tag)
            .unwrap()
            .unwrap();
    purge.receipt_sha256 = "0".repeat(64);
    crate::reflection::retention_authority::save_purge_journal(home.path(), &stale.tag, &purge)
        .unwrap();
    assert!(
        enforce_daily_retention_with_execution(
            home.path(),
            NOW + 3 * 86_400,
            &DailyRetentionConfig::default(),
            &enabled(),
            Some((vault.path(), "NEOTH")),
        )
        .is_err()
    );
    assert_eq!(effect_receipt(home.path(), &stale.tag), receipt);
    assert_eq!(
        crate::reflection::retention_authority::load_purge_journal(home.path(), &stale.tag)
            .unwrap(),
        Some(purge),
    );
}
#[test]
fn v2_bounded_batches_preserve_unselected_expired_records_for_later_ticks() {
    let home = private_retention_home();
    let mut periods = vec![daily(0, "current")];
    settle_daily_admission(home.path(), periods.first().unwrap(), None, None).unwrap();
    for age in 90..220 {
        let period = daily(age, &format!("historical-batch-{age}"));
        write_daily_retention_archive_fixture(home.path(), &period);
        periods.push(period);
    }
    preserve_period_inputs(home.path(), periods.clone());
    let active_archive_count = |home: &Path| {
        let archive = open_existing_daily_retention_archive(home)
            .unwrap()
            .expect("fixture Daily archive exists");
        bounded_retention_child_names(&archive.daily, MAX_DAILY_RETENTION_ENTRIES)
            .unwrap()
            .into_iter()
            .filter(|name| name != OsStr::new(".retention-v2"))
            .count()
    };
    assert_eq!(active_archive_count(home.path()), 131);
    enforce_daily_retention_with_execution(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        &enabled(),
        None,
    )
    .unwrap();
    assert_eq!(
        crate::reflection::retention_authority::list_effect_receipts(home.path())
            .unwrap()
            .len(),
        64
    );
    assert_eq!(active_archive_count(home.path()), 67);
    enforce_daily_retention_with_execution(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        &enabled(),
        None,
    )
    .unwrap();
    assert_eq!(
        crate::reflection::retention_authority::list_effect_receipts(home.path())
            .unwrap()
            .len(),
        128
    );
    assert_eq!(active_archive_count(home.path()), 3);
    enforce_daily_retention_with_execution(
        home.path(),
        NOW,
        &DailyRetentionConfig::default(),
        &enabled(),
        None,
    )
    .unwrap();

    let receipts =
        crate::reflection::retention_authority::list_effect_receipts(home.path()).unwrap();
    assert_eq!(receipts.len(), 130);
    assert_eq!(active_archive_count(home.path()), 1);
    for period in periods.iter().skip(1) {
        assert!(!jsonl_file(home.path(), PeriodKind::Daily, &period.tag).exists());
    }
    let yearly = compose_yearly_synthesis(
        home.path(),
        NOW,
        "2026",
        TopicSynonymMap {
            version: TOPIC_SYNONYM_MAP_VERSION,
            entries: BTreeMap::new(),
        },
    )
    .unwrap()
    .expect("yearly synthesis retains quarantined historical daily input");
    let oldest = &periods.last().expect("oldest historical input").tag;
    let newest = &periods[1].tag;
    assert!(
        yearly
            .tags
            .iter()
            .any(|tag| tag.starts_with(&format!("source:{oldest}:")))
    );
    assert!(
        yearly
            .tags
            .iter()
            .any(|tag| tag.starts_with(&format!("source:{newest}:")))
    );
}
