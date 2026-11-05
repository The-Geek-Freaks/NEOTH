use super::*;
use crate::security::paperless_ingest::{OcrSource, ingest_ocr_text};

fn receipted_request<'a>(
    item: &'a PaperlessOcrPayload,
    input: &'a str,
    vault: &'a Path,
) -> VaultNoteRequest<'a> {
    VaultNoteRequest {
        payload: item,
        input_text: "Original invoice",
        input_sha256: input,
        legacy_doc_id: "legacy",
        vault_root: vault,
        subdir: "mail",
    }
}

#[tokio::test]
async fn receipted_note_closed_wal_never_creates_note_content() {
    let vault = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let item = payload("Original invoice", 'a');
    let writer = crate::wal::writer::closed_test_writer();
    assert!(
        sync_email_to_obsidian_receipted(
            home.path(),
            &writer,
            receipted_request(&item, &"b".repeat(64), vault.path())
        )
        .await
        .is_err()
    );
    assert!(!path(vault.path(), &item).exists());
    assert_eq!(
        fs::read_dir(path(vault.path(), &item).parent().unwrap())
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn receipted_note_reconciles_same_file_without_views_after_writer_restart() {
    let vault = tempfile::tempdir().unwrap();
    let item = payload("Original invoice", 'a');
    let input = "b".repeat(64);
    assert!(vault_directory_fingerprint(vault.path(), "mail").is_err());
    assert!(!vault.path().join("mail").exists());
    let (writer, join, home, segment) =
        crate::wal::writer::spawn_isolated_ready_test_writer("vault-note-restart")
            .await
            .unwrap();
    let first = sync_email_to_obsidian_receipted(
        home.path(),
        &writer,
        receipted_request(&item, &input, vault.path()),
    )
    .await
    .unwrap();
    assert_eq!(first.0, EmailNoteOutcome::Created);
    assert_eq!(
        first.1,
        vault_directory_fingerprint(vault.path(), "mail").unwrap()
    );
    let before = fs::read(path(vault.path(), &item)).unwrap();
    drop(writer);
    join.await.unwrap().unwrap();
    let (writer, join, ready) =
        crate::wal::writer::spawn_for_home_ready(segment, home.path().to_path_buf()).unwrap();
    ready.wait().await.unwrap();
    let replay = sync_email_to_obsidian_receipted(
        home.path(),
        &writer,
        receipted_request(&item, &input, vault.path()),
    )
    .await
    .unwrap();
    assert_eq!(replay, (EmailNoteOutcome::AlreadyPresent, first.1));
    assert_eq!(fs::read(path(vault.path(), &item)).unwrap(), before);
    assert!(!home.path().join("views.db").exists());
    drop(writer);
    join.await.unwrap().unwrap();
}

#[tokio::test]
async fn receipted_note_never_adopts_unbound_exact_or_legacy_files() {
    for legacy in [false, true] {
        let vault = tempfile::tempdir().unwrap();
        let item = payload("Original invoice", 'a');
        let directory = note_directory(vault.path(), "mail", true).unwrap();
        let (_, parent_path) = directory.current();
        let existing = if legacy {
            parent_path.join("legacy.md")
        } else {
            path(vault.path(), &item)
        };
        let bytes = render_email_note(&item, "Original invoice");
        fs::write(&existing, &bytes).unwrap();
        let (writer, join, home, _) =
            crate::wal::writer::spawn_isolated_ready_test_writer("vault-unbound")
                .await
                .unwrap();
        let result = sync_email_to_obsidian_receipted(
            home.path(),
            &writer,
            receipted_request(&item, &"b".repeat(64), vault.path()),
        )
        .await
        .unwrap();
        assert_eq!(result.0, EmailNoteOutcome::LegacyAmbiguous);
        assert_eq!(fs::read_to_string(existing).unwrap(), bytes);
        if legacy {
            assert!(!path(vault.path(), &item).exists());
        }
        drop(writer);
        join.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn receipted_note_preserves_unbound_empty_and_bound_partial_crash_residue() {
    use crate::wal::email_vault_receipts::{Descriptor, Outcome};
    for stage in 0..3 {
        let vault = tempfile::tempdir().unwrap();
        let item = payload("Original invoice", 'a');
        let input = "b".repeat(64);
        let directory = note_directory(vault.path(), "mail", true).unwrap();
        let fingerprint = directory.fingerprint().unwrap();
        let rendition = render_email_note(&item, "Original invoice");
        let intent = Descriptor::intent(
            &"a".repeat(64),
            &input,
            &hex::encode(Sha256::digest(rendition.as_bytes())),
            &fingerprint,
        )
        .unwrap();
        let (writer, join, home, _) =
            crate::wal::writer::spawn_isolated_ready_test_writer("vault-partial")
                .await
                .unwrap();
        assert_eq!(
            writer
                .append_email_vault_receipt_once(home.path(), intent.clone())
                .await,
            Ok(Outcome::Appended)
        );
        let (parent, parent_path) = directory.current();
        let name = OsString::from(format!("{}.md", item.document_id));
        let (mut file, binding) = store::create_private_regular_file_child_create_new(
            parent,
            &name,
            &parent_path.join(&name),
        )
        .unwrap();
        let bytes: &[u8] = if stage == 2 {
            rendition.as_bytes()
        } else if stage == 1 {
            b"partial"
        } else {
            b""
        };
        if stage > 0 {
            assert_eq!(
                writer
                    .append_email_vault_receipt_once(
                        home.path(),
                        intent.bind_file(binding.identity_token()).unwrap()
                    )
                    .await,
                Ok(Outcome::Appended)
            );
            // Deliberately omit sync: reconciliation must supply it itself.
            file.write_all(bytes).unwrap();
        }
        let result = sync_email_to_obsidian_receipted(
            home.path(),
            &writer,
            receipted_request(&item, &input, vault.path()),
        )
        .await
        .unwrap();
        assert_eq!(
            result.0,
            match stage {
                0 => EmailNoteOutcome::LegacyAmbiguous,
                1 => EmailNoteOutcome::Conflict,
                _ => EmailNoteOutcome::AlreadyPresent,
            }
        );
        assert_eq!(fs::read(path(vault.path(), &item)).unwrap(), bytes);
        drop(writer);
        join.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn receipted_note_blocks_input_rendition_file_and_directory_drift() {
    for drift in 0..4 {
        let vault = tempfile::tempdir().unwrap();
        let item = payload("Original invoice", 'a');
        let input = "b".repeat(64);
        let (writer, join, home, _) =
            crate::wal::writer::spawn_isolated_ready_test_writer("vault-drift")
                .await
                .unwrap();
        sync_email_to_obsidian_receipted(
            home.path(),
            &writer,
            receipted_request(&item, &input, vault.path()),
        )
        .await
        .unwrap();
        let target = path(vault.path(), &item);
        let bytes = fs::read(&target).unwrap();
        let changed_input = "c".repeat(64);
        let changed_item = payload("Changed invoice", 'a');
        if drift == 2 {
            fs::rename(&target, target.with_extension("retained")).unwrap();
            fs::write(&target, &bytes).unwrap();
        } else if drift == 3 {
            let parent = target.parent().unwrap();
            fs::rename(parent, parent.with_file_name("retained-directory")).unwrap();
            fs::create_dir(parent).unwrap();
            fs::write(&target, &bytes).unwrap();
        }
        let result = sync_email_to_obsidian_receipted(
            home.path(),
            &writer,
            receipted_request(
                if drift == 1 { &changed_item } else { &item },
                if drift == 0 { &changed_input } else { &input },
                vault.path(),
            ),
        )
        .await;
        assert!(result.is_err() || matches!(result, Ok((EmailNoteOutcome::Conflict, _))));
        assert_eq!(fs::read(target).unwrap(), bytes);
        drop(writer);
        join.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn receipted_note_concurrent_creators_publish_one_file_and_reconcile() {
    let vault = tempfile::tempdir().unwrap();
    let item = payload("Original invoice", 'a');
    let input = "b".repeat(64);
    let (writer, join, home, _) =
        crate::wal::writer::spawn_isolated_ready_test_writer("vault-race")
            .await
            .unwrap();
    let (left, right) = tokio::join!(
        sync_email_to_obsidian_receipted(
            home.path(),
            &writer,
            receipted_request(&item, &input, vault.path())
        ),
        sync_email_to_obsidian_receipted(
            home.path(),
            &writer,
            receipted_request(&item, &input, vault.path())
        ),
    );
    assert_eq!(
        [&left, &right]
            .iter()
            .filter(|result| matches!(result, Ok((EmailNoteOutcome::Created, _))))
            .count(),
        1
    );
    let replay = sync_email_to_obsidian_receipted(
        home.path(),
        &writer,
        receipted_request(&item, &input, vault.path()),
    )
    .await
    .unwrap();
    assert_eq!(replay.0, EmailNoteOutcome::AlreadyPresent);
    assert_eq!(
        fs::read_dir(path(vault.path(), &item).parent().unwrap())
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        fs::read_to_string(path(vault.path(), &item)).unwrap(),
        render_email_note(&item, "Original invoice")
    );
    drop(writer);
    join.await.unwrap().unwrap();
}

fn payload(input: &str, digit: char) -> PaperlessOcrPayload {
    let id = format!("email-{}", digit.to_string().repeat(64));
    ingest_ocr_text(input, OcrSource::TesseractDirect, &id).unwrap()
}

fn path(vault: &Path, item: &PaperlessOcrPayload) -> PathBuf {
    vault
        .join("mail")
        .join("Paperless")
        .join(format!("{}.md", item.document_id))
}

#[test]
fn email_note_retry_preserves_exact_bytes_across_attempt_timestamps() {
    let vault = tempfile::tempdir().unwrap();
    let text = "First invoice line\nSecond invoice line";
    let mut item = payload(text, 'a');
    assert_eq!(
        sync_email_to_obsidian(&item, text, "legacy-1", vault.path(), "mail").unwrap(),
        EmailNoteOutcome::Created
    );
    let target = path(vault.path(), &item);
    let before = fs::read(&target).unwrap();
    item.ts_unix += 1000;
    assert_eq!(
        sync_email_to_obsidian(&item, text, "legacy-1", vault.path(), "mail").unwrap(),
        EmailNoteOutcome::AlreadyPresent
    );
    assert_eq!(fs::read(&target).unwrap(), before);
    assert_eq!(fs::read_dir(target.parent().unwrap()).unwrap().count(), 1);
    let text = String::from_utf8(before).unwrap();
    assert!(!text.contains("generated_unix"));
    assert!(!text.contains("ingested_unix"));
    assert!(text.contains("neoth.email-vault.v1"));
}

#[test]
fn email_note_edited_partial_and_input_drift_are_conflicts() {
    for replacement in ["operator annotation", "# partial", ""] {
        let vault = tempfile::tempdir().unwrap();
        let item = payload("Original invoice", 'b');
        assert_eq!(
            sync_email_to_obsidian(&item, "Original invoice", "legacy", vault.path(), "mail")
                .unwrap(),
            EmailNoteOutcome::Created
        );
        let target = path(vault.path(), &item);
        fs::write(&target, replacement).unwrap();
        assert_eq!(
            sync_email_to_obsidian(&item, "Original invoice", "legacy", vault.path(), "mail")
                .unwrap(),
            EmailNoteOutcome::Conflict
        );
        assert_eq!(fs::read_to_string(target).unwrap(), replacement);
    }
    let vault = tempfile::tempdir().unwrap();
    let original = payload("Original invoice", 'c');
    let changed = payload("Corrected invoice", 'c');
    sync_email_to_obsidian(
        &original,
        "Original invoice",
        "legacy",
        vault.path(),
        "mail",
    )
    .unwrap();
    let target = path(vault.path(), &original);
    let before = fs::read(&target).unwrap();
    assert_eq!(
        sync_email_to_obsidian(
            &changed,
            "Corrected invoice",
            "legacy",
            vault.path(),
            "mail"
        )
        .unwrap(),
        EmailNoteOutcome::Conflict
    );
    // Same rendered payload also cannot hide a changed pre-OCR input digest.
    assert_eq!(
        sync_email_to_obsidian(&original, "Changed input", "legacy", vault.path(), "mail").unwrap(),
        EmailNoteOutcome::Conflict
    );
    assert_eq!(fs::read(target).unwrap(), before);
}

#[test]
fn email_note_legacy_path_is_neither_adopted_nor_duplicated() {
    let vault = tempfile::tempdir().unwrap();
    let item = payload("Invoice body", 'd');
    let target = path(vault.path(), &item);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let legacy = target.parent().unwrap().join("legacy.md");
    fs::write(&legacy, "existing legacy note").unwrap();
    assert_eq!(
        sync_email_to_obsidian(&item, "Invoice body", "legacy", vault.path(), "mail").unwrap(),
        EmailNoteOutcome::LegacyAmbiguous
    );
    assert!(!target.exists());
    assert_eq!(fs::read_to_string(&legacy).unwrap(), "existing legacy note");
    assert_eq!(fs::read_dir(legacy.parent().unwrap()).unwrap().count(), 1);
}

#[test]
fn email_note_invalid_identity_or_subdir_has_no_outside_effect() {
    let parent = tempfile::tempdir().unwrap();
    let vault = parent.path().join("vault");
    fs::create_dir(&vault).unwrap();
    let item = payload("Invoice body", 'e');
    assert!(sync_email_to_obsidian(&item, "Invoice body", "legacy", &vault, "../outside").is_err());
    assert!(!parent.path().join("outside").exists());
    for id in [
        "email-short",
        "email-../outside",
        "email-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let mut invalid = item.clone();
        invalid.document_id = id.into();
        assert!(
            sync_email_to_obsidian(&invalid, "Invoice body", "legacy", &vault, "mail").is_err()
        );
    }
    assert_eq!(fs::read_dir(vault).unwrap().count(), 0);
}

#[test]
fn email_note_conflict_does_not_erase_or_block_an_independent_unit() {
    let vault = tempfile::tempdir().unwrap();
    let first = payload("First invoice", 'a');
    let second = payload("Second invoice", 'b');
    sync_email_to_obsidian(&first, "First invoice", "legacy-a", vault.path(), "mail").unwrap();
    let first_path = path(vault.path(), &first);
    fs::write(&first_path, "operator edit").unwrap();
    assert_eq!(
        sync_email_to_obsidian(&first, "First invoice", "legacy-a", vault.path(), "mail").unwrap(),
        EmailNoteOutcome::Conflict
    );
    assert_eq!(
        sync_email_to_obsidian(&second, "Second invoice", "legacy-b", vault.path(), "mail")
            .unwrap(),
        EmailNoteOutcome::Created
    );
    assert_eq!(fs::read_to_string(first_path).unwrap(), "operator edit");
    assert!(path(vault.path(), &second).exists());
}

#[test]
fn email_note_nonregular_target_is_not_replaced() {
    let vault = tempfile::tempdir().unwrap();
    let item = payload("Invoice body", 'f');
    let target = path(vault.path(), &item);
    fs::create_dir_all(&target).unwrap();
    assert_eq!(
        sync_email_to_obsidian(&item, "Invoice body", "legacy", vault.path(), "mail").unwrap(),
        EmailNoteOutcome::Conflict
    );
    assert!(target.is_dir());
}

#[test]
fn email_note_create_race_requires_exact_existing_bytes() {
    for exact in [true, false] {
        let vault = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(vault.path()).unwrap();
        let item = payload("Concurrent invoice", 'a');
        let target = path(&root, &item);
        let existing = if exact {
            render_email_note(&item, "Concurrent invoice")
        } else {
            "operator content".to_owned()
        };
        let result = sync_email_to_obsidian_observed(
            &item,
            "Concurrent invoice",
            "legacy",
            &root,
            "mail",
            |stage| {
                if stage == NoteObservation::BeforeCreate {
                    fs::write(&target, &existing).unwrap();
                }
            },
        )
        .unwrap();
        assert_eq!(
            result,
            if exact {
                EmailNoteOutcome::AlreadyPresent
            } else {
                EmailNoteOutcome::Conflict
            }
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), existing);
        assert_eq!(fs::read_dir(target.parent().unwrap()).unwrap().count(), 1);
    }
}

#[test]
fn email_note_post_commit_failure_preserves_a_verifiable_retry() {
    let vault = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(vault.path()).unwrap();
    let item = payload("Committed invoice", 'b');
    let target = path(&root, &item);
    let result = sync_email_to_obsidian_observed(
        &item,
        "Committed invoice",
        "legacy",
        &root,
        "mail",
        |stage| {
            if stage == NoteObservation::BeforeCreate {
                store::fail_private_child_post_commit_validation_for_test(&target);
            }
        },
    );
    assert!(result.is_err());
    let bytes = fs::read(&target).unwrap();
    assert_eq!(
        bytes,
        render_email_note(&item, "Committed invoice").as_bytes()
    );
    assert_eq!(
        sync_email_to_obsidian(&item, "Committed invoice", "legacy", &root, "mail").unwrap(),
        EmailNoteOutcome::AlreadyPresent
    );
    assert_eq!(fs::read(&target).unwrap(), bytes);
    assert_eq!(fs::read_dir(target.parent().unwrap()).unwrap().count(), 1);
}

#[test]
fn email_note_bound_unicode_directories_preserve_exact_retry() {
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("Notizen ü");
    fs::create_dir(&vault).unwrap();
    let item = payload("Unicode invoice", 'c');
    let subdir = "Eingang/Rechnungen ä";
    assert_eq!(
        sync_email_to_obsidian(&item, "Unicode invoice", "legacy", &vault, subdir).unwrap(),
        EmailNoteOutcome::Created
    );
    assert_eq!(
        sync_email_to_obsidian(&item, "Unicode invoice", "legacy", &vault, subdir).unwrap(),
        EmailNoteOutcome::AlreadyPresent
    );
    let target = vault
        .join(subdir)
        .join("Paperless")
        .join(format!("{}.md", item.document_id));
    assert_eq!(
        fs::read_to_string(target).unwrap(),
        render_email_note(&item, "Unicode invoice")
    );
}

#[cfg(unix)]
#[test]
fn email_note_replaced_root_or_ancestor_never_receives_a_note() {
    for depth in 0..3 {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("vault");
        fs::create_dir(&root).unwrap();
        let item = payload("Bound invoice", 'd');
        let replaced = match depth {
            0 => root.clone(),
            1 => root.join("mail"),
            _ => root.join("mail/Paperless"),
        };
        let retained = replaced.with_file_name("retained-original");
        let result = sync_email_to_obsidian_observed(
            &item,
            "Bound invoice",
            "legacy",
            &root,
            "mail",
            |stage| {
                if stage == NoteObservation::BeforeCreate {
                    fs::rename(&replaced, &retained).unwrap();
                    fs::create_dir(&replaced).unwrap();
                }
            },
        );
        assert!(result.is_err(), "depth={depth}");
        assert_eq!(fs::read_dir(&replaced).unwrap().count(), 0);
        let original_directory = match depth {
            0 => retained.join("mail/Paperless"),
            1 => retained.join("Paperless"),
            _ => retained,
        };
        assert_eq!(fs::read_dir(original_directory).unwrap().count(), 0);
    }
}

#[cfg(unix)]
#[test]
fn email_note_leaf_replacement_after_read_is_not_completion() {
    let vault = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(vault.path()).unwrap();
    let item = payload("Read invoice", 'e');
    sync_email_to_obsidian(&item, "Read invoice", "legacy", &root, "mail").unwrap();
    let target = path(&root, &item);
    let retained = target.with_file_name("retained-original.md");
    let expected = fs::read(&target).unwrap();
    let result =
        sync_email_to_obsidian_observed(&item, "Read invoice", "legacy", &root, "mail", |stage| {
            if stage == NoteObservation::ExistingRead {
                fs::rename(&target, &retained).unwrap();
                fs::write(&target, &expected).unwrap();
            }
        });
    assert!(result.is_err());
    assert_eq!(fs::read(&target).unwrap(), expected);
    assert_eq!(fs::read(&retained).unwrap(), expected);
}

#[cfg(unix)]
#[test]
fn email_note_detached_publication_stays_incomplete_and_preserved() {
    let vault = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(vault.path()).unwrap();
    let item = payload("Published invoice", 'f');
    let directory = root.join("mail/Paperless");
    let retained = root.join("mail/retained-original");
    let result = sync_email_to_obsidian_observed(
        &item,
        "Published invoice",
        "legacy",
        &root,
        "mail",
        |stage| {
            if stage == NoteObservation::Created {
                fs::rename(&directory, &retained).unwrap();
                fs::create_dir(&directory).unwrap();
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
    assert_eq!(
        fs::read_to_string(retained.join(format!("{}.md", item.document_id))).unwrap(),
        render_email_note(&item, "Published invoice")
    );
}

#[cfg(unix)]
#[test]
fn email_note_parent_sync_failure_cannot_acknowledge_publication() {
    struct ResetSyncFailure;
    impl Drop for ResetSyncFailure {
        fn drop(&mut self) {
            store::force_parent_sync_failure_for_test(false);
        }
    }
    let vault = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(vault.path()).unwrap();
    let item = payload("Unsynced invoice", 'a');
    let reset = ResetSyncFailure;
    let result = sync_email_to_obsidian_observed(
        &item,
        "Unsynced invoice",
        "legacy",
        &root,
        "mail",
        |stage| {
            if stage == NoteObservation::BeforeCreate {
                store::force_parent_sync_failure_for_test(true);
            }
        },
    );
    drop(reset);
    assert!(result.is_err());
    let target = path(&root, &item);
    let bytes = fs::read(&target).unwrap();
    assert_eq!(
        bytes,
        render_email_note(&item, "Unsynced invoice").as_bytes()
    );
    assert_eq!(
        sync_email_to_obsidian(&item, "Unsynced invoice", "legacy", &root, "mail").unwrap(),
        EmailNoteOutcome::AlreadyPresent
    );
    assert_eq!(fs::read(target).unwrap(), bytes);
}
