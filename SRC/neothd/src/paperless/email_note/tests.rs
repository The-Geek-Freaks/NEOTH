use super::*;
use crate::security::paperless_ingest::{OcrSource, ingest_ocr_text};

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
