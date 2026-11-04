use super::*;
use crate::paperless::quarantine::{
    QuarantineReason, list_quarantine_items, load_quarantine_item, quarantine_dir, quarantine_item,
};
use std::sync::{Arc, Barrier};

fn item(uid: &str, body: &str) -> QuarantineItem {
    QuarantineItem {
        uid: uid.into(),
        from: "sender@example.test".into(),
        subject: "test message".into(),
        received_unix: 100,
        reason: QuarantineReason::ScannerError {
            description: "scanner failed".into(),
        },
        findings: vec![],
        body_preview: body.chars().take(512).collect(),
    }
}

fn opaque_id(ch: char) -> String {
    format!("email-{}", ch.to_string().repeat(64))
}

fn record_path(home: &Path, id: &str) -> std::path::PathBuf {
    super::super::item_path(&quarantine_dir(home), id)
}

#[test]
fn separate_account_ids_are_preserved_and_loadable() {
    let home = tempfile::tempdir().unwrap();
    let entry = item("same-mailbox-uid", "same message");
    let ids = [opaque_id('a'), opaque_id('b')];
    for id in &ids {
        assert_eq!(
            persist(home.path(), &entry, id, "same message").unwrap(),
            Outcome::Created
        );
        assert_eq!(
            load_quarantine_item(home.path(), id).unwrap().unwrap().uid,
            *id
        );
    }
    let mut listed: Vec<_> = list_quarantine_items(home.path())
        .unwrap()
        .into_iter()
        .map(|entry| entry.uid)
        .collect();
    listed.sort();
    assert_eq!(listed, ids);
}

#[test]
fn retry_retains_first_timestamp_and_exact_bytes() {
    let home = tempfile::tempdir().unwrap();
    let id = opaque_id('c');
    let mut entry = item("raw-uid", "body");
    assert_eq!(
        persist(home.path(), &entry, &id, "body").unwrap(),
        Outcome::Created
    );
    let original = fs::read(record_path(home.path(), &id)).unwrap();
    entry.received_unix = 200;
    assert_eq!(
        persist(home.path(), &entry, &id, "body").unwrap(),
        Outcome::AlreadyPresent
    );
    assert_eq!(fs::read(record_path(home.path(), &id)).unwrap(), original);
    assert_eq!(
        load_quarantine_item(home.path(), &id)
            .unwrap()
            .unwrap()
            .received_unix,
        100
    );
}

#[test]
fn body_drift_beyond_preview_and_reason_drift_conflict() {
    let home = tempfile::tempdir().unwrap();
    let body = format!("{}first", "x".repeat(512));
    let changed_body = format!("{}second", "x".repeat(512));
    let id = opaque_id('d');
    let mut entry = item("raw-uid", &body);
    persist(home.path(), &entry, &id, &body).unwrap();
    let original = fs::read(record_path(home.path(), &id)).unwrap();
    assert_eq!(
        persist(home.path(), &entry, &id, &changed_body).unwrap(),
        Outcome::Conflict
    );
    entry.reason = QuarantineReason::ScannerError {
        description: "different failure".into(),
    };
    assert_eq!(
        persist(home.path(), &entry, &id, &body).unwrap(),
        Outcome::Conflict
    );
    assert_eq!(fs::read(record_path(home.path(), &id)).unwrap(), original);
}

#[test]
fn legacy_files_block_even_if_hashed_lossy_or_renamed() {
    for (index, ch) in ['e', 'f', '0'].into_iter().enumerate() {
        let home = tempfile::tempdir().unwrap();
        let entry = item("legacy/uid", "legacy body");
        let original_path = quarantine_item(home.path(), &entry).unwrap();
        let dir = quarantine_dir(home.path());
        let path = match index {
            1 => super::super::legacy_item_path(&dir, &entry.uid),
            2 => dir.join("renamed.json"),
            _ => original_path.clone(),
        };
        if path != original_path {
            fs::rename(&original_path, &path).unwrap();
        }
        let original = fs::read(&path).unwrap();
        let id = opaque_id(ch);
        assert_eq!(
            persist(home.path(), &entry, &id, "legacy body").unwrap(),
            Outcome::LegacyAmbiguous
        );
        assert_eq!(fs::read(path).unwrap(), original);
        assert!(!record_path(home.path(), &id).exists());
    }
}

#[test]
fn unsafe_targets_and_invalid_ids_fail_closed() {
    let entry = item("raw-uid", "body");
    let id = opaque_id('8');
    for kind in 0..4 {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(quarantine_dir(home.path())).unwrap();
        let path = record_path(home.path(), &id);
        match kind {
            0 => fs::write(&path, b"{").unwrap(),
            1 => fs::create_dir(&path).unwrap(),
            2 => fs::write(&path, b"{}").unwrap(),
            _ => fs::write(&path, vec![b'x'; MAX_RECORD_BYTES as usize + 1]).unwrap(),
        }
        assert_eq!(
            persist(home.path(), &entry, &id, "body").unwrap(),
            Outcome::Conflict
        );
    }
    for field in ["schema", "subject"] {
        let home = tempfile::tempdir().unwrap();
        persist(home.path(), &entry, &id, "body").unwrap();
        let path = record_path(home.path(), &id);
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope[field] = serde_json::json!("edited");
        let changed = serde_json::to_vec_pretty(&envelope).unwrap();
        fs::write(&path, &changed).unwrap();
        assert_eq!(
            persist(home.path(), &entry, &id, "body").unwrap(),
            Outcome::Conflict
        );
        assert_eq!(fs::read(path).unwrap(), changed);
    }
    let home = tempfile::tempdir().unwrap();
    assert!(persist(home.path(), &entry, "../outside", "body").is_err());
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    fs::create_dir(quarantine_dir(home.path())).unwrap();
    fs::write(quarantine_dir(home.path()).join("legacy.json"), b"{").unwrap();
    assert!(persist(home.path(), &entry, &id, "body").is_err());

    #[cfg(unix)]
    {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(quarantine_dir(home.path())).unwrap();
        let outside = home.path().join("outside");
        fs::write(&outside, b"preserve").unwrap();
        std::os::unix::fs::symlink(&outside, record_path(home.path(), &id)).unwrap();
        assert_eq!(
            persist(home.path(), &entry, &id, "body").unwrap(),
            Outcome::Conflict
        );
        assert_eq!(fs::read(outside).unwrap(), b"preserve");
    }
}

#[test]
fn concurrent_creation_has_one_winner_and_retry_is_idempotent() {
    let home = tempfile::tempdir().unwrap();
    let id = opaque_id('a');
    let entry = item("raw-uid", "body");
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let path = home.path().to_owned();
        let barrier = Arc::clone(&barrier);
        let entry = entry.clone();
        let id = id.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            persist(&path, &entry, &id, "body")
        }));
    }
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(Outcome::Created)))
            .count(),
        1
    );
    assert!(outcomes.iter().all(|outcome| matches!(
        outcome,
        Ok(Outcome::Created | Outcome::AlreadyPresent | Outcome::Conflict) | Err(_)
    )));
    let original = fs::read(record_path(home.path(), &id)).unwrap();
    assert_eq!(
        persist(home.path(), &entry, &id, "body").unwrap(),
        Outcome::AlreadyPresent
    );
    assert_eq!(fs::read(record_path(home.path(), &id)).unwrap(), original);
}
