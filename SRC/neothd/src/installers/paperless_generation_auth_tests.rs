use super::*;

fn fresh_root() -> (
    tempfile::TempDir,
    OwnedPaperlessRoot,
    PaperlessVolumeSetSnapshot,
) {
    let home = tempfile::tempdir().unwrap();
    let root_path = crate::config::InstancePaths::for_home(home.path()).paperless_root;
    paperless_staging::prepare_at(&root_path).unwrap();
    let root = paperless_staging::open_owned_root_at(&root_path).unwrap();
    let project = project_name(&root.display);
    let snapshot = PaperlessVolumeSetSnapshot {
        schema_version: 1,
        project,
        volume_set_id: uuid::Uuid::new_v4().to_string(),
        logical_volumes: paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .map(|volume| volume.logical_name.to_owned())
            .collect(),
    };
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    write_auth_test_child(&root, VOLUME_SET_NAME, &bytes);
    emit_rotation_marker(&root, &snapshot.project, &snapshot.volume_set_id, &bytes).unwrap();
    (home, root, snapshot)
}

fn write_auth_test_child(root: &OwnedPaperlessRoot, name: &str, bytes: &[u8]) {
    let state = lifecycle_state_dir(root).unwrap();
    crate::skills::store::atomic_write_private_child_create_new(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        bytes,
    )
    .unwrap();
    ensure_bound(root).unwrap();
}

#[test]
fn malformed_completed_receipt_blocks_fresh_token_begin() {
    let (_home, root, _snapshot) = fresh_root();
    write_auth_test_child(&root, RECEIPT_NAME, b"{}");
    assert_eq!(
        begin_fresh_generation_token(
            &root,
            SecretsBackend::File,
            Some("http://127.0.0.1:18000"),
            "http://127.0.0.1:18000",
            Some(&SecretString::from("old"))
        )
        .unwrap_err(),
        "paperless_generation_auth_receipt"
    );
}

#[test]
fn fresh_grant_accepts_reloaded_new_token_and_rejects_substitution() {
    let (_home, root, _snapshot) = fresh_root();
    let old = SecretString::from("old-token");
    let new = SecretString::from("fresh-token");
    let grant = begin_fresh_generation_token(
        &root,
        SecretsBackend::File,
        Some("http://127.0.0.1:18000"),
        "http://127.0.0.1:18000",
        Some(&old),
    )
    .unwrap()
    .unwrap();
    record_new_token_fingerprint(&root, &grant, &new).unwrap();
    let reloaded = begin_fresh_generation_token(
        &root,
        SecretsBackend::File,
        Some("http://127.0.0.1:18000"),
        "http://127.0.0.1:18000",
        Some(&new),
    )
    .unwrap()
    .unwrap();
    assert!(token_is_persisted_new(&root, &reloaded, &new).unwrap());
    let bytes = read_optional_auth_child(&root, VOLUME_SET_NAME)
        .unwrap()
        .unwrap();
    emit_rotation_marker(&root, &reloaded.project, &reloaded.volume_set_id, &bytes).unwrap();
    assert_eq!(
        begin_fresh_generation_token(
            &root,
            SecretsBackend::File,
            Some("http://127.0.0.1:18000"),
            "http://127.0.0.1:18000",
            Some(&SecretString::from("third"))
        )
        .unwrap_err(),
        "paperless_generation_auth_binding_changed"
    );
}

#[test]
fn file_cas_preserves_other_credentials_and_accepts_retry_after_reload() {
    let (home, root, _snapshot) = fresh_root();
    std::fs::write(
        home.path().join("credentials.yaml"),
        "paperless_url: http://127.0.0.1:18000\npaperless_token: old\nprovider_key: keep\n",
    )
    .unwrap();
    let old = SecretString::from("old");
    let new = SecretString::from("new");
    let grant = begin_fresh_generation_token(
        &root,
        SecretsBackend::File,
        Some("http://127.0.0.1:18000"),
        "http://127.0.0.1:18000",
        Some(&old),
    )
    .unwrap()
    .unwrap();
    record_new_token_fingerprint(&root, &grant, &new).unwrap();
    persist_fresh_generation_token_at(home.path(), &root, &grant, &new).unwrap();
    persist_fresh_generation_token_at(home.path(), &root, &grant, &new).unwrap();
    let persisted = Credentials::load_or_default(&home.path().join("credentials.yaml")).unwrap();
    assert_eq!(persisted.paperless_token.unwrap().expose_secret(), "new");
    assert_eq!(persisted.provider_key.unwrap().expose_secret(), "keep");
}

#[test]
fn receipt_crash_window_returns_false_before_receipt_and_absent_marker_is_noop() {
    let (_home, root, _snapshot) = fresh_root();
    let old = SecretString::from("old");
    let new = SecretString::from("new");
    let grant = begin_fresh_generation_token(
        &root,
        SecretsBackend::File,
        Some("http://127.0.0.1:18000"),
        "http://127.0.0.1:18000",
        Some(&old),
    )
    .unwrap()
    .unwrap();
    record_new_token_fingerprint(&root, &grant, &new).unwrap();
    assert!(!retire_if_completed_receipt_matches(&root, &new).unwrap());
    remove_auth_child(&root).unwrap();
    let receipt = PaperlessLifecycleReceipt {
        schema_version: 2,
        operation: "install",
        contract_id: paperless_staging::OCI_CONTRACT_ID,
        project: project_name(&root.display),
        loopback_port: 18000,
        images: Vec::new(),
        containers: Vec::new(),
        volumes: Vec::new(),
        volume_set_id: None,
        authenticated_api_ready: true,
    };
    assert!(retire_after_authenticated_receipt(&root, &receipt).is_ok());
}

#[test]
fn keychain_cas_requires_effective_store_agreement_and_rejects_third_value() {
    use crate::config::keychain::{InMemorySecretStore, SecretStore};
    let (home, root, _snapshot) = fresh_root();
    std::fs::write(
        home.path().join("freedom.yaml"),
        "secrets_backend: keychain\n",
    )
    .unwrap();
    std::fs::write(
        home.path().join("credentials.yaml"),
        "paperless_url: http://127.0.0.1:18000\nprovider_key: keep\n",
    )
    .unwrap();
    let old = SecretString::from("old");
    let new = SecretString::from("new");
    let grant = begin_fresh_generation_token(
        &root,
        SecretsBackend::Keychain,
        Some("http://127.0.0.1:18000"),
        "http://127.0.0.1:18000",
        Some(&old),
    )
    .unwrap()
    .unwrap();
    record_new_token_fingerprint(&root, &grant, &new).unwrap();
    let store = InMemorySecretStore::default();
    store.set("paperless_token", &old).unwrap();
    persist_keychain_generation_token_with_store(home.path(), &grant, &new, &store).unwrap();
    store
        .set("paperless_token", &SecretString::from("third"))
        .unwrap();
    assert_eq!(
        persist_keychain_generation_token_with_store(home.path(), &grant, &new, &store)
            .unwrap_err(),
        "paperless_generation_auth_token_conflict"
    );
    std::fs::write(
        home.path().join("credentials.yaml"),
        "paperless_url: http://127.0.0.1:18000\npaperless_token: override\n",
    )
    .unwrap();
    assert_eq!(
        persist_keychain_generation_token_with_store(home.path(), &grant, &new, &store)
            .unwrap_err(),
        "paperless_generation_auth_binding_changed"
    );
}
