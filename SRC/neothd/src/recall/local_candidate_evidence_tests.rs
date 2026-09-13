use super::*;

use crate::cli::chat::LocalChatCommunicationSubject;
use crate::config::memory::TranscriptMiningRetention;
use crate::memory::transcript_mining_runtime::AuthenticatedLocalIngress;
use crate::memory::transcript_mining_store::{RawReceiptResolution, TranscriptMiningStore};
use crate::wal::writer::{WalWriterHandle, spawn_for_home};
use tempfile::TempDir;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_secs() as i64
}

fn make_home() -> TempDir {
    let home = tempfile::tempdir().expect("temporary NEOTH home");
    std::fs::create_dir_all(home.path().join("wal")).expect("create WAL directory");
    home
}

fn open_store(home: &std::path::Path) -> TranscriptMiningStore {
    let ingress = AuthenticatedLocalIngress::from_local_chat(
        &LocalChatCommunicationSubject::for_test(),
        home,
        TranscriptMiningRetention::Hours24,
    )
    .expect("initialize fixture HMAC authority");
    let conn = crate::memory::store::open(&home.join("views.db")).expect("open fixture views");
    TranscriptMiningStore::open(conn, ingress).expect("open fixture transcript store")
}

fn start_writer(home: &std::path::Path) -> (WalWriterHandle, tokio::task::JoinHandle<()>) {
    spawn_for_home(
        home.join("wal").join("local-evidence-000001.wal"),
        home.to_path_buf(),
    )
    .expect("spawn production WAL writer")
}

async fn stop_writer(writer: WalWriterHandle, join: tokio::task::JoinHandle<()>) {
    drop(writer);
    join.await.expect("WAL writer task completes");
}

async fn activate(
    store: &mut TranscriptMiningStore,
    writer: &WalWriterHandle,
    home: &std::path::Path,
    text: &str,
) {
    let now = now_unix();
    let raw = store
        .prepare_operator_raw_birth("local-evidence-session", text, now)
        .expect("prepare fixture RAW");
    let raw_receipt = writer
        .append_planned_raw_text_once(home, raw.raw_descriptor().unwrap())
        .await
        .expect("append fixture RAW");
    let RawReceiptResolution::Bound(bound) = store
        .record_raw_receipt(&raw, &raw_receipt, now)
        .expect("authenticate fixture RAW")
    else {
        panic!("fresh fixture RAW must bind")
    };
    let bound_receipt = writer
        .append_planned_mining_outbox_once(home, bound.bound_descriptor().unwrap())
        .await
        .expect("append fixture Bound");
    store
        .record_bound_receipt(&bound, &bound_receipt, now)
        .expect("authenticate fixture Bound");
}

fn selections(provenance_id: &str) -> Vec<u8> {
    format!("{{\"candidate_id\":\"candidate-01\",\"provenance_id\":\"{provenance_id}\",\"raw_offset\":0,\"source_len\":5}}\n").into_bytes()
}

pub(crate) fn initialize_fixture_signing_key(home: &std::path::Path) -> String {
    let key = crate::wal::signing::load_or_init_signing_key(&home.join("wal").join("signing.key"))
        .expect("explicit fixture signing key initialization");
    crate::wal::signing::pubkey_b64(&key)
}

fn local_artifact_bytes(
    dir: &std::path::Path,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, String) {
    let manifest = std::fs::read(dir.join("candidate-evidence-manifest.json")).unwrap();
    let receipt = std::fs::read(dir.join("candidate-evidence-receipt.json")).unwrap();
    let candidates = std::fs::read(dir.join("candidates.jsonl")).unwrap();
    let custody = std::fs::read(dir.join(LOCAL_CANDIDATE_EVIDENCE_CUSTODY_FILE)).unwrap();
    let manifest_hash = sha256(&manifest);
    let receipt_hash = sha256(&receipt);
    (
        manifest,
        receipt,
        candidates,
        custody,
        manifest_hash,
        receipt_hash,
    )
}

/// Real retained RAW + Bound fixture, deliberately exposed to recall-side
/// tests so consumers exercise the same existing-only reader and WAL custody.
pub(crate) struct LocalEvidenceFixture {
    pub(crate) home: TempDir,
    pub(crate) context: CandidateEvidenceUseContext,
    pub(crate) provenance_id: String,
    store: TranscriptMiningStore,
    writer: WalWriterHandle,
    join: tokio::task::JoinHandle<()>,
}

pub(crate) async fn local_evidence_fixture(text: &str) -> LocalEvidenceFixture {
    let home = make_home();
    let mut store = open_store(home.path());
    let (writer, join) = start_writer(home.path());
    activate(&mut store, &writer, home.path(), text).await;
    let context =
        CandidateEvidenceUseContext::open(Some(home.path())).expect("open existing-only reader");
    let provenance_id = list_local_candidates(&context, 1)
        .expect("list active fixture")
        .pop()
        .expect("one active fixture candidate")
        .provenance_id;
    LocalEvidenceFixture {
        home,
        context,
        provenance_id,
        store,
        writer,
        join,
    }
}

impl LocalEvidenceFixture {
    pub(crate) async fn revoke(&mut self) {
        let revoked = self
            .store
            .prepare_pending_revocations(now_unix() + 86_400)
            .expect("expire active fixture");
        assert_eq!(revoked.len(), 1);
        let receipt = self
            .writer
            .append_planned_mining_outbox_once(
                self.home.path(),
                revoked[0].revoked_descriptor().unwrap(),
            )
            .await
            .unwrap();
        self.store
            .record_revoked_receipt(&revoked[0], &receipt, now_unix() + 86_400)
            .unwrap();
    }

    pub(crate) async fn shutdown(self) {
        stop_writer(self.writer, self.join).await;
    }
}

#[tokio::test]
async fn local_export_round_trips_and_exact_retry_is_deterministic() {
    let fixture = local_evidence_fixture("hello retained operator transcript").await;
    let signing_pubkey = initialize_fixture_signing_key(fixture.home.path());
    let evidence = tempfile::tempdir().unwrap();
    let export_dir = evidence.path().join("bundle");
    std::fs::create_dir(&export_dir).unwrap();
    let selection = selections(&fixture.provenance_id);
    let first = export_local_candidates(
        &fixture.context,
        &selection,
        "bundle-01",
        &export_dir,
        &signing_pubkey,
    )
    .expect("export explicitly selected authenticated span");
    let second = export_local_candidates(
        &fixture.context,
        &selection,
        "bundle-01",
        &export_dir,
        &signing_pubkey,
    )
    .expect("exact retry reuses byte-identical artifacts");
    assert_eq!(first.source_sha256, second.source_sha256);
    assert_eq!(first.candidates_sha256, second.candidates_sha256);
    let loaded =
        load_candidate_evidence_with_context(&export_dir, &signing_pubkey, &fixture.context)
            .expect("local context loader revalidates RAW plus Bound custody");
    assert_eq!(loaded.candidates().len(), 1);
    assert_eq!(
        std::fs::read(export_dir.join("source.evidence")).unwrap(),
        b"hello"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn export_rejects_utf8_midpoint_and_duplicate_source_selection() {
    let fixture = local_evidence_fixture("hällo transcript").await;
    let signing_pubkey = initialize_fixture_signing_key(fixture.home.path());
    let evidence = tempfile::tempdir().unwrap();
    let malformed = format!(
        "{{\"candidate_id\":\"candidate-01\",\"provenance_id\":\"{}\",\"raw_offset\":2,\"source_len\":1}}\n",
        fixture.provenance_id
    );
    assert!(
        export_local_candidates(
            &fixture.context,
            malformed.as_bytes(),
            "bundle-utf8",
            evidence.path(),
            &signing_pubkey
        )
        .is_err()
    );
    let duplicate = format!(
        "{{\"candidate_id\":\"candidate-01\",\"provenance_id\":\"{}\",\"raw_offset\":0,\"source_len\":1}}\n{{\"candidate_id\":\"candidate-02\",\"provenance_id\":\"{}\",\"raw_offset\":0,\"source_len\":1}}\n",
        fixture.provenance_id, fixture.provenance_id
    );
    assert!(
        export_local_candidates(
            &fixture.context,
            duplicate.as_bytes(),
            "bundle-duplicate",
            evidence.path(),
            &signing_pubkey
        )
        .is_err()
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn missing_local_authorities_never_initialize_reader_or_exporter() {
    let home = make_home();
    let signing = home.path().join("wal").join("signing.key");
    assert!(CandidateEvidenceUseContext::open(Some(home.path())).is_err());
    assert!(!home.path().join("wal").join("hmac.key").exists());
    assert!(!home.path().join("views.db").exists());
    assert!(!signing.exists());

    let mut store = open_store(home.path());
    let (writer, join) = start_writer(home.path());
    activate(
        &mut store,
        &writer,
        home.path(),
        "authenticated but unsigned",
    )
    .await;
    let context = CandidateEvidenceUseContext::open(Some(home.path())).unwrap();
    let provenance_id = list_local_candidates(&context, 1)
        .unwrap()
        .pop()
        .unwrap()
        .provenance_id;
    let evidence = tempfile::tempdir().unwrap();
    assert!(
        export_local_candidates(
            &context,
            &selections(&provenance_id),
            "bundle-unsigned",
            evidence.path(),
            "invalid"
        )
        .is_err()
    );
    assert!(
        !signing.exists(),
        "exporter must not initialize signing authority"
    );
    assert!(
        !evidence.path().join("source.evidence").exists(),
        "failed unsigned export must not emit a bundle child"
    );
    stop_writer(writer, join).await;
}

#[tokio::test]
async fn local_export_cannot_use_foreign_home_legacy_rows_or_deleted_source() {
    let fixture = local_evidence_fixture("selected retained source").await;
    let other = local_evidence_fixture("independent home source").await;
    let key = initialize_fixture_signing_key(fixture.home.path());
    let output = tempfile::tempdir().unwrap();
    export_local_candidates(
        &fixture.context,
        &selections(&fixture.provenance_id),
        "local-delete",
        output.path(),
        &key,
    )
    .unwrap();
    assert!(
        load_candidate_evidence_with_context(output.path(), &key, &other.context).is_err(),
        "a valid foreign home cannot supply this source authority"
    );
    let conn = crate::memory::store::open(&fixture.home.path().join("views.db")).unwrap();
    crate::memory::transcript_store::insert_turn(
        &conn,
        "legacy",
        "operator",
        now_unix(),
        "legacy unbound source",
    )
    .unwrap();
    assert_eq!(
        list_local_candidates(&fixture.context, 20).unwrap().len(),
        1,
        "legacy raw text is not local mining authority"
    );
    assert_eq!(conn.execute("DELETE FROM raw_turns WHERE id=(SELECT raw_turn_id FROM transcript_mining_provenance WHERE provenance_id=?1)", [&fixture.provenance_id]).unwrap(), 1);
    assert!(
        list_local_candidates(&fixture.context, 20)
            .unwrap()
            .is_empty()
    );
    assert!(
        load_candidate_evidence_with_context(output.path(), &key, &fixture.context).is_err(),
        "a signed export cannot outlive deletion of its retained source"
    );
    drop(conn);
    other.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn revoked_local_custody_rejects_loader_and_persisted_metadata() {
    let mut fixture = local_evidence_fixture("custody must be revalidated").await;
    let signing_pubkey = initialize_fixture_signing_key(fixture.home.path());
    let evidence = tempfile::tempdir().unwrap();
    let export_dir = evidence.path().join("bundle");
    std::fs::create_dir(&export_dir).unwrap();
    export_local_candidates(
        &fixture.context,
        &selections(&fixture.provenance_id),
        "bundle-revoked",
        &export_dir,
        &signing_pubkey,
    )
    .unwrap();
    let (manifest, receipt, candidates, custody, manifest_hash, receipt_hash) =
        local_artifact_bytes(&export_dir);
    let loaded =
        load_candidate_evidence_with_context(&export_dir, &signing_pubkey, &fixture.context)
            .unwrap();
    let key_hash = loaded.expected_receipt_pubkey_sha256();
    crate::recall::parity_candidate_evidence::validate_persisted_candidate_evidence_metadata_with_context(
        &manifest, &receipt, &candidates, Some(&custody), &signing_pubkey, &manifest_hash, &receipt_hash, key_hash, &fixture.context,
    ).expect("fresh retained custody must validate with the decoded public-key digest");
    let mut mutated_custody = custody.clone();
    *mutated_custody.last_mut().expect("nonempty custody") ^= 1;
    assert!(crate::recall::parity_candidate_evidence::validate_persisted_candidate_evidence_metadata_with_context(
        &manifest, &receipt, &candidates, Some(&mutated_custody), &signing_pubkey, &manifest_hash, &receipt_hash, key_hash, &fixture.context,
    ).is_err(), "an exact custody mutation must fail before local evidence is reused");
    fixture.revoke().await;
    assert!(
        load_candidate_evidence_with_context(&export_dir, &signing_pubkey, &fixture.context)
            .is_err()
    );
    assert!(crate::recall::parity_candidate_evidence::validate_persisted_candidate_evidence_metadata_with_context(
        &manifest, &receipt, &candidates, Some(&custody), &signing_pubkey, &manifest_hash, &receipt_hash, key_hash, &fixture.context,
    ).is_err());
    fixture.shutdown().await;
}
