#![cfg(test)]

//! Real loopback HTTP regressions for the scoped Dream-to-Obsidian sync route.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use super::*;
use crate::config::FreedomConfig;
use crate::security::api_tokens;

const PATH: &str = "/api/dreams/obsidian/sync";
const DAY: &str = "2026-09-24";
const SUBDIR: &str = "ScopedDreams";

async fn start_dream_sync_http_test_server(
    home: &std::path::Path,
    config: FreedomConfig,
) -> (
    Arc<ApiState>,
    crate::wal::writer::WalWriterHandle,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
    Arc<Notify>,
    u16,
) {
    let (writer, wal_join) =
        crate::wal::writer::spawn(home.join("dream-obsidian-http-test.wal")).unwrap();
    let state = Arc::new(ApiState {
        writer: writer.clone(),
        config: Arc::new(config.clone()),
        reload_controller: Arc::new(crate::config::reload::ReloadController::new(
            config,
            home.join("freedom.yaml"),
        )),
        home: home.to_path_buf(),
        token: "dream-obsidian-master-test-token".to_owned(),
        cooldown: Arc::new(AuthCooldown::new()),
        boot_instant: Instant::now(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown = Arc::new(Notify::new());
    let server = tokio::spawn(run_server(
        listener,
        Arc::clone(&state),
        Arc::clone(&shutdown),
    ));
    (state, writer, wal_join, server, shutdown, port)
}

async fn post_dream_sync_http(port: u16, token: Option<&str>, body: &str) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let authorization = token
            .map(|value| format!("Authorization: Bearer {value}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "POST {PATH} HTTP/1.1\r\n\
             Host: localhost\r\n\
             {authorization}\
             Content-Type: application/json\r\n\
             Connection: close\r\n\
             Content-Length: {}\r\n\r\n{}",
            body.len(),
            body,
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let mut envelope: serde_json::Value = serde_json::from_str(body).unwrap();
        envelope["_http_status"] =
            serde_json::Value::String(head.split_whitespace().nth(1).unwrap().to_owned());
        envelope
    })
    .await
    .expect("Dream Obsidian sync HTTP exchange timed out")
}

async fn stop_dream_sync_http_test_server(
    state: Arc<ApiState>,
    writer: crate::wal::writer::WalWriterHandle,
    wal_join: tokio::task::JoinHandle<()>,
    server: tokio::task::JoinHandle<()>,
    shutdown: Arc<Notify>,
) {
    shutdown.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(3), server)
        .await
        .expect("Dream Obsidian sync HTTP server did not stop")
        .expect("Dream Obsidian sync HTTP server task panicked");
    drop(state);
    drop(writer);
    tokio::time::timeout(std::time::Duration::from_secs(3), wal_join)
        .await
        .expect("Dream Obsidian sync WAL writer did not stop")
        .expect("Dream Obsidian sync WAL writer panicked");
}

fn scoped_token(home: &std::path::Path, scopes: Vec<String>) -> (String, String) {
    let (record, token) = api_tokens::create_token("dream-obsidian-http", scopes, None).unwrap();
    let token_id = record.id.clone();
    api_tokens::save_store(home, &[record]).unwrap();
    (token_id, token)
}

fn configured(vault: &std::path::Path) -> FreedomConfig {
    let mut config = FreedomConfig::default();
    config.dreaming.enabled = true;
    config.autonomy = crate::permissions::AutonomyLevel::Standard;
    config.obsidian_vault = Some(vault.to_string_lossy().into_owned());
    config.obsidian_subdir = Some(SUBDIR.to_owned());
    config
}

fn request(day: &str) -> String {
    serde_json::json!({"day": day}).to_string()
}

fn archived_dream(day: &str) -> crate::daemon::dreaming::Dream {
    crate::daemon::dreaming::Dream {
        composed_ts_unix: 1_790_208_000,
        day: day.to_owned(),
        theme_label: "private dream theme".to_owned(),
        summary: "private archived dream summary".to_owned(),
        event_ids: vec![42],
        tags: vec!["private".to_owned()],
    }
}

fn dream_note(vault: &std::path::Path) -> std::path::PathBuf {
    vault.join(SUBDIR).join("Dreams").join(format!("{DAY}.md"))
}

fn n8n_audit_payloads(wal: &std::path::Path) -> Vec<serde_json::Value> {
    let bytes = std::fs::read(wal).unwrap();
    let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
    let mut offset = header.header_len();
    let mut payloads = Vec::new();
    while offset < bytes.len() {
        let frame = crate::wal::frame::decode_frame(&bytes[offset..]).unwrap();
        if frame.header.event_type == crate::wal::events::EVENT_TYPE_N8N_REQUEST {
            payloads.push(serde_json::from_slice(frame.payload).unwrap());
        }
        offset += frame.header.total_len as usize;
    }
    payloads
}

#[tokio::test]
async fn dream_sync_scope_is_rejected_before_body_parse_or_vault_side_effect() {
    let home = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let vault = workspace.path().join("uncreated-vault");
    let (_, wrong_token) = scoped_token(home.path(), vec![api_tokens::SCOPE_RECALL_READ.to_owned()]);
    let (state, writer, wal_join, server, shutdown, port) =
        start_dream_sync_http_test_server(home.path(), configured(&vault)).await;

    let denied = post_dream_sync_http(port, Some(&wrong_token), "{not-json").await;
    assert_eq!(denied["_http_status"], "403");
    assert_eq!(denied["error"]["code"], "PermissionDenied");
    assert!(!vault.exists());

    stop_dream_sync_http_test_server(state, writer, wal_join, server, shutdown).await;
}

#[tokio::test]
async fn dream_sync_rejects_invalid_unknown_and_private_request_fields_with_fixed_400() {
    let home = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();
    let (_, token) = scoped_token(
        home.path(),
        vec![api_tokens::SCOPE_DREAMS_OBSIDIAN_WRITE.to_owned()],
    );
    let (state, writer, wal_join, server, shutdown, port) =
        start_dream_sync_http_test_server(home.path(), configured(vault.path())).await;

    for body in [
        "{not-json".to_owned(),
        r#"{"day":"2026-9-24"}"#.to_owned(),
        r#"{"day":"2026-09-024"}"#.to_owned(),
        r#"{"day":"２０２６-09-24"}"#.to_owned(),
        r#"{"day":"2026-09-24","private_vault":"attacker"}"#.to_owned(),
        r#"{"day":"2026-09-24","token":"private-bearer-material"}"#.to_owned(),
    ] {
        let response = post_dream_sync_http(port, Some(&token), &body).await;
        assert_eq!(response["_http_status"], "400", "{body}");
        assert_eq!(response["error"]["code"], "BadRequest");
        assert_eq!(response["error"]["message"], "dream_obsidian_sync_request_invalid");
        assert!(!response.to_string().contains("private-bearer-material"));
    }
    assert!(!vault.path().join(SUBDIR).exists());

    stop_dream_sync_http_test_server(state, writer, wal_join, server, shutdown).await;
}

#[tokio::test]
async fn dream_sync_archived_day_writes_only_configured_vault_and_redacts_paths() {
    let home = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();
    let ambient = home.path().join("NEOTH-sessions").join("Dreams");
    std::fs::create_dir_all(&ambient).unwrap();
    std::fs::write(ambient.join(format!("{DAY}.md")), "ambient private dream").unwrap();
    crate::daemon::dreaming::append_dream(home.path(), &archived_dream(DAY)).unwrap();
    let (_, token) = scoped_token(
        home.path(),
        vec![api_tokens::SCOPE_DREAMS_OBSIDIAN_WRITE.to_owned()],
    );
    let (state, writer, wal_join, server, shutdown, port) =
        start_dream_sync_http_test_server(home.path(), configured(vault.path())).await;

    let response = post_dream_sync_http(port, Some(&token), &request(DAY)).await;
    assert_eq!(response["_http_status"], "200");
    assert_eq!(response["data"]["day"], DAY);
    assert_eq!(response["data"]["written"], true);
    assert_eq!(response["data"]["dream_count"], 1);
    assert!(response["data"]["bytes_written"].as_u64().unwrap() > 0);
    assert!(matches!(
        response["data"]["durability"].as_str(),
        Some("published_and_synced" | "published_durability_unknown")
    ));
    assert!(response["data"].get("target_path").is_none());
    let note = dream_note(vault.path());
    assert!(note.exists());
    assert!(std::fs::read_to_string(note).unwrap().contains("private archived dream summary"));
    assert_eq!(std::fs::read_to_string(ambient.join(format!("{DAY}.md"))).unwrap(), "ambient private dream");
    let serialized = response.to_string();
    assert!(!serialized.contains(vault.path().to_string_lossy().as_ref()));
    assert!(!serialized.contains(home.path().to_string_lossy().as_ref()));
    assert!(!serialized.contains("ambient private dream"));

    stop_dream_sync_http_test_server(state, writer, wal_join, server, shutdown).await;
}

#[tokio::test]
async fn dream_sync_quiet_day_leaves_configured_vault_uncreated() {
    let home = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let vault = workspace.path().join("uncreated-vault");
    let (_, token) = scoped_token(
        home.path(),
        vec![api_tokens::SCOPE_DREAMS_OBSIDIAN_WRITE.to_owned()],
    );
    let (state, writer, wal_join, server, shutdown, port) =
        start_dream_sync_http_test_server(home.path(), configured(&vault)).await;

    let response = post_dream_sync_http(port, Some(&token), &request(DAY)).await;
    assert_eq!(response["_http_status"], "200");
    assert_eq!(response["data"]["written"], false);
    assert_eq!(response["data"]["dream_count"], 0);
    assert_eq!(response["data"]["bytes_written"], 0);
    assert_eq!(response["data"]["durability"], "not_written");
    assert!(!vault.exists());

    stop_dream_sync_http_test_server(state, writer, wal_join, server, shutdown).await;
}

#[tokio::test]
async fn dream_sync_policy_vault_and_retirement_refuse_before_output() {
    for case in ["disabled", "strict", "missing_vault", "retired"] {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let vault = workspace.path().join("uncreated-vault");
        crate::daemon::dreaming::append_dream(home.path(), &archived_dream(DAY)).unwrap();
        let mut config = configured(&vault);
        match case {
            "disabled" => config.dreaming.enabled = false,
            "strict" => config.autonomy = crate::permissions::AutonomyLevel::Strict,
            "missing_vault" => config.obsidian_vault = None,
            _ => {}
        }
        let (state, writer, wal_join, server, shutdown, port) =
            start_dream_sync_http_test_server(home.path(), config).await;
        if case == "retired" {
            state.reload_controller.retire_generation_effect_runtime();
        }
        let response = post_dream_sync_http(port, Some(&state.token), &request(DAY)).await;
        let expected = if case == "missing_vault" { "503" } else { "403" };
        assert_eq!(response["_http_status"], expected, "{case}");
        assert!(!vault.exists(), "{case}");
        stop_dream_sync_http_test_server(state, writer, wal_join, server, shutdown).await;
        let receipts = n8n_audit_payloads(&home.path().join("dream-obsidian-http-test.wal"));
        assert!(!receipts.iter().any(|receipt| receipt["kind"] == "n8n_dream_obsidian_sync"));
    }
}

#[tokio::test]
async fn dream_sync_corrupt_input_returns_fixed_503_without_output() {
    let home = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(crate::daemon::dreaming::dreams_dir(home.path())).unwrap();
    std::fs::write(
        crate::daemon::dreaming::jsonl_file_for_day(home.path(), DAY),
        b"{private corrupt dream input}\n",
    )
    .unwrap();
    let (_, token) = scoped_token(
        home.path(),
        vec![api_tokens::SCOPE_DREAMS_OBSIDIAN_WRITE.to_owned()],
    );
    let (state, writer, wal_join, server, shutdown, port) =
        start_dream_sync_http_test_server(home.path(), configured(vault.path())).await;

    let response = post_dream_sync_http(port, Some(&token), &request(DAY)).await;
    assert_eq!(response["_http_status"], "503");
    assert_eq!(response["error"]["code"], "StoreUnavailable");
    assert_eq!(
        response["error"]["message"],
        "dream_obsidian_sync_failed"
    );
    let serialized = response.to_string();
    assert!(!serialized.contains("private corrupt dream input"));
    assert!(!serialized.contains(vault.path().to_string_lossy().as_ref()));
    assert!(!dream_note(vault.path()).exists());
    assert!(!vault.path().join(SUBDIR).exists());

    stop_dream_sync_http_test_server(state, writer, wal_join, server, shutdown).await;
}

#[tokio::test]
async fn dream_sync_wal_receipt_records_verified_scoped_token_id_without_secrets() {
    let home = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();
    crate::daemon::dreaming::append_dream(home.path(), &archived_dream(DAY)).unwrap();
    let (token_id, token) = scoped_token(
        home.path(),
        vec![api_tokens::SCOPE_DREAMS_OBSIDIAN_WRITE.to_owned()],
    );
    let wal = home.path().join("dream-obsidian-http-test.wal");
    let (state, writer, wal_join, server, shutdown, port) =
        start_dream_sync_http_test_server(home.path(), configured(vault.path())).await;

    let response = post_dream_sync_http(port, Some(&token), &request(DAY)).await;
    assert_eq!(response["_http_status"], "200");
    let request_id = response["request_id"].as_str().unwrap();
    let durability = response["data"]["durability"].clone();
    assert!(matches!(
        durability.as_str(),
        Some("published_and_synced" | "published_durability_unknown")
    ));
    stop_dream_sync_http_test_server(state, writer, wal_join, server, shutdown).await;

    let receipts = n8n_audit_payloads(&wal);
    let sync_receipts = receipts
        .iter()
        .filter(|payload| payload["kind"] == "n8n_dream_obsidian_sync")
        .collect::<Vec<_>>();
    assert_eq!(sync_receipts.len(), 2);
    for receipt in &sync_receipts {
        assert_eq!(receipt["request_id"], request_id);
        assert_eq!(receipt["caller"]["kind"], "scoped_token");
        assert_eq!(receipt["caller"]["token_id"], token_id);
        let serialized = receipt.to_string();
        assert!(!serialized.contains(&token));
        assert!(!serialized.contains(vault.path().to_string_lossy().as_ref()));
        assert!(!serialized.contains("private archived dream summary"));
    }
    assert!(sync_receipts.iter().any(|receipt| receipt["phase"] == "admission"));
    let completed = sync_receipts
        .iter()
        .find(|receipt| receipt["phase"] == "completed")
        .expect("completed Dream sync receipt");
    assert_eq!(completed["durability"], durability);
}
