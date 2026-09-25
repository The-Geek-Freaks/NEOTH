#![cfg(test)]

//! Real loopback HTTP regressions for the bounded Paperless consult route.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use super::*;
use crate::config::FreedomConfig;
use crate::security::api_tokens;

const PATH: &str = "/api/paperless/consult";

async fn start_consult_http_test_server(
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
        crate::wal::writer::spawn(home.join("paperless-consult-http-test.wal")).unwrap();
    let state = Arc::new(ApiState {
        writer: writer.clone(),
        config: Arc::new(config.clone()),
        reload_controller: Arc::new(crate::config::reload::ReloadController::new(
            config,
            home.join("freedom.yaml"),
        )),
        home: home.to_path_buf(),
        token: "paperless-consult-master-test-token".to_owned(),
        cooldown: Arc::new(AuthCooldown::new()),
        boot_instant: Instant::now(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown = Arc::new(Notify::new());
    let server = tokio::spawn(run_server(listener, Arc::clone(&state), Arc::clone(&shutdown)));
    (state, writer, wal_join, server, shutdown, port)
}

async fn post_consult_http(port: u16, token: Option<&str>, body: &str) -> serde_json::Value {
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
        envelope["_http_status"] = serde_json::Value::String(
            head.split_whitespace().nth(1).unwrap().to_owned(),
        );
        envelope
    })
    .await
    .expect("paperless consult HTTP exchange timed out")
}

async fn stop_consult_http_test_server(
    state: Arc<ApiState>,
    writer: crate::wal::writer::WalWriterHandle,
    wal_join: tokio::task::JoinHandle<()>,
    server: tokio::task::JoinHandle<()>,
    shutdown: Arc<Notify>,
) {
    shutdown.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(3), server)
        .await
        .expect("paperless consult HTTP server did not stop")
        .expect("paperless consult HTTP server task panicked");
    drop(state);
    drop(writer);
    tokio::time::timeout(std::time::Duration::from_secs(3), wal_join)
        .await
        .expect("paperless consult HTTP WAL writer did not stop")
        .expect("paperless consult HTTP WAL writer panicked");
}

fn consult_token(home: &std::path::Path, scopes: Vec<String>) -> String {
    let (record, token) = api_tokens::create_token("paperless-consult-http", scopes, None).unwrap();
    api_tokens::save_store(home, &[record]).unwrap();
    token
}

fn configured(vault: &std::path::Path, subdir: &str) -> FreedomConfig {
    FreedomConfig {
        obsidian_vault: Some(vault.to_string_lossy().into_owned()),
        obsidian_subdir: Some(subdir.to_owned()),
        ..FreedomConfig::default()
    }
}

fn body(question: &str, limit: usize) -> String {
    serde_json::json!({"question": question, "limit": limit}).to_string()
}

#[tokio::test]
async fn consult_scope_is_rejected_before_body_parse_or_vault_read() {
    let home = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();
    let wrong_token = consult_token(home.path(), vec![api_tokens::SCOPE_RECALL_READ.to_owned()]);
    let (state, writer, wal_join, server, shutdown, port) =
        start_consult_http_test_server(home.path(), configured(vault.path(), "Scoped")).await;

    let denied = post_consult_http(port, Some(&wrong_token), "{not-json").await;
    assert_eq!(denied["_http_status"], "403");
    assert_eq!(denied["error"]["code"], "PermissionDenied");
    assert!(!vault.path().join("Scoped").exists());

    stop_consult_http_test_server(state, writer, wal_join, server, shutdown).await;
}

#[tokio::test]
async fn consult_rejects_strict_invalid_requests_before_configured_vault_read() {
    let home = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();
    let marker = vault.path().join("Scoped").join("Paperless").join("private.md");
    std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
    std::fs::write(&marker, "private fixture must not be read").unwrap();
    let before = std::fs::read(&marker).unwrap();
    let token = consult_token(home.path(), vec![api_tokens::SCOPE_PAPERLESS_CONSULT_READ.to_owned()]);
    let (state, writer, wal_join, server, shutdown, port) =
        start_consult_http_test_server(home.path(), configured(vault.path(), "Scoped")).await;

    let oversized = serde_json::json!({"question": "x".repeat(4097)}).to_string();
    for request in [
        "{not-json".to_owned(),
        r#"{"question":"invoice","private_vault":"attacker"}"#.to_owned(),
        r#"{"question":"   "}"#.to_owned(),
        oversized,
        body("invoice", 0),
        body("invoice", 21),
    ] {
        let response = post_consult_http(port, Some(&token), &request).await;
        assert_eq!(response["_http_status"], "400", "{request}");
        assert_eq!(response["error"]["message"], "paperless_consult_request_invalid");
    }
    assert_eq!(std::fs::read(&marker).unwrap(), before);

    stop_consult_http_test_server(state, writer, wal_join, server, shutdown).await;
}

#[tokio::test]
async fn consult_reads_only_configured_vault_and_redacts_paths_from_real_match_response() {
    let home = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();
    let ambient = home.path().join("NEOTH").join("Paperless");
    let configured_note = vault.path().join("Scoped").join("Paperless").join("acme.md");
    std::fs::create_dir_all(configured_note.parent().unwrap()).unwrap();
    std::fs::write(&configured_note, "ACME invoice totals are settled.").unwrap();
    std::fs::create_dir_all(&ambient).unwrap();
    std::fs::write(ambient.join("ambient.md"), "invoice private ambient marker").unwrap();
    let token = consult_token(home.path(), vec![api_tokens::SCOPE_PAPERLESS_CONSULT_READ.to_owned()]);
    let (state, writer, wal_join, server, shutdown, port) =
        start_consult_http_test_server(home.path(), configured(vault.path(), "Scoped")).await;

    let response = post_consult_http(port, Some(&token), &body("invoice acme", 5)).await;
    assert_eq!(response["_http_status"], "200");
    assert_eq!(response["data"]["coverage"], "local_paperless_notes_keyword_lookup");
    assert_eq!(response["data"]["matches"].as_array().unwrap().len(), 1);
    let matched = &response["data"]["matches"][0];
    assert_eq!(matched.as_object().unwrap().len(), 3);
    assert!(matched.get("path").is_none());
    assert_eq!(matched["filename"], "acme.md");
    assert!(matched["excerpt"].as_str().unwrap().contains("ACME invoice"));
    assert!(matched["score"].is_u64());
    let serialized = response.to_string();
    assert!(!serialized.contains(vault.path().to_string_lossy().as_ref()));
    assert!(!serialized.contains(home.path().to_string_lossy().as_ref()));
    assert!(!serialized.contains("ambient.md"));
    assert!(!serialized.contains("private ambient marker"));

    stop_consult_http_test_server(state, writer, wal_join, server, shutdown).await;
}

#[tokio::test]
async fn consult_missing_configuration_returns_fixed_503() {
    let home = tempfile::tempdir().unwrap();
    let token = consult_token(home.path(), vec![api_tokens::SCOPE_PAPERLESS_CONSULT_READ.to_owned()]);
    let (state, writer, wal_join, server, shutdown, port) =
        start_consult_http_test_server(home.path(), FreedomConfig::default()).await;

    let response = post_consult_http(port, Some(&token), &body("invoice", 5)).await;
    assert_eq!(response["_http_status"], "503");
    assert_eq!(response["error"]["code"], "StoreUnavailable");
    assert_eq!(response["error"]["message"], "paperless_consult_vault_not_configured");
    assert!(!response.to_string().contains(home.path().to_string_lossy().as_ref()));

    stop_consult_http_test_server(state, writer, wal_join, server, shutdown).await;
}

#[tokio::test]
async fn consult_distinguishes_missing_directory_from_file_corrupt_and_oversized_store_failures() {
    let home = tempfile::tempdir().unwrap();
    let vault = tempfile::tempdir().unwrap();
    let token = consult_token(home.path(), vec![api_tokens::SCOPE_PAPERLESS_CONSULT_READ.to_owned()]);
    let (state, writer, wal_join, server, shutdown, port) =
        start_consult_http_test_server(home.path(), configured(vault.path(), "Scoped")).await;

    let empty = post_consult_http(port, Some(&token), &body("invoice", 5)).await;
    assert_eq!(empty["_http_status"], "200");
    assert_eq!(empty["data"]["matches"], serde_json::json!([]));
    let paperless = vault.path().join("Scoped").join("Paperless");
    std::fs::create_dir_all(paperless.parent().unwrap()).unwrap();
    std::fs::write(&paperless, b"not-a-directory").unwrap();
    let file_error = post_consult_http(port, Some(&token), &body("invoice", 5)).await;
    assert_eq!(file_error["_http_status"], "503");
    std::fs::remove_file(&paperless).unwrap();
    std::fs::create_dir(&paperless).unwrap();
    std::fs::write(paperless.join("corrupt.md"), [0xff, 0xfe]).unwrap();
    let corrupt_error = post_consult_http(port, Some(&token), &body("invoice", 5)).await;
    assert_eq!(corrupt_error["_http_status"], "503");
    std::fs::remove_file(paperless.join("corrupt.md")).unwrap();
    std::fs::write(paperless.join("oversized.md"), "x".repeat(256 * 1024 + 1)).unwrap();
    let oversized_error = post_consult_http(port, Some(&token), &body("invoice", 5)).await;
    assert_eq!(oversized_error["_http_status"], "503");
    for response in [file_error, corrupt_error, oversized_error] {
        assert_eq!(response["error"]["message"], "paperless_consult_unavailable_or_limit_exceeded");
        assert!(!response.to_string().contains(vault.path().to_string_lossy().as_ref()));
    }

    stop_consult_http_test_server(state, writer, wal_join, server, shutdown).await;
}
