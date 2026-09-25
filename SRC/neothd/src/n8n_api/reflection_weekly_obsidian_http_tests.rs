#![cfg(test)]

//! Loopback contract coverage for weekly reflection Obsidian synchronization.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use super::*;
use crate::config::FreedomConfig;
use crate::reflection::weekly_archive::{open_weekly_archive_session, WeeklyArchiveCandidate};
use crate::security::api_tokens;

const PATH: &str = "/api/reflections/weekly/obsidian/sync";
const WEEK: &str = "2026-W21";
const SUBDIR: &str = "ScopedWeekly";

struct Home {
    _root: crate::test_env::CanonicalTempDir,
    path: std::path::PathBuf,
}

impl Home {
    fn new() -> Self {
        let root = crate::test_env::canonical_tempdir().unwrap();
        #[cfg(unix)]
        let path = {
            use std::os::unix::fs::DirBuilderExt as _;
            let path = root.path().join("private-home");
            std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            path
        };
        #[cfg(windows)]
        let path = {
            let path = root.path().join("private-home");
            crate::wal::win_native::create_private_directory_new(&path).unwrap();
            path
        };
        Self { _root: root, path }
    }
    fn path(&self) -> &Path { &self.path }
}

async fn start(home: &Path, config: FreedomConfig) -> (Arc<ApiState>, crate::wal::writer::WalWriterHandle, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>, Arc<Notify>, u16) {
    let (writer, wal) = crate::wal::writer::spawn(home.join("weekly-http.wal")).unwrap();
    let state = Arc::new(ApiState {
        writer: writer.clone(), config: Arc::new(config.clone()),
        reload_controller: Arc::new(crate::config::reload::ReloadController::new(config, home.join("freedom.yaml"))),
        home: home.to_path_buf(), token: "weekly-master-token".into(), cooldown: Arc::new(AuthCooldown::new()), boot_instant: Instant::now(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown = Arc::new(Notify::new());
    let server = tokio::spawn(run_server(listener, Arc::clone(&state), Arc::clone(&shutdown)));
    (state, writer, wal, server, shutdown, port)
}

async fn stop(state: Arc<ApiState>, writer: crate::wal::writer::WalWriterHandle, wal: tokio::task::JoinHandle<()>, server: tokio::task::JoinHandle<()>, shutdown: Arc<Notify>) {
    shutdown.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(3), server).await.unwrap().unwrap();
    drop(state); drop(writer);
    tokio::time::timeout(std::time::Duration::from_secs(3), wal).await.unwrap().unwrap();
}

async fn post(port: u16, token: Option<&str>, body: &str) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
    let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
    let authorization = token.map(|token| format!("Authorization: Bearer {token}\r\n")).unwrap_or_default();
    let request = format!("POST {PATH} HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new(); stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap(); let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let mut json: serde_json::Value = serde_json::from_str(body).unwrap();
    json["_http_status"] = serde_json::Value::String(head.split_whitespace().nth(1).unwrap().into()); json
    }).await.expect("weekly reflection Obsidian HTTP exchange timed out")
}

fn token(home: &Path, scopes: Vec<String>) -> (String, String) {
    let (record, bearer) = api_tokens::create_token("weekly-http", scopes, None).unwrap();
    let id = record.id.clone(); api_tokens::save_store(home, &[record]).unwrap(); (id, bearer)
}

fn config(vault: &Path) -> FreedomConfig {
    FreedomConfig { obsidian_vault: Some(vault.to_string_lossy().into_owned()), obsidian_subdir: Some(SUBDIR.into()), ..FreedomConfig::default() }
}

fn request(week: &str) -> String { serde_json::json!({"week": week}).to_string() }
fn note(vault: &Path) -> std::path::PathBuf { vault.join(SUBDIR).join("Reflections").join(format!("{WEEK}.md")) }

fn persist_legacy_and_canonical(home: &Path) -> (crate::reflection::WeeklyReflection, crate::reflection::WeeklyReflection) {
    use crate::reflection::WeeklyReflection;
    let legacy = WeeklyReflection { iso_week_tag: WEEK.into(), generated_ts_unix: 1_700_000_000, topics: vec!["legacy".into()], body: "legacy private reflection".into(), tags: vec![], producer_key: None };
    std::fs::create_dir_all(home.join("reflections")).unwrap();
    std::fs::write(home.join("reflections").join(format!("{WEEK}.jsonl")), format!("{}\n", serde_json::to_string(&legacy).unwrap())).unwrap();
    let mut session = open_weekly_archive_session(home, WEEK).unwrap();
    let body = crate::reflection::build_reflection_item(WEEK, &["canonical".into()], 1_700_000_001).unwrap().body;
    let intent = session.load_or_create_intent(WeeklyArchiveCandidate { generated_ts_unix: 1_700_000_001, topics: vec!["canonical".into()], body }).unwrap();
    let canonical = intent.to_reflection(); session.append_once(&intent).unwrap(); (legacy, canonical)
}

fn audits(wal: &Path) -> Vec<serde_json::Value> {
    let bytes = std::fs::read(wal).unwrap(); let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap(); let mut offset = header.header_len(); let mut out = Vec::new();
    while offset < bytes.len() { let frame = crate::wal::frame::decode_frame(&bytes[offset..]).unwrap(); if frame.header.event_type == crate::wal::events::EVENT_TYPE_N8N_REQUEST { out.push(serde_json::from_slice(frame.payload).unwrap()); } offset += frame.header.total_len as usize; }
    out
}

#[tokio::test]
async fn weekly_scope_rejects_before_body_parse_or_vault_effect() {
    let home = Home::new(); let vault = Home::new();
    let (wrong_record, wrong) = api_tokens::create_token("weekly-wrong-scope", vec![api_tokens::SCOPE_RECALL_READ.into()], None).unwrap();
    let (dream_record, dream_scope) = api_tokens::create_token("weekly-dream-scope", vec![api_tokens::SCOPE_DREAMS_OBSIDIAN_WRITE.into()], None).unwrap();
    api_tokens::save_store(home.path(), &[wrong_record, dream_record]).unwrap();
    let (state, writer, wal, server, shutdown, port) = start(home.path(), config(vault.path())).await;
    let unauthenticated = post(port, None, "{bad-json").await;
    assert_eq!(unauthenticated["_http_status"], "401");
    let response = post(port, Some(&wrong), "{bad-json").await;
    assert_eq!(response["_http_status"], "403"); assert_eq!(response["error"]["code"], "PermissionDenied"); assert!(!vault.path().join(SUBDIR).exists());
    let dream_denied = post(port, Some(&dream_scope), "{bad-json").await;
    assert_eq!(dream_denied["_http_status"], "403"); assert_eq!(dream_denied["error"]["code"], "PermissionDenied");
    stop(state, writer, wal, server, shutdown).await;
}

#[tokio::test]
async fn weekly_strict_body_and_missing_vault_use_fixed_errors() {
    let home = Home::new(); let vault = Home::new(); let (_, bearer) = token(home.path(), vec![api_tokens::SCOPE_REFLECTIONS_WEEKLY_OBSIDIAN_WRITE.into()]);
    let (state, writer, wal, server, shutdown, port) = start(home.path(), config(vault.path())).await;
    for body in ["{bad-json", r#"{"week":"2026-W54"}"#, r#"{"week":"２０２６-W21"}"#, r#"{"week":"2026-W21","private_vault":"secret"}"#] { let response = post(port, Some(&bearer), body).await; assert_eq!(response["_http_status"], "400"); assert_eq!(response["error"]["message"], "reflection_weekly_obsidian_sync_request_invalid"); assert!(!response.to_string().contains("secret")); }
    stop(state, writer, wal, server, shutdown).await;
    let (state, writer, wal, server, shutdown, port) = start(home.path(), FreedomConfig::default()).await;
    let response = post(port, Some(&bearer), &request(WEEK)).await;
    assert_eq!(response["_http_status"], "503"); assert_eq!(response["error"]["message"], "reflection_weekly_obsidian_sync_vault_not_configured");
    stop(state, writer, wal, server, shutdown).await;
}

#[tokio::test]
async fn weekly_sync_works_with_dreaming_disabled_and_quiet_week_creates_no_target() {
    let home = Home::new(); let vault = Home::new(); let (_, bearer) = token(home.path(), vec![api_tokens::SCOPE_REFLECTIONS_WEEKLY_OBSIDIAN_WRITE.into()]);
    let (state, writer, wal, server, shutdown, port) = start(home.path(), config(vault.path())).await;
    let response = post(port, Some(&bearer), &request(WEEK)).await;
    assert_eq!(response["_http_status"], "200"); assert_eq!(response["data"]["written"], false); assert_eq!(response["data"]["durability"], "not_written"); assert!(!note(vault.path()).exists());
    stop(state, writer, wal, server, shutdown).await;
}

#[tokio::test]
async fn weekly_existing_legacy_and_canonical_archive_syncs_and_redacts_response_paths() {
    let home = Home::new(); let vault = Home::new(); let (legacy, canonical) = persist_legacy_and_canonical(home.path()); let (_, bearer) = token(home.path(), vec![api_tokens::SCOPE_REFLECTIONS_WEEKLY_OBSIDIAN_WRITE.into()]);
    let (state, writer, wal, server, shutdown, port) = start(home.path(), config(vault.path())).await;
    let response = post(port, Some(&bearer), &request(WEEK)).await;
    assert_eq!(response["_http_status"], "200"); assert_eq!(response["data"]["reflection_count"], 2); assert_eq!(response["data"]["written"], true); assert!(matches!(response["data"]["durability"].as_str(), Some("published_and_synced" | "published_durability_unknown")));
    let expected = format!("{}\n---\n\n{}", legacy.to_obsidian_md(), canonical.to_obsidian_md()); let rendered = std::fs::read_to_string(note(vault.path())).unwrap(); assert_eq!(rendered, expected); assert_eq!(response["data"]["bytes_written"], expected.len()); let encoded = response.to_string(); assert!(!encoded.contains(home.path().to_string_lossy().as_ref())); assert!(!encoded.contains(vault.path().to_string_lossy().as_ref()));
    stop(state, writer, wal, server, shutdown).await;
}

#[tokio::test]
async fn weekly_corrupt_source_fails_without_target_and_wal_uses_opaque_verified_caller() {
    let home = Home::new(); let vault = Home::new(); let (token_id, bearer) = token(home.path(), vec![api_tokens::SCOPE_REFLECTIONS_WEEKLY_OBSIDIAN_WRITE.into()]);
    std::fs::create_dir_all(home.path().join("reflections")).unwrap(); std::fs::write(home.path().join("reflections").join(format!("{WEEK}.jsonl")), b"{private corrupt source}\n").unwrap();
    let wal_path = home.path().join("weekly-http.wal"); let (state, writer, wal, server, shutdown, port) = start(home.path(), config(vault.path())).await;
    let response = post(port, Some(&bearer), &request(WEEK)).await; let request_id = response["request_id"].clone();
    assert_eq!(response["_http_status"], "503"); assert_eq!(response["error"]["message"], "reflection_weekly_obsidian_sync_failed"); assert!(!note(vault.path()).exists()); stop(state, writer, wal, server, shutdown).await;
    let receipts = audits(&wal_path).into_iter().filter(|value| value["kind"] == "n8n_reflection_weekly_obsidian_sync").collect::<Vec<_>>(); assert_eq!(receipts.len(), 2); assert!(receipts.iter().any(|value| value["phase"] == "admission")); assert!(receipts.iter().any(|value| value["phase"] == "failed")); for receipt in receipts { let encoded = receipt.to_string(); assert_eq!(receipt["request_id"], request_id); assert_eq!(receipt["accepted_epoch"], 0); assert_eq!(receipt["caller"]["kind"], "scoped_token"); assert_eq!(receipt["caller"]["token_id"], token_id); assert!(!encoded.contains(&bearer)); assert!(!encoded.contains("private corrupt source")); assert!(!encoded.contains(home.path().to_string_lossy().as_ref())); assert!(!encoded.contains(vault.path().to_string_lossy().as_ref())); }
}

#[tokio::test]
async fn weekly_retired_generation_rejects_before_sync() {
    let home = Home::new(); let vault = Home::new(); let (_, bearer) = token(home.path(), vec![api_tokens::SCOPE_REFLECTIONS_WEEKLY_OBSIDIAN_WRITE.into()]);
    let (state, writer, wal, server, shutdown, port) = start(home.path(), config(vault.path())).await;
    state.reload_controller.retire_generation_effect_runtime();
    let response = post(port, Some(&bearer), &request(WEEK)).await;
    assert_eq!(response["_http_status"], "403"); assert_eq!(response["error"]["message"], "reflection_weekly_obsidian_sync_generation_retired"); assert!(!note(vault.path()).exists());
    stop(state, writer, wal, server, shutdown).await;
}
