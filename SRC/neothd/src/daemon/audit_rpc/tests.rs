//! AUDIT-RPC-01 tests — exercise the public surface across all submodules
//! (token / sidecar / server / client) via the `mod.rs` re-exports.

use super::*;

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::n8n_api::auth::AuthCooldown;

async fn raw_post(addr: SocketAddr, token: Option<&str>, body: &str) -> u16 {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "POST /audit HTTP/1.1\r\nHost: x\r\n{auth}Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    resp.split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
}

#[test]
fn allowlist_contains_exactly_the_oneshot_codes() {
    assert_eq!(ALLOWED_CLIENT_EVENT_TYPES.len(), 32);
    // Autonomy-level changes (`neoth autonomy set`) + the lease/OS one-shots.
    for c in [0xA2u8, 0xA3] {
        assert!(
            is_allowed_client_event(c),
            "{c:#x} (autonomy) must be allowed"
        );
    }
    // EM-02b calendar external-write audits.
    for c in [0xCAu8, 0xCB] {
        assert!(
            is_allowed_client_event(c),
            "{c:#x} (calendar) must be allowed"
        );
    }
    // SR-017 / GOLD-SEC-30 consent grant/revoke marker audits.
    for c in [0xDBu8, 0xDC] {
        assert!(
            is_allowed_client_event(c),
            "{c:#x} (consent) must be allowed"
        );
    }
    for c in [0xDAu8, 0xDD] {
        assert!(
            is_allowed_client_event(c),
            "{c:#x} (preset/FULL-AUTO transaction) must be allowed"
        );
    }
    // GOLD-ADOPT-23 point 3 — `neoth risk-confirm` grant audit.
    assert!(
        is_allowed_client_event(0x54),
        "0x54 (risk_confirm_granted) must be allowed"
    );
    for c in 0xA5u8..=0xADu8 {
        assert!(is_allowed_client_event(c), "{c:#x} must be allowed");
    }
    // AUDIT-RPC-01 Commit-3 (Session 36): the remaining one-shot CLIs —
    // ingest (0x2C/0x2D), recall-score (0x3E), self-update (0xD2), and model
    // pull (0xD7/0xD8) — now forward instead of silently skipping when a
    // daemon owns the WAL.
    for c in [
        0x2Cu8, 0x2D, 0x30, 0x31, 0x3D, 0x3E, 0x9B, 0xC8, 0xD2, 0xD7, 0xD8, 0xD9, 0xF5,
    ] {
        assert!(
            is_allowed_client_event(c),
            "{c:#x} (one-shot) must be allowed"
        );
    }
    // recon (`neoth recon uncover/tlsx`) forwards its RECON_RUN audit.
    assert!(
        is_allowed_client_event(0xF6),
        "0xF6 (recon_run) must be allowed"
    );
    // Daemon-lifecycle / cluster / quota codes are NOT forwardable — and the
    // autonomy codes must NOT bleed into the neighbouring 0xA0/0xA1/0xA4.
    for c in [0x10u8, 0x15, 0xA0, 0xA1, 0xA4, 0xAE, 0xAF, 0xE0, 0xF0] {
        assert!(!is_allowed_client_event(c), "{c:#x} must be refused");
    }

    let proof_rotation = crate::wal::events::ExtendedSubtype::ProofKeyRotated as u8;
    let http_intent = crate::wal::events::ExtendedSubtype::ExternalHttpIntent as u8;
    let http_result = crate::wal::events::ExtendedSubtype::ExternalHttpResult as u8;
    let communication_controlled =
        crate::wal::events::ExtendedSubtype::CommunicationProfileControlled as u8;
    let self_edit_proposed = crate::wal::events::ExtendedSubtype::SelfEditProposed as u8;
    assert_eq!(
        ALLOWED_CLIENT_EXTENDED_SUBTYPES,
        &[
            proof_rotation,
            http_intent,
            http_result,
            communication_controlled,
        ]
    );
    assert!(is_allowed_client_event_pair(0x00, proof_rotation));
    assert!(is_allowed_client_event_pair(0x00, communication_controlled));
    assert!(!is_allowed_client_event_pair(0x00, 0));
    assert!(!is_allowed_client_event_pair(0x00, self_edit_proposed));
    assert!(is_allowed_client_event_pair(0xA8, 0));
    assert!(
        !is_allowed_client_event_pair(0xA8, proof_rotation),
        "a non-zero subtype on an allowed top-level code must be rejected"
    );
}

#[test]
fn is_reachable_is_false_without_a_sidecar() {
    let dir = tempdir().unwrap();
    assert!(!is_reachable(dir.path()), "no sidecar ⇒ not reachable");
}

#[test]
fn enforce_required_audit_only_bails_when_required_live_and_unreachable() {
    let dir = tempdir().unwrap(); // no sidecar ⇒ unreachable
    // Flag off ⇒ always Ok (best-effort posture).
    assert!(enforce_required_audit(false, true, dir.path()).is_ok());
    // No daemon ⇒ Ok (the one-shot writes its own frame locally).
    assert!(enforce_required_audit(true, false, dir.path()).is_ok());
    // Required + daemon live + listener unreachable ⇒ fail-closed.
    assert!(enforce_required_audit(true, true, dir.path()).is_err());
}

#[test]
fn token_round_trips_through_secure_write() {
    let dir = tempdir().unwrap();
    let t = init_rpc_token(dir.path()).unwrap();
    assert_eq!(t.len(), 43);
    assert_eq!(read_rpc_token(dir.path()).unwrap(), t);
}

#[test]
fn sidecar_round_trips_port_without_full_token() {
    let dir = tempdir().unwrap();
    write_sidecar(dir.path(), 54321, std::process::id(), "supersecrettoken").unwrap();
    assert_eq!(read_sidecar(dir.path()).unwrap().0, 54321);
    // The full token must NEVER be in the sidecar — only an 8-char hint.
    let raw = std::fs::read(sidecar_path(dir.path())).unwrap();
    let body = crate::wal::compaction::maybe_unwrap_dpapi(&raw, &sidecar_path(dir.path())).unwrap();
    let s = String::from_utf8_lossy(&body);
    assert!(s.contains("supersec"));
    assert!(!s.contains("supersecrettoken"));
}

#[test]
fn sidecar_guard_removes_on_drop() {
    let dir = tempdir().unwrap();
    let t = init_rpc_token(dir.path()).unwrap();
    write_sidecar(dir.path(), 1, std::process::id(), &t).unwrap();
    {
        let _g = SidecarGuard::new(dir.path().to_path_buf());
        assert!(sidecar_path(dir.path()).exists());
    }
    assert!(!sidecar_path(dir.path()).exists());
    assert!(!rpc_token_path(dir.path()).exists());
}

#[tokio::test]
async fn valid_token_appends_allowed_frame_and_emits_accept() {
    use crate::wal::events::EVENT_TYPE_OS_APP_LAUNCH;
    let segdir = tempdir().unwrap();
    let seg = segdir.path().join("000001.wal");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), segdir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "tok-valid".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
    };
    let (addr, task) = bind_and_serve(state).await.unwrap();

    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(br#"{"program":"/bin/x"}"#);
    let body =
        format!("{{\"event_type\":{EVENT_TYPE_OS_APP_LAUNCH},\"payload_b64\":{payload_b64:?}}}");
    let status = raw_post(addr, Some("tok-valid"), &body).await;
    assert_eq!(status, 200);

    task.abort();
    drop(writer);
    wal_join.await.ok();

    // The forwarded 0xAC frame AND the 0xAE accept frame both landed.
    let bytes = tokio::fs::read(&seg).await.unwrap();
    let mut types = Vec::new();
    let mut cur = crate::wal::segment_header::SEGMENT_HEADER_LEN;
    while cur < bytes.len() {
        let Ok(f) = crate::wal::frame::decode_frame(&bytes[cur..]) else {
            break;
        };
        types.push(f.header.event_type);
        cur = cur.saturating_add(f.header.total_len as usize);
    }
    assert!(
        types.contains(&EVENT_TYPE_OS_APP_LAUNCH),
        "forwarded frame landed"
    );
    assert!(
        types.contains(&crate::wal::events::EVENT_TYPE_AUDIT_RPC_ACCEPT),
        "accept marker landed"
    );
}

#[tokio::test]
async fn subtype_allowlist_accepts_only_the_exact_extended_identity() {
    let segdir = tempdir().unwrap();
    let seg = segdir.path().join("000001.wal");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), segdir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "tok-subtype".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
    };
    let (addr, task) = bind_and_serve(state).await.unwrap();
    let subtype = crate::wal::events::ExtendedSubtype::ProofKeyRotated as u8;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(b"{}");

    let accepted =
        format!("{{\"event_type\":0,\"event_subtype\":{subtype},\"payload_b64\":{payload_b64:?}}}");
    assert_eq!(raw_post(addr, Some("tok-subtype"), &accepted).await, 200);

    let extended_zero =
        format!("{{\"event_type\":0,\"event_subtype\":0,\"payload_b64\":{payload_b64:?}}}");
    assert_eq!(
        raw_post(addr, Some("tok-subtype"), &extended_zero).await,
        422
    );

    let top_level_with_subtype = format!(
        "{{\"event_type\":168,\"event_subtype\":{subtype},\"payload_b64\":{payload_b64:?}}}"
    );
    assert_eq!(
        raw_post(addr, Some("tok-subtype"), &top_level_with_subtype).await,
        422
    );

    task.abort();
    drop(writer);
    wal_join.await.ok();
    let bytes = tokio::fs::read(&seg).await.unwrap();
    let frame =
        crate::wal::frame::decode_frame(&bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..])
            .unwrap();
    assert_eq!(frame.header.event_type, 0x00);
    assert_eq!(frame.header.event_subtype, subtype);
}

#[tokio::test]
async fn wrong_token_is_401_and_writes_no_frame() {
    let segdir = tempdir().unwrap();
    let seg = segdir.path().join("000001.wal");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), segdir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "tok-valid".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
    };
    let (addr, task) = bind_and_serve(state).await.unwrap();
    let body = r#"{"event_type":168,"payload_b64":"e30="}"#;
    let status = raw_post(addr, Some("tok-WRONG"), body).await;
    assert_eq!(status, 401);
    // missing token too
    assert_eq!(raw_post(addr, None, body).await, 401);
    task.abort();
    drop(writer);
    wal_join.await.ok();
    // No frame written (auth failures are not audited).
    let bytes = tokio::fs::read(&seg).await.unwrap();
    assert!(
        crate::wal::frame::decode_frame(&bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..])
            .is_err()
    );
}

#[tokio::test]
async fn blocked_event_type_is_422_and_emits_reject() {
    use crate::wal::events::EVENT_TYPE_AUDIT_RPC_REJECT;
    let segdir = tempdir().unwrap();
    let seg = segdir.path().join("000001.wal");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), segdir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "tok".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
    };
    let (addr, task) = bind_and_serve(state).await.unwrap();
    // 0x10 (daemon lifecycle) is NOT forwardable.
    let body = r#"{"event_type":16,"payload_b64":"e30="}"#;
    let status = raw_post(addr, Some("tok"), body).await;
    assert_eq!(status, 422);
    task.abort();
    drop(writer);
    wal_join.await.ok();
    let bytes = tokio::fs::read(&seg).await.unwrap();
    let f =
        crate::wal::frame::decode_frame(&bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..])
            .unwrap();
    assert_eq!(f.header.event_type, EVENT_TYPE_AUDIT_RPC_REJECT);
}

#[tokio::test]
async fn client_round_trips_against_a_live_listener() {
    use crate::wal::events::EVENT_TYPE_OS_FILE_READ;
    let home = tempdir().unwrap();
    let seg_dir = tempdir().unwrap();
    let seg = seg_dir.path().join("000001.wal");
    let token = init_rpc_token(home.path()).unwrap();
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), seg_dir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: token.clone(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
    };
    let (addr, task) = bind_and_serve(state).await.unwrap();
    // The test process is alive, so the client's pid-liveness check passes.
    write_sidecar(home.path(), addr.port(), std::process::id(), &token).unwrap();

    // The CLIENT path: read sidecar+token, connect, POST.
    try_post_audit_frame(
        home.path(),
        EVENT_TYPE_OS_FILE_READ,
        br#"{"path":"/etc/hosts","bytes":42}"#,
    )
    .await
    .expect("client round-trip must succeed end-to-end");

    task.abort();
    drop(writer);
    wal_join.await.ok();
    let bytes = tokio::fs::read(&seg).await.unwrap();
    let f =
        crate::wal::frame::decode_frame(&bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..])
            .unwrap();
    assert_eq!(f.header.event_type, EVENT_TYPE_OS_FILE_READ);
}

#[tokio::test]
async fn subtype_client_round_trips_against_a_live_listener() {
    let home = tempdir().unwrap();
    let seg_dir = tempdir().unwrap();
    let seg = seg_dir.path().join("000001.wal");
    let token = init_rpc_token(home.path()).unwrap();
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), seg_dir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: token.clone(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
    };
    let (addr, task) = bind_and_serve(state).await.unwrap();
    write_sidecar(home.path(), addr.port(), std::process::id(), &token).unwrap();
    let subtype = crate::wal::events::ExtendedSubtype::ProofKeyRotated as u8;

    try_post_audit_frame_with_subtype(home.path(), 0x00, subtype, b"{}")
        .await
        .expect("subtype-aware client round-trip must succeed");

    task.abort();
    drop(writer);
    wal_join.await.ok();
    let bytes = tokio::fs::read(&seg).await.unwrap();
    let frame =
        crate::wal::frame::decode_frame(&bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..])
            .unwrap();
    assert_eq!(frame.header.event_type, 0x00);
    assert_eq!(frame.header.event_subtype, subtype);
}

#[tokio::test]
async fn client_unavailable_when_no_sidecar() {
    let home = tempdir().unwrap();
    let r = try_post_audit_frame(home.path(), 0xA8, b"{}").await;
    assert!(matches!(r, Err(AuditRpcClientError::Unavailable(_))));
}

#[tokio::test]
async fn client_rejects_stale_sidecar_with_dead_pid() {
    // A sidecar left by a crashed daemon (dead pid) must NOT be trusted —
    // the recycled port could belong to an unrelated process, and sending
    // the bearer token there would disclose it.
    let home = tempdir().unwrap();
    init_rpc_token(home.path()).unwrap();
    // 999_999_999 is above any OS pid_max (and stays positive as an i32
    // pid_t, so the unix `kill(pid,0)` check can't alias to the -1
    // "whole process group" sentinel) — reliably a dead pid on all OSes.
    write_sidecar(home.path(), 5000, 999_999_999, "tok").unwrap();
    let r = try_post_audit_frame(home.path(), 0xA8, b"{}").await;
    assert!(
        matches!(r, Err(AuditRpcClientError::Unavailable(ref m)) if m.contains("stale")),
        "a dead-pid sidecar must be refused as stale, got {r:?}"
    );
}
