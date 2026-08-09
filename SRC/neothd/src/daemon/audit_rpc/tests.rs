//! AUDIT-RPC-01 tests — exercise the public surface across all submodules
//! (token / sidecar / server / client) via the `mod.rs` re-exports.

use super::*;

use std::sync::Arc;

use base64::Engine;
use sha2::Digest as _;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::n8n_api::auth::AuthCooldown;

fn test_endpoint_nonce() -> String {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .expect("OS CSPRNG must generate the audit-RPC test endpoint nonce");
    hex::encode(nonce)
}

fn canonical_test_wal(home: &std::path::Path, namespace: &str) -> std::path::PathBuf {
    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir).unwrap();
    wal_dir.join(format!("{namespace}-000001.wal"))
}

fn publish_test_endpoint(
    home: &std::path::Path,
    endpoint: &AuditEndpointV2,
    endpoint_nonce: &str,
) -> crate::daemon::pidfile::PidGuard {
    let mut guard = crate::daemon::pidfile::acquire(&home.join("neothd.pid")).unwrap();
    write_sidecar(home, endpoint, std::process::id(), endpoint_nonce).unwrap();
    guard.publish_endpoint_nonce(endpoint_nonce).unwrap();
    guard
}

async fn raw_post(addr: &AuditEndpointV2, token: Option<&str>, body: &str) -> u16 {
    raw_post_path(addr, "/audit", token, body).await.0
}

async fn raw_post_path(
    addr: &AuditEndpointV2,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> (u16, String) {
    let mut s = super::transport::connect(addr).await.unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\n{auth}Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let status = resp
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    let response_body = resp
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, response_body)
}

async fn recv_runtime_transition_for_home(
    subscriber: &mut crate::skills::registry::RuntimeAuthorityTransitionTestSubscriber,
    home: &std::path::Path,
) -> crate::skills::registry::RuntimeAuthorityTransitionKind {
    let expected_home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let (observed_home, kind) = subscriber.recv().await.unwrap();
            if observed_home == expected_home {
                return kind;
            }
        }
    })
    .await
    .expect("runtime authority transition was not emitted after durable ACK")
}

#[test]
fn allowlist_contains_exactly_the_oneshot_codes() {
    assert_eq!(ALLOWED_CLIENT_EVENT_TYPES.len(), 40);
    let mut unique_event_types = ALLOWED_CLIENT_EVENT_TYPES.to_vec();
    unique_event_types.sort_unstable();
    unique_event_types.dedup();
    assert_eq!(
        unique_event_types.len(),
        ALLOWED_CLIENT_EVENT_TYPES.len(),
        "the compile-time audit-RPC allowlist must not contain duplicate codes"
    );
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
    // Interactive decision + SR-017 / GOLD-SEC-30 grant/revoke audits.
    for c in [0x65u8, 0xDB, 0xDC] {
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
    for c in [0xA0u8, 0xA1] {
        assert!(
            is_allowed_client_event(c),
            "{c:#x} (one-shot permission decision) must be allowed"
        );
    }
    // GOLD-ADOPT-23 point 3 — `neoth risk-confirm` grant audit.
    assert!(
        is_allowed_client_event(0x54),
        "0x54 (risk_confirm_granted) must be allowed"
    );
    assert!(
        is_allowed_client_event(0xBB),
        "0xBB (operator_feedback) must be allowed"
    );
    for c in [0x8Eu8, 0x8F] {
        assert!(
            is_allowed_client_event(c),
            "{c:#x} (PTY session lifecycle) must be allowed"
        );
    }
    for c in 0xA5u8..=0xADu8 {
        assert!(is_allowed_client_event(c), "{c:#x} must be allowed");
    }
    // AUDIT-RPC-01 Commit-3 (Session 36): the remaining one-shot CLIs —
    // ingest (0x2C/0x2D), recall-score (0x3E), self-update (0xD2), and model
    // pull (0xD7/0xD8) — now forward instead of silently skipping when a
    // daemon owns the WAL.
    for c in [
        0x2Cu8, 0x2D, 0x30, 0x31, 0x3D, 0x3E, 0x9B, 0xC8, 0xD2, 0xD7, 0xD8, 0xD9, 0xDE, 0xF5,
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
    assert!(
        is_allowed_client_event(0xFE),
        "0xFE (loyal_buddy_activated) must be allowed"
    );
    // Daemon-lifecycle / cluster / quota codes are NOT forwardable — and the
    // autonomy codes must NOT bleed into the neighbouring 0xA4.
    for c in [0x10u8, 0x15, 0xA4, 0xAE, 0xAF, 0xE0, 0xF0] {
        assert!(!is_allowed_client_event(c), "{c:#x} must be refused");
    }

    let proof_rotation = crate::wal::events::ExtendedSubtype::ProofKeyRotated as u8;
    let http_intent = crate::wal::events::ExtendedSubtype::ExternalHttpIntent as u8;
    let http_result = crate::wal::events::ExtendedSubtype::ExternalHttpResult as u8;
    let communication_controlled =
        crate::wal::events::ExtendedSubtype::CommunicationProfileControlled as u8;
    let self_edit_proposed = crate::wal::events::ExtendedSubtype::SelfEditProposed as u8;
    let plugin_removal_intent = crate::wal::events::ExtendedSubtype::PluginRemovalIntent as u8;
    let plugin_removal_result = crate::wal::events::ExtendedSubtype::PluginRemovalResult as u8;
    let skill_install_intent = crate::wal::events::ExtendedSubtype::SkillInstallIntent as u8;
    let skill_install_result = crate::wal::events::ExtendedSubtype::SkillInstallResult as u8;
    let skill_removal_intent = crate::wal::events::ExtendedSubtype::SkillRemovalIntent as u8;
    let skill_removal_result = crate::wal::events::ExtendedSubtype::SkillRemovalResult as u8;
    let skill_authority_decision =
        crate::wal::events::ExtendedSubtype::SkillAuthorityDecision as u8;
    // GOLD-LF-P1-01 — os_tools::gate reaches the WAL over this RPC route via
    // AuditSink::DaemonRpc, so its intent/result pairs are admitted. The
    // channel and media pairs are deliberately NOT here: they hold an
    // in-process WalWriterHandle, and admitting a subtype with no client
    // caller would widen the accepted surface for nothing.
    let os_file_write_intent = crate::wal::events::ExtendedSubtype::OsFileWriteIntent as u8;
    let os_file_write_result = crate::wal::events::ExtendedSubtype::OsFileWriteResult as u8;
    let os_app_launch_intent = crate::wal::events::ExtendedSubtype::OsAppLaunchIntent as u8;
    let os_app_launch_result = crate::wal::events::ExtendedSubtype::OsAppLaunchResult as u8;
    assert_eq!(
        ALLOWED_CLIENT_EXTENDED_SUBTYPES,
        &[
            proof_rotation,
            http_intent,
            http_result,
            communication_controlled,
            plugin_removal_intent,
            plugin_removal_result,
            skill_install_intent,
            skill_install_result,
            skill_removal_intent,
            skill_removal_result,
            skill_authority_decision,
            os_file_write_intent,
            os_file_write_result,
            os_app_launch_intent,
            os_app_launch_result,
        ]
    );
    assert!(is_allowed_client_event_pair(0x00, plugin_removal_intent));
    assert!(is_allowed_client_event_pair(0x00, plugin_removal_result));
    assert!(is_allowed_client_event_pair(0x00, skill_install_intent));
    assert!(is_allowed_client_event_pair(0x00, skill_install_result));
    assert!(is_allowed_client_event_pair(0x00, skill_removal_intent));
    assert!(is_allowed_client_event_pair(0x00, skill_removal_result));
    assert!(is_allowed_client_event_pair(0x00, skill_authority_decision));
    assert!(is_allowed_client_event_pair(0x00, proof_rotation));
    assert!(is_allowed_client_event_pair(0x00, communication_controlled));
    assert!(is_allowed_client_event_pair(0x00, os_file_write_intent));
    assert!(is_allowed_client_event_pair(0x00, os_file_write_result));
    assert!(is_allowed_client_event_pair(0x00, os_app_launch_intent));
    assert!(is_allowed_client_event_pair(0x00, os_app_launch_result));
    // The pairs with no client caller must stay OUT — this is the half of the
    // contract that actually bounds the surface.
    assert!(!is_allowed_client_event_pair(
        0x00,
        crate::wal::events::ExtendedSubtype::ChannelEgressIntent as u8
    ));
    assert!(!is_allowed_client_event_pair(
        0x00,
        crate::wal::events::ExtendedSubtype::MediaCallIntent as u8
    ));
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
fn sidecar_round_trips_typed_endpoint_without_bearer_material() {
    let dir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let endpoint = super::transport::endpoint_for_home(dir.path(), &endpoint_nonce).unwrap();
    write_sidecar(dir.path(), &endpoint, std::process::id(), &endpoint_nonce).unwrap();
    let record = read_sidecar(dir.path()).unwrap();
    assert_eq!(record.endpoint, endpoint);
    assert_eq!(record.pid, std::process::id());
    assert_eq!(record.endpoint_nonce, endpoint_nonce);
    let raw = std::fs::read(sidecar_path(dir.path())).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("supersecrettoken"));
}

#[test]
fn sidecar_guard_removes_on_drop() {
    let dir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    init_rpc_token(dir.path()).unwrap();
    let endpoint = super::transport::endpoint_for_home(dir.path(), &endpoint_nonce).unwrap();
    write_sidecar(dir.path(), &endpoint, std::process::id(), &endpoint_nonce).unwrap();
    {
        let _g = SidecarGuard::new(dir.path().to_path_buf());
        assert!(sidecar_path(dir.path()).exists());
    }
    assert!(!sidecar_path(dir.path()).exists());
    assert!(!rpc_token_path(dir.path()).exists());
}

#[tokio::test]
async fn daemon_sidecar_guard_aborts_its_published_listener_on_early_return() {
    let dir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    init_rpc_token(dir.path()).unwrap();
    let endpoint = super::transport::endpoint_for_home(dir.path(), &endpoint_nonce).unwrap();
    write_sidecar(dir.path(), &endpoint, std::process::id(), &endpoint_nonce).unwrap();
    let task = tokio::spawn(std::future::pending::<()>());
    let guard = SidecarGuard::with_listener(dir.path().to_path_buf(), task.abort_handle());
    drop(guard);
    let error = task
        .await
        .expect_err("listener must be aborted with discovery");
    assert!(error.is_cancelled());
    assert!(!sidecar_path(dir.path()).exists());
    assert!(!rpc_token_path(dir.path()).exists());
}

#[tokio::test]
async fn aborting_listener_aborts_idle_connection_before_wal_drain() {
    let segdir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(segdir.path(), "audit-idle-shutdown");
    let (writer, wal_join) = crate::wal::spawn_for_home(seg, segdir.path().to_path_buf()).unwrap();
    let cooldown = Arc::new(AuthCooldown::new());
    let state = AuditRpcState {
        token: "idle-test".into(),
        writer: writer.clone(),
        cooldown: Arc::clone(&cooldown),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(segdir.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    let mut idle = super::transport::connect(&addr).await.unwrap();
    idle.write_all(b"P").await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while Arc::strong_count(&cooldown) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("audit-RPC never accepted the idle connection");

    task.abort();
    let _ = task.await;
    drop(writer);
    tokio::time::timeout(std::time::Duration::from_secs(3), wal_join)
        .await
        .expect("idle audit-RPC connection retained its WAL sender")
        .expect("WAL writer task panicked");

    drop(idle);
}

#[tokio::test]
async fn valid_token_appends_allowed_frame_and_emits_accept() {
    use crate::wal::events::EVENT_TYPE_OS_APP_LAUNCH;
    let segdir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(segdir.path(), "audit-valid");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), segdir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "tok-valid".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(segdir.path(), &endpoint_nonce, state)
        .await
        .unwrap();

    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(br#"{"program":"/bin/x"}"#);
    let body =
        format!("{{\"event_type\":{EVENT_TYPE_OS_APP_LAUNCH},\"payload_b64\":{payload_b64:?}}}");
    let status = raw_post(&addr, Some("tok-valid"), &body).await;
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

#[cfg(feature = "cluster")]
#[tokio::test]
async fn membership_invite_confirm_revoke_and_status_are_typed_and_authenticated() {
    use crate::cluster::membership::{
        BootId, CarrierKind, EnrollmentInvite, EnrollmentReceipt, LocalNodeIdentity,
        MembershipConfirmRequest, MembershipController, MembershipInviteRequest,
        MembershipRevokeBinding, MembershipRevokeRequest, MembershipState, MembershipStore,
        RevocationIntentState, RevocationIntentStatus, RevokeReceipt, TransportIdentity,
    };

    let home = tempdir().unwrap();
    let peer_home = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(home.path(), "audit-membership-rpc");
    let (writer, wal_join) = crate::wal::spawn_for_home(seg, home.path().to_path_buf()).unwrap();
    let store = MembershipStore::open(home.path()).unwrap();
    let controller = Arc::new(MembershipController::with_audit_writer(
        store.clone(),
        Arc::new(crate::cluster::membership::LiveSessionRegistry::new()),
        writer.clone(),
    ));
    let state = AuditRpcState {
        token: "membership-token".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        membership: Some(Arc::clone(&controller)),
        audit_routes_enabled: false,
    };
    let (addr, task) = bind_and_serve(home.path(), &endpoint_nonce, state)
        .await
        .unwrap();

    let identity = LocalNodeIdentity::load_or_create(peer_home.path()).unwrap();
    let transport = TransportIdentity::parse("ab".repeat(32)).unwrap();
    let now = crate::time::now_unix_i64();
    let invite_request = MembershipInviteRequest {
        stable_node_id: identity.stable_node_id().clone(),
        signing_public_key_hex: hex::encode(identity.verifying_key().to_bytes()),
        carrier: CarrierKind::Peeroxide,
        transport_identity: transport.clone(),
        endpoint: "127.0.0.1:31337".into(),
        label: "rpc-peer".into(),
        expires_at_unix: now + 120,
    };
    let invite_body = serde_json::to_string(&invite_request).unwrap();
    assert_eq!(
        raw_post_path(&addr, "/membership/invite", None, &invite_body)
            .await
            .0,
        401
    );
    assert_eq!(
        rusqlite::Connection::open(store.path())
            .unwrap()
            .query_row("SELECT COUNT(*) FROM enrollment_invites", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap(),
        0,
        "unauthenticated invite must not mutate the authority"
    );

    let (status, body) = raw_post_path(
        &addr,
        "/membership/invite",
        Some("membership-token"),
        &invite_body,
    )
    .await;
    assert_eq!(status, 200);
    let invite: EnrollmentInvite = serde_json::from_str(&body).expect("typed invite response");
    let attestation = identity
        .attest_endpoint(
            CarrierKind::Peeroxide,
            transport.clone(),
            BootId::new(),
            "rpc-runtime".into(),
            "127.0.0.1:31337".into(),
            invite.auth_epoch,
            invite.issued_at_membership_epoch,
            Some(invite.invitation_digest.clone()),
            now + 60,
        )
        .unwrap();
    let confirm_body = serde_json::to_string(&MembershipConfirmRequest {
        invite_id: invite.invite_id.clone(),
        attestation,
        carrier: CarrierKind::Peeroxide,
        authenticated_transport: transport,
        endpoint: "127.0.0.1:31337".into(),
    })
    .unwrap();
    assert_eq!(
        raw_post_path(&addr, "/membership/confirm", Some("wrong"), &confirm_body)
            .await
            .0,
        401
    );
    let pending = store.snapshot().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].state,
        MembershipState::Pending,
        "unauthenticated confirm must not activate membership"
    );

    let (status, body) = raw_post_path(
        &addr,
        "/membership/confirm",
        Some("membership-token"),
        &confirm_body,
    )
    .await;
    assert_eq!(status, 200);
    let receipt: EnrollmentReceipt =
        serde_json::from_str(&body).expect("typed enrollment receipt response");
    assert_eq!(receipt.stable_node_id, *identity.stable_node_id());
    assert_eq!(
        receipt.issued_at_membership_epoch,
        invite.issued_at_membership_epoch
    );
    assert_eq!(
        receipt.committed_membership_epoch,
        invite.issued_at_membership_epoch
    );
    assert_eq!(store.snapshot().unwrap()[0].state, MembershipState::Active);

    let envelope = controller.snapshot().unwrap().into_envelope().unwrap();
    let member = envelope.snapshot.members.first().unwrap();
    let request_id = crate::cluster::membership::new_revocation_request_id();
    let revoke_body = serde_json::to_string(&MembershipRevokeRequest {
        binding: MembershipRevokeBinding {
            request_id: request_id.clone(),
            stable_node_id: member.stable_node_id.clone(),
            reason: "operator_rpc".into(),
            source: "operator_rpc_test".into(),
            snapshot_version: envelope.snapshot_version,
            snapshot_digest: envelope.snapshot_digest.clone(),
            authority_epoch: envelope.snapshot.authority_epoch,
            member_auth_epoch: member.auth_epoch,
            member_membership_epoch: member.membership_epoch,
        },
    })
    .unwrap();
    assert_eq!(
        raw_post_path(&addr, "/membership/revoke", None, &revoke_body)
            .await
            .0,
        401
    );
    let (status, body) = raw_post_path(
        &addr,
        "/membership/revoke",
        Some("membership-token"),
        &revoke_body,
    )
    .await;
    assert_eq!(status, 200);
    let revoke: RevokeReceipt =
        serde_json::from_str(&body).expect("typed revocation receipt response");
    assert_eq!(revoke.request_id, request_id);
    assert_eq!(revoke.intent_state, RevocationIntentState::Completed);
    assert!(revoke.tombstone_committed);

    let status_body = serde_json::json!({"request_id": request_id}).to_string();
    let (status, body) = raw_post_path(
        &addr,
        "/membership/revoke/status",
        Some("membership-token"),
        &status_body,
    )
    .await;
    assert_eq!(status, 200);
    let persisted: Option<RevocationIntentStatus> =
        serde_json::from_str(&body).expect("typed revocation status response");
    let persisted = persisted.expect("completed revocation status");
    assert_eq!(persisted.state, RevocationIntentState::Completed);
    assert_eq!(
        persisted.receipt_id.as_deref(),
        Some(revoke.receipt_id.as_str())
    );

    let (status, body) = raw_post_path(
        &addr,
        "/membership/revoke",
        Some("membership-token"),
        &revoke_body,
    )
    .await;
    assert_eq!(status, 200);
    let retry: RevokeReceipt =
        serde_json::from_str(&body).expect("typed retry revocation receipt response");
    assert!(retry.already_revoked);
    assert_eq!(retry.receipt_id, revoke.receipt_id);

    task.abort();
    drop(controller);
    drop(writer);
    wal_join.await.ok();
}

#[tokio::test]
async fn subtype_allowlist_accepts_only_the_exact_extended_identity() {
    let segdir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(segdir.path(), "audit-subtype");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), segdir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "tok-subtype".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(segdir.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    let subtype = crate::wal::events::ExtendedSubtype::ProofKeyRotated as u8;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(b"{}");

    let accepted =
        format!("{{\"event_type\":0,\"event_subtype\":{subtype},\"payload_b64\":{payload_b64:?}}}");
    assert_eq!(raw_post(&addr, Some("tok-subtype"), &accepted).await, 200);

    let extended_zero =
        format!("{{\"event_type\":0,\"event_subtype\":0,\"payload_b64\":{payload_b64:?}}}");
    assert_eq!(
        raw_post(&addr, Some("tok-subtype"), &extended_zero).await,
        422
    );

    let top_level_with_subtype = format!(
        "{{\"event_type\":168,\"event_subtype\":{subtype},\"payload_b64\":{payload_b64:?}}}"
    );
    assert_eq!(
        raw_post(&addr, Some("tok-subtype"), &top_level_with_subtype).await,
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
async fn internal_skill_mutation_route_stays_live_when_public_audit_routes_are_disabled() {
    let home = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let source = home.path().join("incoming-internal-route");
    let skills_dir = home.path().join("skills");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("skill.yaml"),
        "id: internal_route\n\
         description: Mandatory internal audit route\n\
         trigger_keywords: [internal]\n\
         system_prompt: Exercise the daemon-owned lifecycle.\n",
    )
    .unwrap();

    let wal = home.path().join("wal");
    std::fs::create_dir_all(&wal).unwrap();
    let segment = wal.join("000001.wal");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(segment, home.path().to_path_buf()).unwrap();
    let token = init_rpc_token(home.path()).unwrap();
    let state = AuditRpcState {
        token: token.clone(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: false,
    };
    let (addr, task) = bind_and_serve(home.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    let _pid_guard = publish_test_endpoint(home.path(), &addr, &endpoint_nonce);

    assert_eq!(
        raw_post_path(&addr, "/health", Some(&token), "{}").await.0,
        200,
        "authenticated endpoint discovery must remain available"
    );
    assert_eq!(
        raw_post_path(&addr, "/audit", Some(&token), "{}").await.0,
        404,
        "the operator-disabled public audit route must stay disabled"
    );

    let mut prepared = crate::skills::installer::prepare_install_from_local_with_expectation(
        &source,
        &skills_dir,
        false,
        None,
        "a17e0000a17e0000a17e0000a17e0000",
    )
    .unwrap();
    prepared.mark_intent_submitting().unwrap();
    let intent = crate::skills::mutation_lifecycle::deliver_intent(
        home.path(),
        None,
        &prepared.audit_binding(),
    )
    .await
    .unwrap();
    let crate::skills::mutation_lifecycle::IntentDelivery::Durable(receipt) = intent else {
        panic!("mandatory internal route must durably deliver the exact intent");
    };
    prepared.mark_intent_durable_authenticated(receipt).unwrap();
    prepared.commit().unwrap();
    crate::skills::mutation_lifecycle::reconcile_pending(home.path(), &skills_dir, None)
        .await
        .unwrap();

    assert!(skills_dir.join("internal_route/skill.yaml").is_file());
    assert!(!skills_dir.join(".neoth-skill-mutation.json").exists());

    task.abort();
    drop(writer);
    wal_join.await.ok();
}

#[tokio::test]
async fn skill_mutation_audit_id_is_idempotent_and_conflicts_fail_closed() {
    let segdir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let mut transitions =
        crate::skills::registry::subscribe_runtime_authority_transitions_for_test();
    let seg = canonical_test_wal(segdir.path(), "audit-skill-dedup");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), segdir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "skill-dedup-token".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(segdir.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    let subtype = crate::wal::events::ExtendedSubtype::SkillInstallResult as u8;
    let operation_id = "deadbeefdeadbeefdeadbeefdeadbeef";
    let audit_event_id = "9".repeat(64);
    let payload = serde_json::to_vec(&serde_json::json!({
        "operation_id": operation_id,
        "audit_event_id": audit_event_id,
        "skill_id": "dedup_skill",
        "status": "committed",
    }))
    .unwrap();
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
    let request =
        format!("{{\"event_type\":0,\"event_subtype\":{subtype},\"payload_b64\":{payload_b64:?}}}");

    assert_eq!(
        raw_post(&addr, Some("skill-dedup-token"), &request).await,
        200
    );
    assert_eq!(
        recv_runtime_transition_for_home(&mut transitions, segdir.path()).await,
        crate::skills::registry::RuntimeAuthorityTransitionKind::InstallResult
    );
    assert_eq!(
        raw_post(&addr, Some("skill-dedup-token"), &request).await,
        200,
        "retry after a lost response must ACK the existing audit id"
    );
    assert_eq!(
        recv_runtime_transition_for_home(&mut transitions, segdir.path()).await,
        crate::skills::registry::RuntimeAuthorityTransitionKind::InstallResult,
        "a duplicate durable ACK must still wake a runtime that missed the first transition"
    );

    let conflicting = serde_json::to_vec(&serde_json::json!({
        "operation_id": operation_id,
        "audit_event_id": audit_event_id,
        "skill_id": "different_skill",
        "status": "committed",
    }))
    .unwrap();
    let conflicting_b64 = base64::engine::general_purpose::STANDARD.encode(conflicting);
    let conflicting_request = format!(
        "{{\"event_type\":0,\"event_subtype\":{subtype},\"payload_b64\":{conflicting_b64:?}}}"
    );
    assert_eq!(
        raw_post(&addr, Some("skill-dedup-token"), &conflicting_request).await,
        409
    );

    task.abort();
    drop(writer);
    wal_join.await.ok();
    let bytes = tokio::fs::read(&seg).await.unwrap();
    let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
    let mut cursor = header.header_len();
    let mut matching_results = 0usize;
    while cursor < bytes.len() {
        let frame = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
        if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
            && frame.header.event_subtype == subtype
        {
            matching_results += 1;
        }
        cursor += frame.header.total_len as usize;
    }
    assert_eq!(
        matching_results, 1,
        "one deterministic audit id may produce exactly one terminal frame"
    );
}

#[tokio::test]
async fn unauthenticated_authority_ingress_cannot_poison_unrelated_skill_scans() {
    let home = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let wal_dir = home.path().join("wal");
    std::fs::create_dir_all(&wal_dir).unwrap();
    crate::wal::compaction::load_or_init_key(&wal_dir.join("hmac.key")).unwrap();
    crate::skills::authority::initialize_authority_key_for_test(home.path()).unwrap();
    let segment = wal_dir.join("authority-ingress-000001.wal");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "authority-ingress-token".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (address, task) = bind_and_serve(home.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    let subtype = crate::wal::events::ExtendedSubtype::SkillAuthorityDecision as u8;
    let payload = serde_json::to_vec(&serde_json::json!({
        "audit_event_id": "a".repeat(64),
        "operation_id": "b".repeat(32),
    }))
    .unwrap();
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let request =
        format!("{{\"event_type\":0,\"event_subtype\":{subtype},\"payload_b64\":{payload_b64:?}}}");

    let (status, response) = raw_post_path(
        &address,
        "/skill-mutation-audit",
        Some("authority-ingress-token"),
        &request,
    )
    .await;
    assert_eq!(status, 400, "{response}");
    assert!(
        response.contains("authentication"),
        "the rejection must identify the missing authority authentication: {response}"
    );

    task.abort();
    drop(writer);
    wal_join.await.ok();
    let bytes = tokio::fs::read(&segment).await.unwrap();
    let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
    let mut cursor = header.header_len();
    while cursor < bytes.len() {
        let frame = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
        assert!(
            frame.header.event_type != crate::wal::events::EVENT_TYPE_EXTENDED
                || frame.header.event_subtype != subtype,
            "unauthenticated authority payload reached the durable WAL"
        );
        cursor += frame.header.total_len as usize;
    }
    assert!(
        !crate::skills::authority::scan_authority_wal_head_exists_for_test(
            home.path(),
            "unrelated"
        )
        .unwrap(),
        "a rejected authority request must leave unrelated Skill scans healthy"
    );
}

#[tokio::test]
async fn skill_mutation_dedup_survives_caller_cancellation_after_durable_append() {
    let segdir = tempdir().unwrap();
    let seg = canonical_test_wal(segdir.path(), "audit-skill-cancel-dedup");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), segdir.path().to_path_buf()).unwrap();
    let gate = crate::wal::writer::TestAckGate::once(crate::wal::events::EVENT_TYPE_EXTENDED);
    let subtype = crate::wal::events::ExtendedSubtype::SkillRemovalResult as u8;
    let audit_event_id = "7".repeat(64);
    let payload = serde_json::to_vec(&serde_json::json!({
        "operation_id": "facade00facade00facade00facade00",
        "audit_event_id": audit_event_id,
        "skill_id": "cancelled_skill",
        "status": "committed",
    }))
    .unwrap();
    let dedup_key = format!("{subtype:02x}:{audit_event_id}");
    let payload_sha256 = hex::encode(sha2::Sha256::digest(&payload));

    let cancelled_caller = tokio::spawn(super::server::append_skill_audit_idempotently(
        writer.clone().with_test_ack_gate(gate.clone()),
        crate::wal::events::EVENT_TYPE_EXTENDED,
        subtype,
        payload.clone(),
        dedup_key.clone(),
        payload_sha256.clone(),
    ));
    gate.wait_until_durable().await;
    cancelled_caller.abort();
    let _ = cancelled_caller.await;
    gate.release();

    let retry = super::server::append_skill_audit_idempotently(
        writer.clone(),
        crate::wal::events::EVENT_TYPE_EXTENDED,
        subtype,
        payload,
        dedup_key,
        payload_sha256,
    )
    .await
    .unwrap();
    assert!(
        matches!(retry, super::server::SkillAuditAppendOutcome::Duplicate),
        "a cancelled caller must not reopen the append window"
    );

    drop(writer);
    wal_join.await.ok();
    let bytes = tokio::fs::read(&seg).await.unwrap();
    let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
    let mut cursor = header.header_len();
    let mut matching_results = 0usize;
    while cursor < bytes.len() {
        let frame = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
        if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
            && frame.header.event_subtype == subtype
        {
            matching_results += 1;
        }
        cursor += frame.header.total_len as usize;
    }
    assert_eq!(matching_results, 1);
}

#[tokio::test]
async fn cancelled_pre_durability_rpc_append_retains_then_recovers_exact_journal() {
    let home = tempdir().unwrap();
    let source = home.path().join("incoming-rpc-cancel");
    let skills_dir = home.path().join("skills");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("skill.yaml"),
        "id: rpc_cancel\n\
         description: RPC cancellation recovery\n\
         trigger_keywords: [rpc]\n\
         system_prompt: Keep the exact lifecycle binding.\n",
    )
    .unwrap();
    let mut prepared = crate::skills::installer::prepare_install_from_local_with_expectation(
        &source,
        &skills_dir,
        false,
        None,
        "a11d0000a11d0000a11d0000a11d0000",
    )
    .unwrap();
    prepared.mark_intent_submitting().unwrap();
    let binding = prepared.audit_binding();
    drop(prepared);

    let wal_dir = home.path().join("wal");
    std::fs::create_dir_all(&wal_dir).unwrap();
    let (writer, wal_join) = crate::wal::spawn_for_home(
        wal_dir.join("rpc-pre-durable-cancel-000001.wal"),
        home.path().to_path_buf(),
    )
    .unwrap();
    let gate = crate::wal::writer::TestAckGate::once(crate::wal::events::EVENT_TYPE_EXTENDED);
    let blocker_payload = br#"{"rpc_blocker":true}"#.to_vec();
    let blocker_header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &blocker_payload)
            .event_subtype(
                crate::wal::events::ExtendedSubtype::CommunicationProfileControlled as u8,
            )
            .build();
    let blocker_writer = writer.clone().with_test_ack_gate(gate.clone());
    let blocker =
        tokio::spawn(async move { blocker_writer.append(blocker_header, blocker_payload).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), gate.wait_until_durable())
        .await
        .expect("blocker must hold the WAL writer before the Skill frame");

    let subtype = crate::wal::events::ExtendedSubtype::SkillInstallIntent as u8;
    let key = crate::wal::compaction::load_existing_key(&wal_dir.join("hmac.key")).unwrap();
    let payload =
        crate::skills::mutation_lifecycle::skill_mutation_audit_payload(&binding, false, &key)
            .unwrap();
    let payload_sha256 = hex::encode(sha2::Sha256::digest(&payload));
    let dedup_key = format!("{subtype:02x}:{}", binding.intent_audit_event_id());
    let coordinator = Arc::new(super::server::SkillAuditCoordinator::default());
    let cancelled = tokio::spawn(
        super::server::append_skill_audit_idempotently_with_coordinator(
            Arc::clone(&coordinator),
            writer.clone(),
            crate::wal::events::EVENT_TYPE_EXTENDED,
            subtype,
            payload,
            dedup_key,
            payload_sha256,
        ),
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if coordinator.inflight_count().await == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Skill RPC append must enter the coordinator");
    assert_eq!(coordinator.inflight_count().await, 1);
    cancelled.abort();
    let _ = cancelled.await;

    assert_eq!(
        crate::skills::mutation_lifecycle::scan_skill_mutation_audit_count(
            home.path(),
            &binding,
            false,
        )
        .unwrap(),
        0
    );
    let pending = crate::skills::mutation_lifecycle::reconcile_pending(
        home.path(),
        &skills_dir,
        Some(&writer),
    )
    .await
    .expect_err("an in-flight same-process append must keep its journal");
    assert!(pending.to_string().contains("entered intent delivery"));
    assert!(skills_dir.join(".neoth-skill-mutation.json").exists());

    gate.release();
    blocker.await.unwrap().unwrap();
    for _ in 0..100 {
        if crate::skills::mutation_lifecycle::scan_skill_mutation_audit_count(
            home.path(),
            &binding,
            false,
        )
        .unwrap()
            == 1
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        crate::skills::mutation_lifecycle::scan_skill_mutation_audit_count(
            home.path(),
            &binding,
            false,
        )
        .unwrap(),
        1
    );
    crate::skills::mutation_lifecycle::reconcile_pending(home.path(), &skills_dir, Some(&writer))
        .await
        .unwrap();
    assert!(!skills_dir.join(".neoth-skill-mutation.json").exists());
    assert!(!skills_dir.join("rpc_cancel").exists());

    drop(writer);
    wal_join.await.ok();
}

#[tokio::test]
async fn skill_mutation_singleflight_is_bounded_and_recovers_capacity() {
    let segdir = tempdir().unwrap();
    let seg = canonical_test_wal(segdir.path(), "audit-skill-singleflight");
    let (writer, wal_join) = crate::wal::spawn_for_home(seg, segdir.path().to_path_buf()).unwrap();
    let coordinator = Arc::new(super::server::SkillAuditCoordinator::default());
    let gate = crate::wal::writer::TestAckGate::once(crate::wal::events::EVENT_TYPE_EXTENDED);
    let subtype = crate::wal::events::ExtendedSubtype::SkillInstallIntent as u8;

    let first_payload = br#"{"operation_id":"00000000000000000000000000000000"}"#.to_vec();
    let first_sha256 = hex::encode(sha2::Sha256::digest(&first_payload));
    let first = tokio::spawn(
        super::server::append_skill_audit_idempotently_with_coordinator(
            Arc::clone(&coordinator),
            writer.clone().with_test_ack_gate(gate.clone()),
            crate::wal::events::EVENT_TYPE_EXTENDED,
            subtype,
            first_payload.clone(),
            "singleflight-00".to_string(),
            first_sha256.clone(),
        ),
    );
    gate.wait_until_durable().await;

    let mut requests = Vec::new();
    for index in 1..super::server::MAX_SKILL_AUDIT_INFLIGHT {
        let payload = format!("{{\"operation_id\":\"{index:032x}\"}}").into_bytes();
        let payload_sha256 = hex::encode(sha2::Sha256::digest(&payload));
        requests.push(tokio::spawn(
            super::server::append_skill_audit_idempotently_with_coordinator(
                Arc::clone(&coordinator),
                writer.clone(),
                crate::wal::events::EVENT_TYPE_EXTENDED,
                subtype,
                payload,
                format!("singleflight-{index:02}"),
                payload_sha256,
            ),
        ));
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if coordinator.inflight_count().await == super::server::MAX_SKILL_AUDIT_INFLIGHT {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all bounded Skill-audit workers must enter the coordinator");
    assert_eq!(
        coordinator.inflight_count().await,
        super::server::MAX_SKILL_AUDIT_INFLIGHT
    );

    let overflow_payload = br#"{"operation_id":"ffffffffffffffffffffffffffffffff"}"#.to_vec();
    let overflow_sha256 = hex::encode(sha2::Sha256::digest(&overflow_payload));
    assert_eq!(
        super::server::append_skill_audit_idempotently_with_coordinator(
            Arc::clone(&coordinator),
            writer.clone(),
            crate::wal::events::EVENT_TYPE_EXTENDED,
            subtype,
            overflow_payload,
            "singleflight-overflow".to_string(),
            overflow_sha256,
        )
        .await
        .unwrap(),
        super::server::SkillAuditAppendOutcome::CapacityReached
    );

    let joined_retry = tokio::spawn(
        super::server::append_skill_audit_idempotently_with_coordinator(
            Arc::clone(&coordinator),
            writer.clone(),
            crate::wal::events::EVENT_TYPE_EXTENDED,
            subtype,
            first_payload,
            "singleflight-00".to_string(),
            first_sha256,
        ),
    );
    tokio::task::yield_now().await;
    assert_eq!(
        coordinator.inflight_count().await,
        super::server::MAX_SKILL_AUDIT_INFLIGHT,
        "a retry must join the existing worker, not consume another slot"
    );

    gate.release();
    assert!(matches!(
        first.await.unwrap().unwrap(),
        super::server::SkillAuditAppendOutcome::Appended(_)
    ));
    for request in requests {
        assert!(matches!(
            request.await.unwrap().unwrap(),
            super::server::SkillAuditAppendOutcome::Appended(_)
        ));
    }
    assert_eq!(
        joined_retry.await.unwrap().unwrap(),
        super::server::SkillAuditAppendOutcome::Duplicate
    );
    assert_eq!(coordinator.inflight_count().await, 0);

    let after_payload = br#"{"operation_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}"#.to_vec();
    let after_sha256 = hex::encode(sha2::Sha256::digest(&after_payload));
    assert!(matches!(
        super::server::append_skill_audit_idempotently_with_coordinator(
            coordinator,
            writer.clone(),
            crate::wal::events::EVENT_TYPE_EXTENDED,
            subtype,
            after_payload,
            "singleflight-after-drain".to_string(),
            after_sha256,
        )
        .await
        .unwrap(),
        super::server::SkillAuditAppendOutcome::Appended(_)
    ));

    drop(writer);
    wal_join.await.ok();
}

#[tokio::test]
async fn wrong_token_is_401_and_writes_no_frame() {
    let segdir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(segdir.path(), "audit-oversized");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), segdir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "tok-valid".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(segdir.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    let body = r#"{"event_type":168,"payload_b64":"e30="}"#;
    let status = raw_post(&addr, Some("tok-WRONG"), body).await;
    assert_eq!(status, 401);
    // missing token too
    assert_eq!(raw_post(&addr, None, body).await, 401);
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
async fn valid_bearer_bypasses_and_resets_shared_ipc_cooldown() {
    let segdir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(segdir.path(), "audit-cooldown-reset");
    let (writer, wal_join) = crate::wal::spawn_for_home(seg, segdir.path().to_path_buf()).unwrap();
    let cooldown = Arc::new(AuthCooldown::new());
    let now = std::time::Instant::now();
    for _ in 0..crate::n8n_api::AUTH_FAILURE_STRIKE_LIMIT {
        cooldown.record_failure("same-user-ipc", now);
    }
    assert!(cooldown.is_locked("same-user-ipc", now));
    let state = AuditRpcState {
        token: "tok-valid".into(),
        writer: writer.clone(),
        cooldown: Arc::clone(&cooldown),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(segdir.path(), &endpoint_nonce, state)
        .await
        .unwrap();

    let (status, body) = raw_post_path(&addr, "/health", Some("tok-valid"), "").await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !cooldown.is_locked("same-user-ipc", std::time::Instant::now()),
        "a valid bearer must clear a cooldown poisoned by another same-user client"
    );

    task.abort();
    drop(writer);
    wal_join.await.ok();
}

#[tokio::test]
async fn blocked_event_type_is_422_and_emits_reject() {
    use crate::wal::events::EVENT_TYPE_AUDIT_RPC_REJECT;
    let segdir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(segdir.path(), "audit-route");
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), segdir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "tok".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(segdir.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    // 0x10 (daemon lifecycle) is NOT forwardable.
    let body = r#"{"event_type":16,"payload_b64":"e30="}"#;
    let status = raw_post(&addr, Some("tok"), body).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_round_trips_against_a_live_listener() {
    use crate::wal::events::EVENT_TYPE_OS_FILE_READ;
    let home = tempdir().unwrap();
    let seg_dir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(seg_dir.path(), "audit-stale-endpoint");
    let token = init_rpc_token(home.path()).unwrap();
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), seg_dir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: token.clone(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(home.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    let _daemon_owner = publish_test_endpoint(home.path(), &addr, &endpoint_nonce);
    assert!(
        is_reachable(home.path()),
        "live same-user IPC health probe must accept the exact response body"
    );

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
async fn jobs_run_token_client_is_request_bound_and_single_use() {
    let home = tempdir().unwrap();
    let seg_dir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(seg_dir.path(), "audit-stale-nonce");
    let token = init_rpc_token(home.path()).unwrap();
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), seg_dir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: token.clone(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(home.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    let _daemon_owner = publish_test_endpoint(home.path(), &addr, &endpoint_nonce);
    let binding = "ab".repeat(32);
    let approval = mint_jobs_run_token(home.path(), &binding)
        .await
        .expect("jobs token mint");

    assert!(
        !consume_jobs_run_token(home.path(), &approval, &"cd".repeat(32)).await,
        "a different request binding must not consume or authorise the token"
    );
    assert!(consume_jobs_run_token(home.path(), &approval, &binding).await);
    assert!(
        !consume_jobs_run_token(home.path(), &approval, &binding).await,
        "jobs token must be single-use"
    );

    task.abort();
    drop(writer);
    wal_join.await.ok();

    let bytes = tokio::fs::read(&seg).await.unwrap();
    let frame =
        crate::wal::frame::decode_frame(&bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..])
            .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
    assert_eq!(
        frame.header.event_type,
        crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED
    );
    assert_eq!(payload["action"], "ExecArbitrary");
    assert_eq!(payload["decision"], "operator_approval_token_minted");
    assert_eq!(payload["authority_boundary"], "same_uid_operator");
    assert_eq!(payload["request_binding_sha256"], binding);
}

#[tokio::test]
async fn jobs_run_token_mint_fails_when_its_mandatory_audit_writer_is_down() {
    let home = tempdir().unwrap();
    let seg_dir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(seg_dir.path(), "audit-dead-writer");
    let token = init_rpc_token(home.path()).unwrap();
    let (writer, wal_join) = crate::wal::spawn_for_home(seg, seg_dir.path().to_path_buf()).unwrap();
    wal_join.abort();
    let _ = wal_join.await;

    let state = AuditRpcState {
        token: token.clone(),
        writer,
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(home.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    let _daemon_owner = publish_test_endpoint(home.path(), &addr, &endpoint_nonce);

    assert!(
        mint_jobs_run_token(home.path(), &"ab".repeat(32))
            .await
            .is_none(),
        "the daemon must not release an approval token without its WAL proof"
    );
    task.abort();
}

#[tokio::test]
async fn subtype_client_round_trips_against_a_live_listener() {
    let home = tempdir().unwrap();
    let seg_dir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(seg_dir.path(), "audit-token-rotation");
    let token = init_rpc_token(home.path()).unwrap();
    let (writer, wal_join) =
        crate::wal::spawn_for_home(seg.clone(), seg_dir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: token.clone(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(home.path(), &endpoint_nonce, state)
        .await
        .unwrap();
    let _daemon_owner = publish_test_endpoint(home.path(), &addr, &endpoint_nonce);
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
    // an attacker could occupy the stale OS endpoint, and sending the bearer
    // token there would disclose it.
    let home = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    init_rpc_token(home.path()).unwrap();
    // 999_999_999 is above any OS pid_max (and stays positive as an i32
    // pid_t, so the unix `kill(pid,0)` check can't alias to the -1
    // "whole process group" sentinel) — reliably a dead pid on all OSes.
    let endpoint = super::transport::endpoint_for_home(home.path(), &endpoint_nonce).unwrap();
    write_sidecar(home.path(), &endpoint, 999_999_999, &endpoint_nonce).unwrap();
    let r = try_post_audit_frame(home.path(), 0xA8, b"{}").await;
    assert!(
        matches!(r, Err(AuditRpcClientError::Unavailable(ref m)) if m.contains("stale")),
        "a dead-pid sidecar must be refused as stale, got {r:?}"
    );
}
/// The accept loop runs inside a `tokio::select!`, so `accept()` is dropped
/// whenever the other branch wins. It used to remove the pending pipe instance
/// before awaiting the connection, so one such cancellation destroyed the only
/// listener and every later connect failed with "listener is closed". Since the
/// loop treats an accept error as fatal, the daemon served exactly ONE audit
/// connection and then stopped — silently, because the DaemonRpc sink is
/// best-effort. Two sequential round-trips are the smallest thing that fails
/// when that regresses.
#[tokio::test]
async fn listener_serves_more_than_one_connection() {
    let home = tempdir().unwrap();
    let seg_dir = tempdir().unwrap();
    let endpoint_nonce = test_endpoint_nonce();
    let seg = canonical_test_wal(seg_dir.path(), "audit-two-connections");
    let (writer, wal_join) = crate::wal::spawn_for_home(seg, seg_dir.path().to_path_buf()).unwrap();
    let state = AuditRpcState {
        token: "tok".into(),
        writer: writer.clone(),
        cooldown: Arc::new(AuthCooldown::new()),
        fullauto: Arc::new(super::FullAutoTokenStore::new()),
        #[cfg(feature = "cluster")]
        membership: None,
        audit_routes_enabled: true,
    };
    let (addr, task) = bind_and_serve(home.path(), &endpoint_nonce, state)
        .await
        .unwrap();

    let body = r#"{"event_type":168,"payload_b64":"e30="}"#;
    assert_eq!(raw_post(&addr, Some("tok"), body).await, 200, "first");
    assert_eq!(
        raw_post(&addr, Some("tok"), body).await,
        200,
        "the listener must still accept after serving one connection"
    );
    assert_eq!(
        raw_post(&addr, Some("tok"), body).await,
        200,
        "and keep accepting"
    );

    task.abort();
    drop(writer);
    wal_join.await.ok();
}
