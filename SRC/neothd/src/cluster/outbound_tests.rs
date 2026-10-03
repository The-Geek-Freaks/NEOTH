use super::heartbeat::TaskDelegateScope;
use super::membership::{
    AuthEpoch, BootId, CarrierKind, LiveSessionRegistry, LocalNodeIdentity, MembershipController,
    MembershipEpoch, MembershipStore, OutboundTaskDelegateState, TaskDelegateOutboundAssignment,
    TaskDelegateOutboundAssignmentRequest, TransportIdentity,
};
use super::runtime_supervisor::{
    OutboundTaskDelegateController, OutboundTaskDelegateDispatchRequest,
};
use std::sync::Arc;
const NOW: i64 = 1_700_000_000;
const LIVE_GRANT_TTL_SECS: i64 = 300;

fn scope() -> TaskDelegateScope {
    TaskDelegateScope {
        skill_id: "summarize".into(),
        channel_id: Some("telegram".into()),
        account_id: Some("primary".into()),
    }
}

#[test]
fn outbound_deadline_status_is_read_only_until_explicit_authenticated_reconciliation() {
    let home = tempfile::tempdir().expect("home");
    let store = MembershipStore::open(home.path()).expect("store");
    let exact = scope();
    let peer = active_peer(&store, "deadline-status");
    assign(&store, peer.clone(), &exact, true, 1, 0);
    store
        .prepare_task_delegate_outbound_operation_bound(
            "op-deadline-status",
            "task-deadline-status",
            &peer,
            &exact,
            NOW,
            NOW + 5,
            "a".repeat(64),
        )
        .expect("persist deadline before queue");
    let first =
        MembershipStore::task_delegate_outbound_status_read_only(home.path(), "op-deadline-status")
            .expect("first pure read")
            .expect("status");
    let second =
        MembershipStore::task_delegate_outbound_status_read_only(home.path(), "op-deadline-status")
            .expect("second pure read")
            .expect("status");
    assert_eq!(first, second);
    assert_eq!(first.state, OutboundTaskDelegateState::Prepared);
    assert!(
        store
            .mark_task_delegate_outbound_indeterminate("op-deadline-status", NOW + 4)
            .is_err(),
        "pre-deadline reconciliation is denied"
    );
    assert_eq!(
        store
            .mark_task_delegate_outbound_indeterminate("op-deadline-status", NOW + 5)
            .expect("elapsed explicit mutation"),
        OutboundTaskDelegateState::Indeterminate
    );
    assert_eq!(
        MembershipStore::task_delegate_outbound_status_read_only(home.path(), "op-deadline-status")
            .unwrap()
            .unwrap()
            .state,
        OutboundTaskDelegateState::Indeterminate
    );
}

#[test]
fn outbound_deadline_rejects_expired_prepare_and_late_result_cannot_settle_indeterminate() {
    let home = tempfile::tempdir().expect("home");
    let store = MembershipStore::open(home.path()).expect("store");
    let exact = scope();
    let peer = active_peer(&store, "deadline-late-result");
    assign(&store, peer.clone(), &exact, true, 1, 0);
    assert!(
        store
            .prepare_task_delegate_outbound_operation_bound(
                "op-expired",
                "task-expired",
                &peer,
                &exact,
                NOW,
                NOW,
                "b".repeat(64),
            )
            .is_err(),
        "expired request creates no operation"
    );
    store
        .prepare_task_delegate_outbound_operation_bound(
            "op-late",
            "task-late",
            &peer,
            &exact,
            NOW,
            NOW + 1,
            "c".repeat(64),
        )
        .expect("live operation");
    store
        .mark_task_delegate_outbound_indeterminate("op-late", NOW + 1)
        .expect("explicit expired state");
    assert!(
        store
            .receive_task_delegate_outbound_result(
                &peer,
                &completed_result("task-late", "too late"),
                NOW + 2,
            )
            .is_err(),
        "late result cannot settle indeterminate custody"
    );
    assert!(
        store
            .task_delegate_outbound_result("op-late")
            .unwrap()
            .is_none()
    );
}

fn active_peer(store: &MembershipStore, label: &str) -> String {
    active_peer_at(store, label, NOW, NOW + 60)
}

fn active_live_peer(store: &MembershipStore, label: &str, now: i64) -> String {
    active_peer_at(store, label, now, now.saturating_add(LIVE_GRANT_TTL_SECS))
}

fn active_peer_at(store: &MembershipStore, label: &str, now: i64, expires_at_unix: i64) -> String {
    let peer_home = tempfile::tempdir().expect("create isolated peer identity");
    let identity =
        LocalNodeIdentity::load_or_create(peer_home.path()).expect("create isolated peer identity");
    let transport = TransportIdentity::peeroxide(&identity.peeroxide_key_pair().public_key);
    let attestation = identity
        .attest_endpoint(
            CarrierKind::Peeroxide,
            transport.clone(),
            BootId::new(),
            format!("outbound-{label}"),
            "127.0.0.1:1234".into(),
            AuthEpoch::INITIAL,
            MembershipEpoch::new(2).expect("valid membership epoch"),
            Some("test-invite".into()),
            expires_at_unix,
        )
        .expect("attest isolated peer");
    store
        .confirm_attestation(
            &attestation,
            CarrierKind::Peeroxide,
            &transport,
            "127.0.0.1:1234",
            &format!("outbound-{label}"),
            now,
        )
        .expect("confirm active peer");
    transport.as_str().to_owned()
}

fn assign(
    store: &MembershipStore,
    peer_key: String,
    scope: &TaskDelegateScope,
    allowed: bool,
    priority: u64,
    expected_revision: u64,
) -> TaskDelegateOutboundAssignment {
    store
        .set_task_delegate_outbound_assignment(
            &TaskDelegateOutboundAssignment {
                peer_key,
                skill_id: scope.skill_id.clone(),
                channel_id: scope.channel_id.clone(),
                account_id: scope.account_id.clone(),
                allowed,
                priority,
                revision: 0,
            },
            expected_revision,
        )
        .expect("commit exact outbound assignment")
}

fn dispatch_request(
    operation_id: &str,
    task_id: &str,
    scope: TaskDelegateScope,
) -> OutboundTaskDelegateDispatchRequest {
    OutboundTaskDelegateDispatchRequest {
        operation_id: operation_id.into(),
        task_id: task_id.into(),
        prompt: "summarize this exact authorized task".into(),
        model_hint: None,
        max_output_tokens: None,
        deadline_unix: NOW + 60,
        scope,
    }
}

fn completed_result(task_id: &str, text: &str) -> super::heartbeat::TaskResultBody {
    super::heartbeat::TaskResultBody {
        task_id: task_id.into(),
        status: super::heartbeat::TaskResultStatus::Completed,
        result: Some(text.into()),
        provider_name: Some("fixture-provider".into()),
        requested_max_output_tokens: Some(64),
        effective_output_token_ceiling: Some(64),
    }
}

#[test]
fn task_result_validator_enforces_terminal_payload_shape_without_requiring_nonempty_completion() {
    let completed_empty = completed_result("shape-completed", "");
    assert!(super::heartbeat::validate_task_result(&completed_empty).is_ok());

    let mut completed_missing = completed_empty.clone();
    completed_missing.result = None;
    assert!(super::heartbeat::validate_task_result(&completed_missing).is_err());

    let rejected_with_payload = super::heartbeat::TaskResultBody {
        task_id: "shape-rejected".into(),
        status: super::heartbeat::TaskResultStatus::Rejected {
            reason: "operator_assignment_denied".into(),
        },
        result: Some("must not be retained as a completion".into()),
        provider_name: None,
        requested_max_output_tokens: None,
        effective_output_token_ceiling: None,
    };
    assert!(super::heartbeat::validate_task_result(&rejected_with_payload).is_err());

    let failed_without_payload = super::heartbeat::TaskResultBody {
        task_id: "shape-failed".into(),
        status: super::heartbeat::TaskResultStatus::Failed {
            error: "no_provider_on_this_node".into(),
        },
        result: None,
        provider_name: None,
        requested_max_output_tokens: None,
        effective_output_token_ceiling: None,
    };
    assert!(super::heartbeat::validate_task_result(&failed_without_payload).is_ok());
}

#[test]
fn worker_result_outbox_reopens_exact_duplicates_and_rejects_foreign_or_conflicting_ack() {
    let home = tempfile::tempdir().expect("create worker authority home");
    let store = MembershipStore::open(home.path()).expect("open authority store");
    let peer_key = active_peer(&store, "worker-outbox");
    let grant = store
        .admit(
            CarrierKind::Peeroxide,
            &TransportIdentity::parse(peer_key.clone()).expect("parse authenticated peer"),
            NOW,
        )
        .expect("admit authenticated requester");
    let body = completed_result("worker-outbox-task", "retained exact result");
    let context = "a".repeat(64);
    assert_eq!(
        store
            .reserve_worker_task_execution(&grant, &body.task_id, &context, NOW)
            .expect("reserve before provider"),
        super::membership::WorkerTaskExecutionReservation::Reserved
    );
    assert_eq!(
        store
            .reserve_worker_task_execution(&grant, &body.task_id, &context, NOW)
            .expect("concurrent duplicate remains non-executable"),
        super::membership::WorkerTaskExecutionReservation::Existing
    );
    assert!(
        store
            .reserve_worker_task_execution(&grant, &body.task_id, &"c".repeat(64), NOW)
            .is_err(),
        "same id with changed authenticated request context must fail closed"
    );
    assert_eq!(
        store
            .persist_worker_task_result_outbox(&grant, &context, &body, NOW + 1)
            .expect("persist before send"),
        super::membership::WorkerTaskResultOutboxReceipt::Stored
    );
    assert_eq!(
        store
            .persist_worker_task_result_outbox(&grant, &context, &body, NOW + 2)
            .expect("exact duplicate retained"),
        super::membership::WorkerTaskResultOutboxReceipt::Duplicate
    );
    let pending = store
        .pending_worker_task_result_outbox(&grant, NOW + 3)
        .expect("read pending after first send loss");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].body, body);
    let digest = super::heartbeat::task_result_digest(&body).expect("bounded digest");
    let wrong = super::heartbeat::TaskResultAckBody {
        task_id: body.task_id.clone(),
        result_digest: "b".repeat(64),
    };
    assert!(
        !store
            .acknowledge_worker_task_result_outbox(&grant, &wrong, NOW + 4)
            .expect("wrong digest is non-settling")
    );
    let exact = super::heartbeat::TaskResultAckBody {
        task_id: body.task_id.clone(),
        result_digest: digest,
    };
    assert!(
        store
            .acknowledge_worker_task_result_outbox(&grant, &exact, NOW + 5)
            .expect("exact ack settles")
    );
    assert!(
        store
            .worker_task_result_outbox_for_task(&grant, &body.task_id, NOW + 6)
            .expect("tombstone retained")
            .is_some()
    );
    drop(store);
    let reopened = MembershipStore::open(home.path()).expect("reopen durable outbox");
    let reopened_grant = reopened
        .admit(
            CarrierKind::Peeroxide,
            &TransportIdentity::parse(peer_key).expect("parse peer"),
            NOW + 7,
        )
        .expect("re-admit");
    assert!(
        reopened
            .worker_task_result_outbox_for_task(&reopened_grant, &body.task_id, NOW + 7)
            .expect("reopened tombstone")
            .is_some()
    );
}

#[test]
fn worker_result_outbox_failed_offer_replays_on_registered_session_and_ack_keeps_tombstone() {
    let home = tempfile::tempdir().expect("create worker outbox home");
    let store = MembershipStore::open(home.path()).expect("open authority store");
    let live_now = crate::time::now_unix_i64();
    let peer_key = active_live_peer(&store, "worker-live-offer", live_now);
    let grant = store
        .admit(
            CarrierKind::Peeroxide,
            &TransportIdentity::parse(peer_key.clone()).expect("parse peer"),
            live_now,
        )
        .expect("admit peer");
    let streams = Arc::new(super::peer_streams::PeerStreamRegistry::new());
    let outbox = super::result_outbox::WorkerResultOutbox::new(
        home.path(),
        Arc::clone(&streams),
        "local-worker".into(),
    )
    .expect("open production outbox");
    let body = completed_result("worker-live-offer-task", "stored before session exists");
    let context = "d".repeat(64);
    outbox
        .persist_and_offer(&grant, &context, &body)
        .expect("failed initial offer still persists");
    let (_generation, mut receiver, _cancel) =
        streams.register_authorized_session(&peer_key, &grant);
    assert_eq!(
        outbox
            .replay_for_session(&grant)
            .expect("registered replay"),
        1
    );
    let queued = receiver
        .try_recv()
        .expect("same-session replay queues retained body");
    match &*queued {
        super::heartbeat::WireFrame {
            body: super::heartbeat::FrameBody::TaskResult(actual),
            ..
        } => assert_eq!(actual, &body),
        other => panic!("expected retained TaskResult, got {other:?}"),
    }
    // Simulate a healthy master whose durable result commit failed: it emits
    // no ACK, but the worker reopens the stale offered row on the existing
    // session cadence and offers the exact retained bytes again.
    store
        .reopen_stale_offered_worker_task_results(&grant, i64::MAX, crate::time::now_unix_i64())
        .expect("reopen lost-ack offer");
    assert_eq!(
        outbox
            .flush_session(&grant)
            .expect("same-session lost-ack retry"),
        1
    );
    assert!(
        receiver.try_recv().is_ok(),
        "lost ACK reoffers without reconnect or provider"
    );
    let digest = super::heartbeat::task_result_digest(&body).expect("digest");
    let wrong = super::heartbeat::TaskResultAckBody {
        task_id: body.task_id.clone(),
        result_digest: "e".repeat(64),
    };
    assert!(
        !outbox
            .acknowledge(&grant, &wrong)
            .expect("wrong digest leaves pending")
    );
    let exact = super::heartbeat::TaskResultAckBody {
        task_id: body.task_id.clone(),
        result_digest: digest,
    };
    assert!(
        outbox
            .acknowledge(&grant, &exact)
            .expect("exact ack settles")
    );
    assert!(
        outbox
            .replay_duplicate_task(
                &grant,
                &super::heartbeat::TaskDelegateBody {
                    task_id: body.task_id.clone(),
                    prompt: "different prompt is rejected by binding before provider".into(),
                    model_hint: None,
                    max_output_tokens: None,
                    deadline_unix: None,
                    scope: None
                }
            )
            .is_err()
    );
}

#[test]
fn worker_result_outbox_flushes_tail_after_current_session_queue_drains() {
    let home = tempfile::tempdir().expect("create queue-drain home");
    let store = MembershipStore::open(home.path()).expect("open authority store");
    let live_now = crate::time::now_unix_i64();
    let peer_key = active_live_peer(&store, "worker-backlog", live_now);
    let grant = store
        .admit(
            CarrierKind::Peeroxide,
            &TransportIdentity::parse(peer_key.clone()).expect("parse peer"),
            live_now,
        )
        .expect("admit peer");
    let streams = Arc::new(super::peer_streams::PeerStreamRegistry::new());
    let outbox = super::result_outbox::WorkerResultOutbox::new(
        home.path(),
        Arc::clone(&streams),
        "local-worker".into(),
    )
    .expect("open production outbox");
    let count = super::peer_streams::OUTBOUND_QUEUE_DEPTH + 1;
    for index in 0..count {
        let body = completed_result(&format!("worker-backlog-{index}"), "bounded retained body");
        store
            .persist_worker_task_result_outbox(
                &grant,
                &format!("{index:064x}"),
                &body,
                live_now + index as i64,
            )
            .expect("persist backlog row");
    }
    let (_generation, mut receiver, _cancel) =
        streams.register_authorized_session(&peer_key, &grant);
    assert_eq!(
        outbox
            .replay_for_session(&grant)
            .expect("initial bounded offer"),
        super::peer_streams::OUTBOUND_QUEUE_DEPTH
    );
    let _first = receiver
        .try_recv()
        .expect("session owner drains one offered row");
    assert_eq!(
        outbox
            .flush_session(&grant)
            .expect("same session tail flush"),
        1
    );
    let mut received = 1usize;
    while receiver.try_recv().is_ok() {
        received += 1;
    }
    assert_eq!(
        received, count,
        "tail is offered after same-session queue drain without reconnect"
    );
}

#[test]
fn outbound_candidates_require_the_exact_allowed_scope() {
    let home = tempfile::tempdir().expect("create authority home");
    let store = MembershipStore::open(home.path()).expect("open authority store");
    let exact = scope();
    let peer_key = active_peer(&store, "exact-scope");
    let allowed = assign(&store, peer_key.clone(), &exact, true, 10, 0);

    let wrong_scope = TaskDelegateScope {
        account_id: Some("secondary".into()),
        ..exact.clone()
    };
    assert!(
        store
            .task_delegate_outbound_candidates(&wrong_scope)
            .expect("query mismatched scope")
            .is_empty(),
        "an exact outbound grant must not become a wildcard"
    );

    let denied = assign(
        &store,
        peer_key,
        &exact,
        false,
        allowed.priority,
        allowed.revision,
    );
    assert_eq!(denied.revision, 2);
    assert!(
        store
            .task_delegate_outbound_candidates(&exact)
            .expect("query denied scope")
            .is_empty(),
        "a denied exact route must not be selected"
    );
}

#[test]
fn outbound_candidates_order_by_priority_then_authenticated_peer_key_and_stale_cas_preserves_route()
{
    let home = tempfile::tempdir().expect("create authority home");
    let store = MembershipStore::open(home.path()).expect("open authority store");
    let exact = scope();
    let peer_a = active_peer(&store, "priority-a");
    let peer_b = active_peer(&store, "priority-b");
    let peer_c = active_peer(&store, "priority-c");
    let committed_a = assign(&store, peer_a.clone(), &exact, true, 5, 0);
    assign(&store, peer_b.clone(), &exact, true, 5, 0);
    assign(&store, peer_c.clone(), &exact, true, 20, 0);

    let before = store
        .task_delegate_outbound_candidates(&exact)
        .expect("query ordered candidates");
    let mut equal_priority = vec![peer_a.clone(), peer_b.clone()];
    equal_priority.sort();
    let expected = vec![
        equal_priority.remove(0),
        equal_priority.remove(0),
        peer_c.clone(),
    ];
    assert_eq!(
        before
            .iter()
            .map(|candidate| candidate.peer_key.clone())
            .collect::<Vec<_>>(),
        expected,
        "the selected route is deterministic across equal-priority peers"
    );

    let stale = store.set_task_delegate_outbound_assignment(
        &TaskDelegateOutboundAssignment {
            priority: 0,
            revision: 0,
            ..committed_a
        },
        0,
    );
    assert!(
        stale
            .expect_err("stale assignment write must refuse")
            .to_string()
            .contains("revision conflict")
    );
    assert_eq!(
        store
            .task_delegate_outbound_candidates(&exact)
            .expect("query candidates after stale write"),
        before,
        "a stale CAS must leave the selected route unchanged"
    );
}

#[test]
fn prepared_outbound_operation_recovers_indeterminate_and_is_never_replayed() {
    let home = tempfile::tempdir().expect("create authority home");
    let store = MembershipStore::open(home.path()).expect("open authority store");
    let exact = scope();
    let peer_key = active_peer(&store, "prepared-recovery");
    assign(&store, peer_key.clone(), &exact, true, 1, 0);
    let prepared = store
        .prepare_task_delegate_outbound_operation(
            "op-prepared",
            "task-prepared",
            &peer_key,
            &exact,
            NOW,
        )
        .expect("persist prepared outbound operation");
    assert_eq!(prepared.state, OutboundTaskDelegateState::Prepared);

    assert_eq!(
        store
            .recover_prepared_task_delegate_outbound_operations(NOW + 1)
            .expect("recover prepared outbound operation"),
        1
    );
    assert_eq!(
        store
            .recover_prepared_task_delegate_outbound_operations(NOW + 2)
            .expect("repeat recovery is inert"),
        0
    );
    assert_eq!(
        store
            .accept_task_delegate_outbound_operation("op-prepared", NOW + 3)
            .expect("late accept reports terminal state"),
        OutboundTaskDelegateState::Indeterminate
    );
    assert!(
        store
            .receive_task_delegate_outbound_result(
                &peer_key,
                &completed_result("task-prepared", "never accepted"),
                NOW + 4,
            )
            .is_err(),
        "recovery must not replay a prepared operation"
    );
    assert!(
        store
            .discard_prepared_task_delegate_outbound_operation("op-prepared")
            .is_err()
    );
}

#[test]
fn only_exact_selected_peer_and_task_settle_outbound_operation_and_late_accept_cannot_reopen_result()
 {
    let home = tempfile::tempdir().expect("create authority home");
    let store = MembershipStore::open(home.path()).expect("open authority store");
    let exact = scope();
    let selected_peer = active_peer(&store, "selected");
    let wrong_peer = active_peer(&store, "wrong");
    assign(&store, selected_peer.clone(), &exact, true, 1, 0);
    assign(&store, wrong_peer.clone(), &exact, true, 2, 0);
    let prepared = store
        .prepare_task_delegate_outbound_operation(
            "op-result",
            "task-result",
            &selected_peer,
            &exact,
            NOW,
        )
        .expect("persist selected prepared operation");
    assert_eq!(prepared.peer_key, selected_peer);
    assert!(
        store
            .receive_task_delegate_outbound_result(
                &wrong_peer,
                &completed_result("task-result", "foreign"),
                NOW + 1,
            )
            .is_err()
    );
    assert!(
        store
            .receive_task_delegate_outbound_result(
                &selected_peer,
                &completed_result("different-task", "foreign"),
                NOW + 1,
            )
            .is_err()
    );
    assert_eq!(
        store
            .accept_task_delegate_outbound_operation("op-result", NOW + 2)
            .expect("accept selected operation"),
        OutboundTaskDelegateState::Accepted
    );
    assert_eq!(
        store
            .receive_task_delegate_outbound_result(
                &selected_peer,
                &completed_result("task-result", "settled"),
                NOW + 3,
            )
            .expect("selected peer stores exact task result"),
        super::membership::OutboundTaskDelegateResultReceipt::Stored
    );
    assert_eq!(
        store
            .accept_task_delegate_outbound_operation("op-result", NOW + 4)
            .expect("late accept must report result"),
        OutboundTaskDelegateState::Resulted
    );
    assert_eq!(
        store
            .receive_task_delegate_outbound_result(
                &selected_peer,
                &completed_result("task-result", "settled"),
                NOW + 5,
            )
            .expect("exact terminal replay is idempotent"),
        super::membership::OutboundTaskDelegateResultReceipt::Duplicate
    );

    store
        .prepare_task_delegate_outbound_operation(
            "op-discard",
            "task-discard",
            &selected_peer,
            &exact,
            NOW + 6,
        )
        .expect("persist operation that the synchronous queue refusal may discard");
    store
        .discard_prepared_task_delegate_outbound_operation("op-discard")
        .expect("only an unaccepted prepared operation is discardable");
    assert!(
        store
            .accept_task_delegate_outbound_operation("op-discard", NOW + 7)
            .is_err(),
        "discarded prepared work cannot be accepted or replayed"
    );
}

#[test]
fn outbound_result_custody_reopens_full_payload_and_rejects_conflicts_without_partial_state() {
    let home = tempfile::tempdir().expect("create authority home");
    let store = MembershipStore::open(home.path()).expect("open authority store");
    let exact = scope();
    let peer_key = active_peer(&store, "result-reopen");
    assign(&store, peer_key.clone(), &exact, true, 1, 0);
    store
        .prepare_task_delegate_outbound_operation(
            "op-reopen",
            "task-reopen",
            &peer_key,
            &exact,
            NOW,
        )
        .expect("prepare outbound task");
    let body = completed_result("task-reopen", "full retained completion");
    assert_eq!(
        store
            .receive_task_delegate_outbound_result(&peer_key, &body, NOW + 1)
            .expect("atomically retain result"),
        super::membership::OutboundTaskDelegateResultReceipt::Stored
    );
    let mut conflict = body.clone();
    conflict.result = Some("different payload".into());
    assert!(
        store
            .receive_task_delegate_outbound_result(&peer_key, &conflict, NOW + 2)
            .is_err()
    );
    drop(store);
    let reopened = MembershipStore::open(home.path()).expect("reopen authority DB");
    let retained = reopened
        .task_delegate_outbound_result("op-reopen")
        .expect("read retained result")
        .expect("terminal result exists after reopen");
    assert_eq!(retained.peer_key, peer_key);
    assert_eq!(retained.task_id, "task-reopen");
    assert_eq!(retained.body, body);
    assert_eq!(
        reopened
            .accept_task_delegate_outbound_operation("op-reopen", NOW + 3)
            .expect("late accept observes terminal result"),
        OutboundTaskDelegateState::Resulted
    );
}

#[test]
fn prepared_result_race_and_revoked_or_indeterminate_operations_fail_closed_without_redelegation() {
    let home = tempfile::tempdir().expect("create authority home");
    let sessions = Arc::new(LiveSessionRegistry::new());
    let controller = MembershipController::new(
        MembershipStore::open(home.path()).expect("open authority store"),
        Arc::clone(&sessions),
    );
    let exact = scope();
    let peer_key = active_peer(controller.store(), "result-race");
    assign(controller.store(), peer_key.clone(), &exact, true, 1, 0);
    controller
        .store()
        .prepare_task_delegate_outbound_operation("op-race", "task-race", &peer_key, &exact, NOW)
        .expect("prepare result race");
    assert_eq!(
        controller
            .store()
            .receive_task_delegate_outbound_result(
                &peer_key,
                &completed_result("task-race", "arrived before local accept"),
                NOW + 1,
            )
            .expect("prepared/result race resolves to terminal custody"),
        super::membership::OutboundTaskDelegateResultReceipt::Stored
    );
    assert_eq!(
        controller
            .store()
            .accept_task_delegate_outbound_operation("op-race", NOW + 2)
            .expect("late queue acceptance cannot reopen result"),
        OutboundTaskDelegateState::Resulted
    );

    controller
        .store()
        .prepare_task_delegate_outbound_operation(
            "op-indeterminate",
            "task-indeterminate",
            &peer_key,
            &exact,
            NOW,
        )
        .expect("prepare indeterminate operation");
    controller
        .store()
        .recover_prepared_task_delegate_outbound_operations(NOW + 3)
        .expect("mark only remaining prepared operation indeterminate");
    assert!(
        controller
            .store()
            .receive_task_delegate_outbound_result(
                &peer_key,
                &completed_result("task-indeterminate", "late result"),
                NOW + 4,
            )
            .is_err()
    );

    controller
        .store()
        .prepare_task_delegate_outbound_operation(
            "op-revoked",
            "task-revoked",
            &peer_key,
            &exact,
            NOW,
        )
        .expect("prepare revocable operation");
    controller
        .revoke("outbound-result-race", "test revoke", NOW + 5)
        .expect("revoke active peer")
        .expect("revoke receipt");
    assert!(
        controller
            .store()
            .receive_task_delegate_outbound_result(
                &peer_key,
                &completed_result("task-race", "arrived before local accept"),
                NOW + 6,
            )
            .is_err(),
        "revocation rejects even an otherwise exact duplicate"
    );
    assert!(
        controller
            .store()
            .receive_task_delegate_outbound_result(
                &peer_key,
                &completed_result("task-revoked", "must not settle after revoke"),
                NOW + 7,
            )
            .is_err()
    );
    assert!(
        controller
            .store()
            .task_delegate_outbound_result("op-revoked")
            .expect("read rejected result slot")
            .is_none()
    );
}

#[test]
fn result_state_update_trigger_abort_rolls_back_prior_result_insert_and_terminal_state_together() {
    let home = tempfile::tempdir().expect("create authority home");
    let store = MembershipStore::open(home.path()).expect("open authority store");
    let exact = scope();
    let peer_key = active_peer(&store, "result-storage-trigger");
    assign(&store, peer_key.clone(), &exact, true, 1, 0);
    store
        .prepare_task_delegate_outbound_operation(
            "op-storage",
            "task-storage",
            &peer_key,
            &exact,
            NOW,
        )
        .expect("prepare operation before terminal-state storage failure");
    let raw = rusqlite::Connection::open(store.path())
        .expect("open isolated authority DB for storage-failure fixture");
    raw.execute_batch(
        "CREATE TRIGGER task_delegate_outbound_operations_resulted_abort \
         BEFORE UPDATE OF state ON task_delegate_outbound_operations \
         WHEN NEW.state='resulted' \
         BEGIN SELECT RAISE(ABORT, 'fixture_resulted_state_abort'); END;",
    )
    .expect("install isolated post-insert terminal-state abort trigger");
    drop(raw);
    assert!(
        store
            .receive_task_delegate_outbound_result(
                &peer_key,
                &completed_result(
                    "task-storage",
                    "insert must roll back with later state failure"
                ),
                NOW + 1,
            )
            .is_err()
    );
    assert!(
        store
            .task_delegate_outbound_result("op-storage")
            .expect("read result after aborted terminal-state update")
            .is_none()
    );
    assert_eq!(
        store
            .accept_task_delegate_outbound_operation("op-storage", NOW + 2)
            .expect("aborted terminal-state update must leave operation pre-terminal"),
        OutboundTaskDelegateState::Accepted
    );
}

#[test]
fn runtime_dispatch_fails_over_from_unknown_or_closed_candidate_before_acceptance() {
    for closed_first in [false, true] {
        let home = tempfile::tempdir().expect("create runtime authority home");
        let live_now = crate::time::now_unix_i64();
        let live_sessions = Arc::new(LiveSessionRegistry::new());
        let membership = Arc::new(MembershipController::new(
            MembershipStore::open(home.path()).expect("open runtime authority store"),
            Arc::clone(&live_sessions),
        ));
        let exact = scope();
        let unavailable_peer =
            active_live_peer(membership.store(), "runtime-unavailable", live_now);
        let live_peer = active_live_peer(membership.store(), "runtime-live", live_now);
        assign(
            membership.store(),
            unavailable_peer.clone(),
            &exact,
            true,
            1,
            0,
        );
        assign(membership.store(), live_peer.clone(), &exact, true, 2, 0);

        let streams = Arc::new(super::peer_streams::PeerStreamRegistry::new());
        if closed_first {
            let unavailable_grant = membership
                .store()
                .admit(
                    CarrierKind::Peeroxide,
                    &TransportIdentity::parse(unavailable_peer.clone())
                        .expect("parse unavailable peer transport"),
                    live_now,
                )
                .expect("admit closed peer");
            let (_generation, receiver, _cancel) =
                streams.register_authorized_session(&unavailable_peer, &unavailable_grant);
            drop(receiver);
        }
        let live_grant = membership
            .store()
            .admit(
                CarrierKind::Peeroxide,
                &TransportIdentity::parse(live_peer.clone()).expect("parse live peer transport"),
                live_now,
            )
            .expect("admit live peer");
        let (_generation, mut receiver, _cancel) =
            streams.register_authorized_session(&live_peer, &live_grant);

        let controller = OutboundTaskDelegateController::new(home.path(), Arc::clone(&membership))
            .expect("construct outbound controller");
        controller.install_peer_streams(Arc::clone(&streams));
        let request = dispatch_request(
            if closed_first {
                "op-closed-failover"
            } else {
                "op-unknown-failover"
            },
            if closed_first {
                "task-closed-failover"
            } else {
                "task-unknown-failover"
            },
            exact,
        );
        let receipt = controller
            .dispatch(&request)
            .expect("fail over to live peer");
        assert_eq!(receipt.peer_key, live_peer);
        assert_eq!(receipt.state, OutboundTaskDelegateState::Accepted);
        let delivered = receiver
            .try_recv()
            .expect("only the live candidate receives the delegated frame");
        drop(delivered);
        assert!(
            controller.dispatch(&request).is_err(),
            "an accepted operation/task retry must not fan out to a second send"
        );
        assert!(
            receiver.try_recv().is_err(),
            "the repeated operation/task request must not enqueue another frame"
        );
    }
}

#[test]
fn clearing_previously_live_peer_streams_refuses_new_outbound_dispatch_without_enqueueing() {
    let home = tempfile::tempdir().expect("create teardown authority home");
    let live_now = crate::time::now_unix_i64();
    let live_sessions = Arc::new(LiveSessionRegistry::new());
    let membership = Arc::new(MembershipController::new(
        MembershipStore::open(home.path()).expect("open teardown authority store"),
        Arc::clone(&live_sessions),
    ));
    let exact = scope();
    let peer_key = active_live_peer(membership.store(), "teardown-live", live_now);
    assign(membership.store(), peer_key.clone(), &exact, true, 1, 0);
    let grant = membership
        .store()
        .admit(
            CarrierKind::Peeroxide,
            &TransportIdentity::parse(peer_key.clone()).expect("parse live teardown peer"),
            live_now,
        )
        .expect("admit live teardown peer");
    let streams = Arc::new(super::peer_streams::PeerStreamRegistry::new());
    let (_generation, mut receiver, _cancel) =
        streams.register_authorized_session(&peer_key, &grant);
    let controller = OutboundTaskDelegateController::new(home.path(), Arc::clone(&membership))
        .expect("construct teardown controller");
    controller.install_peer_streams(Arc::clone(&streams));

    let live_request =
        dispatch_request("op-before-teardown", "task-before-teardown", exact.clone());
    assert_eq!(
        controller
            .dispatch(&live_request)
            .expect("previously live dispatch succeeds")
            .state,
        OutboundTaskDelegateState::Accepted
    );
    drop(
        receiver
            .try_recv()
            .expect("previously live stream receives its one frame"),
    );

    controller.clear_peer_streams();
    let after_teardown = dispatch_request("op-after-teardown", "task-after-teardown", exact);
    assert!(
        controller.dispatch(&after_teardown).is_err(),
        "a cleared runtime must refuse before preparing or queueing a new outbound operation"
    );
    assert!(
        receiver.try_recv().is_err(),
        "teardown-gated dispatch must not enqueue a frame on the former live stream"
    );
}

#[test]
fn capped_outbound_dispatch_uses_fail_closed_tag_and_carries_exact_ceiling() {
    let home = tempfile::tempdir().expect("create capped dispatch authority home");
    let live_now = crate::time::now_unix_i64();
    let live_sessions = Arc::new(LiveSessionRegistry::new());
    let membership = Arc::new(MembershipController::new(
        MembershipStore::open(home.path()).expect("open authority store"),
        live_sessions,
    ));
    let exact = scope();
    let peer_key = active_live_peer(membership.store(), "capped-wire", live_now);
    assign(membership.store(), peer_key.clone(), &exact, true, 1, 0);
    let grant = membership
        .store()
        .admit(
            CarrierKind::Peeroxide,
            &TransportIdentity::parse(peer_key.clone()).expect("parse capped peer transport"),
            live_now,
        )
        .expect("admit capped peer");
    let streams = Arc::new(super::peer_streams::PeerStreamRegistry::new());
    let (_generation, mut receiver, _cancel) =
        streams.register_authorized_session(&peer_key, &grant);
    let controller = OutboundTaskDelegateController::new(home.path(), Arc::clone(&membership))
        .expect("construct capped outbound controller");
    controller.install_peer_streams(streams);
    let mut request = dispatch_request("op-capped", "task-capped", exact);
    request.model_hint = Some("advisory-only".into());
    request.max_output_tokens = Some(73);

    assert_eq!(
        controller
            .dispatch(&request)
            .expect("capped dispatch queues on exact authorized live peer")
            .state,
        OutboundTaskDelegateState::Accepted
    );
    let delivered = receiver.try_recv().expect("one capped frame delivered");
    assert_eq!(
        delivered.kind,
        super::heartbeat::FrameKind::TaskDelegateCapped
    );
    match &delivered.body {
        super::heartbeat::FrameBody::TaskDelegateCapped(body) => {
            assert_eq!(body.max_output_tokens, Some(73));
            assert_eq!(body.model_hint.as_deref(), Some("advisory-only"));
        }
        other => panic!("capped dispatch must not downgrade to legacy body: {other:?}"),
    }
}

#[test]
fn clear_waits_for_inflight_dispatch_admission_then_fences_later_dispatches() {
    let home = tempfile::tempdir().expect("create concurrent teardown authority home");
    let live_now = crate::time::now_unix_i64();
    let live_sessions = Arc::new(LiveSessionRegistry::new());
    let membership = Arc::new(MembershipController::new(
        MembershipStore::open(home.path()).expect("open concurrent teardown authority store"),
        Arc::clone(&live_sessions),
    ));
    let exact = scope();
    let peer_key = active_live_peer(membership.store(), "concurrent-teardown-live", live_now);
    assign(membership.store(), peer_key.clone(), &exact, true, 1, 0);
    let grant = membership
        .store()
        .admit(
            CarrierKind::Peeroxide,
            &TransportIdentity::parse(peer_key.clone()).expect("parse concurrent teardown peer"),
            live_now,
        )
        .expect("admit concurrent teardown peer");
    let streams = Arc::new(super::peer_streams::PeerStreamRegistry::new());
    let (_generation, mut receiver, _cancel) =
        streams.register_authorized_session(&peer_key, &grant);
    let controller = Arc::new(
        OutboundTaskDelegateController::new(home.path(), Arc::clone(&membership))
            .expect("construct concurrent teardown controller"),
    );
    controller.install_peer_streams(Arc::clone(&streams));

    let dispatch_entered = Arc::new(std::sync::Barrier::new(2));
    let dispatch_release = Arc::new(std::sync::Barrier::new(2));
    let entered_observer = Arc::clone(&dispatch_entered);
    let release_observer = Arc::clone(&dispatch_release);
    controller.set_admission_observer(Some(Arc::new(move || {
        entered_observer.wait();
        release_observer.wait();
    })));
    let request = dispatch_request("op-racing-clear", "task-racing-clear", exact.clone());
    let dispatch_controller = Arc::clone(&controller);
    let dispatch_thread = std::thread::spawn(move || dispatch_controller.dispatch(&request));
    dispatch_entered.wait();

    let (clear_started_tx, clear_started_rx) = std::sync::mpsc::channel();
    let (clear_finished_tx, clear_finished_rx) = std::sync::mpsc::channel();
    let clear_controller = Arc::clone(&controller);
    let clear_thread = std::thread::spawn(move || {
        clear_started_tx
            .send(())
            .expect("report clear attempt start");
        clear_controller.clear_peer_streams();
        clear_finished_tx.send(()).expect("report clear completion");
    });
    clear_started_rx
        .recv()
        .expect("clear thread begins while dispatch holds admission lock");
    assert!(
        matches!(
            clear_finished_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ),
        "clear must wait for the in-flight dispatch admission"
    );

    dispatch_release.wait();
    assert_eq!(
        dispatch_thread
            .join()
            .expect("dispatch thread panicked")
            .expect("in-flight dispatch succeeds")
            .state,
        OutboundTaskDelegateState::Accepted
    );
    clear_finished_rx
        .recv()
        .expect("clear completes only after dispatch admission returns");
    clear_thread.join().expect("clear thread panicked");
    controller.set_admission_observer(None);

    drop(
        receiver
            .try_recv()
            .expect("the in-flight dispatch queues exactly one frame"),
    );
    let after_clear = dispatch_request("op-after-racing-clear", "task-after-racing-clear", exact);
    assert!(
        controller.dispatch(&after_clear).is_err(),
        "a dispatch begun after clear returns must be unavailable"
    );
    assert!(
        receiver.try_recv().is_err(),
        "the post-clear dispatch must not enqueue another frame"
    );
}

#[test]
fn deny_that_wins_outbound_authority_gate_sends_nothing_and_leaves_no_replayable_prepare() {
    let home = tempfile::tempdir().expect("create outbound deny-race authority home");
    let live_now = crate::time::now_unix_i64();
    let live_sessions = Arc::new(LiveSessionRegistry::new());
    let membership = Arc::new(MembershipController::new(
        MembershipStore::open(home.path()).expect("open outbound deny-race authority store"),
        Arc::clone(&live_sessions),
    ));
    let exact = scope();
    let peer_key = active_live_peer(membership.store(), "deny-wins", live_now);
    let allowed = membership
        .set_task_delegate_outbound_assignment(&TaskDelegateOutboundAssignmentRequest {
            peer_key: peer_key.clone(),
            skill_id: exact.skill_id.clone(),
            channel_id: exact.channel_id.clone(),
            account_id: exact.account_id.clone(),
            allowed: true,
            priority: 1,
            expected_revision: 0,
        })
        .expect("commit initially allowed exact route");
    let grant = membership
        .store()
        .admit(
            CarrierKind::Peeroxide,
            &TransportIdentity::parse(peer_key.clone()).expect("parse deny-race peer transport"),
            live_now,
        )
        .expect("admit deny-race peer");
    let streams = Arc::new(super::peer_streams::PeerStreamRegistry::new());
    let (_generation, mut receiver, _cancel) =
        streams.register_authorized_session(&peer_key, &grant);
    let controller = Arc::new(
        OutboundTaskDelegateController::new(home.path(), Arc::clone(&membership))
            .expect("construct deny-race controller"),
    );
    controller.install_peer_streams(Arc::clone(&streams));

    let (setter_entered_tx, setter_entered_rx) = std::sync::mpsc::channel();
    let (setter_release_tx, setter_release_rx) = std::sync::mpsc::channel();
    let (dispatch_start_tx, dispatch_start_rx) = std::sync::mpsc::channel();
    let setter_release_rx = Arc::new(std::sync::Mutex::new(setter_release_rx));
    let release_observer = Arc::clone(&setter_release_rx);
    membership.store().set_task_delegate_gate_observers(
        Some(Arc::new(move || {
            setter_entered_tx
                .send(())
                .expect("report deny setter acquired authority gate");
            release_observer
                .lock()
                .expect("lock deny setter release receiver")
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("release deny setter authority gate");
        })),
        Some(Arc::new(move || {
            dispatch_start_tx
                .send(())
                .expect("report dispatch reached outbound authority gate");
        })),
    );
    let deny_membership = Arc::clone(&membership);
    let deny_scope = exact.clone();
    let deny_peer_key = peer_key.clone();
    let (deny_tx, deny_rx) = std::sync::mpsc::channel();
    let _deny_thread = std::thread::spawn(move || {
        let result = deny_membership.set_task_delegate_outbound_assignment(
            &TaskDelegateOutboundAssignmentRequest {
                peer_key: deny_peer_key,
                skill_id: deny_scope.skill_id,
                channel_id: deny_scope.channel_id,
                account_id: deny_scope.account_id,
                allowed: false,
                priority: allowed.committed.priority,
                expected_revision: allowed.committed.revision,
            },
        );
        deny_tx.send(result).expect("report deny setter result");
    });
    setter_entered_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("deny setter holds outbound authority gate");

    let request = dispatch_request("op-deny-wins", "task-deny-wins", exact.clone());
    let dispatch_controller = Arc::clone(&controller);
    let (dispatch_tx, dispatch_rx) = std::sync::mpsc::channel();
    let _dispatch_thread = std::thread::spawn(move || {
        dispatch_tx
            .send(dispatch_controller.dispatch(&request))
            .expect("report dispatch result");
    });
    dispatch_start_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("dispatch did not reach the shared outbound authority gate");
    assert!(
        matches!(
            dispatch_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "dispatch must wait while the earlier deny owns the authority gate"
    );

    setter_release_tx
        .send(())
        .expect("release deny setter authority gate");
    let denied = deny_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("deny setter did not complete")
        .expect("deny setter failed");
    assert!(!denied.committed.allowed);
    assert!(
        dispatch_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("receive denied dispatch result")
            .is_err(),
        "a deny committed before admission must refuse dispatch"
    );
    membership
        .store()
        .set_task_delegate_gate_observers(None, None);
    assert!(
        receiver.try_recv().is_err(),
        "the denied dispatch must enqueue no frame"
    );

    let restored = membership
        .set_task_delegate_outbound_assignment(&TaskDelegateOutboundAssignmentRequest {
            peer_key,
            skill_id: exact.skill_id.clone(),
            channel_id: exact.channel_id.clone(),
            account_id: exact.account_id.clone(),
            allowed: true,
            priority: denied.committed.priority,
            expected_revision: denied.committed.revision,
        })
        .expect("restore exact outbound route");
    assert!(restored.committed.allowed);
    assert_eq!(
        controller
            .dispatch(&dispatch_request("op-deny-wins", "task-deny-wins", exact))
            .expect("same operation succeeds because denied dispatch never prepared it")
            .state,
        OutboundTaskDelegateState::Accepted
    );
    drop(
        receiver
            .try_recv()
            .expect("restored route receives exactly one frame"),
    );
    assert!(
        controller
            .dispatch(&dispatch_request("op-deny-wins", "task-deny-wins", scope()))
            .is_err(),
        "accepted operation must not replay after the restored route dispatch"
    );
    assert!(
        receiver.try_recv().is_err(),
        "the rejected replay must not enqueue a second frame"
    );

    let (dispatch_entered_tx, dispatch_entered_rx) = std::sync::mpsc::channel();
    let (dispatch_release_tx, dispatch_release_rx) = std::sync::mpsc::channel();
    let dispatch_release_rx = Arc::new(std::sync::Mutex::new(dispatch_release_rx));
    let release_observer = Arc::clone(&dispatch_release_rx);
    membership
        .store()
        .set_task_delegate_outbound_gate_held_observer(Some(Arc::new(move || {
            dispatch_entered_tx
                .send(())
                .expect("report dispatch acquired outbound authority gate");
            release_observer
                .lock()
                .expect("lock dispatch release receiver")
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("release dispatch outbound authority gate");
        })));
    let dispatch_first_request =
        dispatch_request("op-dispatch-wins", "task-dispatch-wins", scope());
    let dispatch_controller = Arc::clone(&controller);
    let (dispatch_tx, dispatch_rx) = std::sync::mpsc::channel();
    let _dispatch_thread = std::thread::spawn(move || {
        dispatch_tx
            .send(dispatch_controller.dispatch(&dispatch_first_request))
            .expect("report dispatch-first result");
    });
    dispatch_entered_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("dispatch did not acquire the shared outbound authority gate");

    let deny_membership = Arc::clone(&membership);
    let (deny_started_tx, deny_started_rx) = std::sync::mpsc::channel();
    membership
        .store()
        .set_task_delegate_outbound_setter_contention_observer(Some(Arc::new(move || {
            deny_started_tx
                .send(())
                .expect("report dispatch-first deny contended on the setter gate");
        })));
    let (deny_tx, deny_rx) = std::sync::mpsc::channel();
    let deny_peer_key = restored.committed.peer_key.clone();
    let deny_scope = scope();
    let _deny_thread = std::thread::spawn(move || {
        let result = deny_membership.set_task_delegate_outbound_assignment(
            &TaskDelegateOutboundAssignmentRequest {
                peer_key: deny_peer_key,
                skill_id: deny_scope.skill_id,
                channel_id: deny_scope.channel_id,
                account_id: deny_scope.account_id,
                allowed: false,
                priority: restored.committed.priority,
                expected_revision: restored.committed.revision,
            },
        );
        deny_tx
            .send(result)
            .expect("report dispatch-first deny result");
    });
    deny_started_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("dispatch-first deny did not contend on the shared authority gate");
    assert!(
        matches!(
            deny_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "a deny begun after admission must wait for the accepted queue insertion"
    );
    dispatch_release_tx
        .send(())
        .expect("release dispatch outbound authority gate");
    assert_eq!(
        dispatch_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("dispatch-first result did not arrive")
            .expect("dispatch-first operation failed")
            .state,
        OutboundTaskDelegateState::Accepted
    );
    assert!(
        !deny_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("dispatch-first deny did not complete")
            .expect("dispatch-first deny failed")
            .committed
            .allowed
    );
    membership
        .store()
        .set_task_delegate_outbound_gate_held_observer(None);
    membership
        .store()
        .set_task_delegate_outbound_setter_contention_observer(None);
    drop(
        receiver
            .try_recv()
            .expect("dispatch-first admission queues exactly one frame"),
    );
    assert!(
        controller
            .dispatch(&dispatch_request(
                "op-dispatch-wins",
                "task-dispatch-wins",
                scope()
            ))
            .is_err(),
        "the accepted dispatch-first operation must remain non-replayable after deny"
    );
    assert!(
        receiver.try_recv().is_err(),
        "the rejected dispatch-first replay must not enqueue a second frame"
    );
}
