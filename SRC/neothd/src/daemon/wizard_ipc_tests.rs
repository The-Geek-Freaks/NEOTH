use tokio::io::AsyncWriteExt as _;

use super::*;
use crate::wizard::recommend::ChannelRecommendation;

fn snapshot(response: WizardResponse) -> WizardSnapshot {
    match response {
        WizardResponse::SessionSnapshot { snapshot }
        | WizardResponse::Progress { snapshot }
        | WizardResponse::CommitReady { snapshot }
        | WizardResponse::Completed { snapshot } => snapshot,
        WizardResponse::Rejected { rejection } => {
            panic!("unexpected rejection: {:?}", rejection.code)
        }
    }
}

fn rejection(response: WizardResponse) -> WizardRejectionCode {
    match response {
        WizardResponse::Rejected { rejection } => rejection.code,
        response => panic!("expected rejection, got {response:?}"),
    }
}

fn next(snapshot: &WizardSnapshot) -> WizardSequence {
    WizardSequence(snapshot.accepted_sequence.0 + 1)
}

fn test_state_without_owner(
    home: &std::path::Path,
) -> (State, tokio::sync::mpsc::Receiver<WizardCommand>) {
    let service = WizardSessionService::new(home).unwrap();
    let (updates, _) = tokio::sync::watch::channel(service.snapshot.clone());
    let (commands, receiver) = tokio::sync::mpsc::channel(COMMAND_CAPACITY);
    (
        State {
            token: "expected-bearer".to_owned(),
            commands,
            updates,
        },
        receiver,
    )
}

#[test]
fn prepared_hash_requires_exact_lowercase_sha256() {
    assert!(lower_hex_64(&"a".repeat(64)));
    assert!(!lower_hex_64(&"A".repeat(64)));
    assert!(!lower_hex_64(&"a".repeat(63)));
    assert!(!lower_hex_64(&"g".repeat(64)));
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn wrong_bearer_is_rejected_before_owner_mutation() {
    let home = tempfile::tempdir().unwrap();
    let (listener_task, guard) = bind_and_serve(home.path()).unwrap();
    let error = request_for_test(
        home.path(),
        WizardRequest::OpenOrResume,
        Some("wrong-bearer"),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("rejected request"));

    let client = WizardIpcClient::discover(home.path()).unwrap();
    let opened = snapshot(client.open_or_resume().await.unwrap());
    assert_eq!(opened.accepted_sequence, WizardSequence(0));
    assert_eq!(opened.terminal, WizardTerminalState::Active);
    guard.stop();
    listener_task.await.unwrap().unwrap();
    drop(guard);
}

#[tokio::test]
async fn terminal_response_write_failure_still_stops_admission() {
    let home = tempfile::tempdir().unwrap();
    let service = WizardSessionService::new(home.path()).unwrap();
    let initial = service.snapshot.clone();
    let (updates, _) = tokio::sync::watch::channel(initial.clone());
    let shutdown = std::sync::Arc::new(Shutdown::new());
    let (commands, owner) =
        spawn_owner(service, updates.clone(), std::sync::Arc::clone(&shutdown)).unwrap();
    let state = State {
        token: "terminal-bearer".to_owned(),
        commands,
        updates,
    };
    let body = serde_json::to_vec(&WizardRequest::Cancel {
        session_id: initial.session_id,
        boot_id: initial.boot_id,
        next_sequence: WizardSequence(1),
        from_step: WizardStepId::Welcome,
    })
    .unwrap();
    let (mut peer, server) = tokio::io::duplex(2048);
    let handler = tokio::spawn(handle(server, state, std::sync::Arc::clone(&shutdown)));
    let request = format!(
        "POST /wizard/v1/request HTTP/1.1\r\nAuthorization: Bearer terminal-bearer\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    peer.write_all(request.as_bytes()).await.unwrap();
    peer.write_all(&body).await.unwrap();
    drop(peer);

    assert!(handler.await.unwrap().is_err());
    assert!(shutdown.stopped());
    tokio::task::spawn_blocking(move || owner.join())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stalled_owner_bounds_command_admission_and_reply_waits() {
    let home = tempfile::tempdir().unwrap();
    let (state, mut receiver) = test_state_without_owner(home.path());
    for _ in 0..COMMAND_CAPACITY {
        let (occupied_reply, _) = tokio::sync::oneshot::channel();
        state
            .commands
            .send(WizardCommand {
                request: WizardRequest::OpenOrResume,
                reply: occupied_reply,
            })
            .await
            .unwrap();
    }
    let admission = tokio::time::timeout(
        std::time::Duration::from_secs(6),
        dispatch(&state, WizardRequest::OpenOrResume),
    )
    .await
    .expect("stalled owner admission must honor its five-second deadline")
    .unwrap_err();
    assert!(format!("{admission:#}").contains("admission deadline"));

    for _ in 0..COMMAND_CAPACITY {
        let _ = receiver.recv().await;
    }
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(6),
        dispatch(&state, WizardRequest::OpenOrResume),
    )
    .await
    .expect("stalled owner reply must honor its five-second deadline")
    .unwrap_err();
    assert!(format!("{reply:#}").contains("response deadline"));
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn fresh_home_open_or_resume_creates_only_pending_transaction() {
    let home = tempfile::tempdir().unwrap();
    let (listener_task, guard) = bind_and_serve(home.path()).unwrap();
    let client = WizardIpcClient::discover(home.path()).unwrap();
    let opened = snapshot(client.open_or_resume().await.unwrap());

    assert_eq!(opened.accepted_sequence, WizardSequence(0));
    assert_eq!(opened.terminal, WizardTerminalState::Active);
    assert!(home.path().join(".gui-init").join("pending.json").is_file());
    assert!(!home.path().join("freedom.yaml").exists());
    assert!(!home.path().join("credentials.yaml").exists());
    assert!(!home.path().join(".initialized").exists());
    assert!(!home.path().join("wal").exists());

    guard.stop();
    listener_task.await.unwrap().unwrap();
    drop(guard);
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn reopen_preserves_sequence_and_rejects_stale_identity_or_status_injection() {
    let home = tempfile::tempdir().unwrap();
    let (listener_task, guard) = bind_and_serve(home.path()).unwrap();
    let client = WizardIpcClient::discover(home.path()).unwrap();
    let opened = snapshot(client.open_or_resume().await.unwrap());
    let accepted = snapshot(
        client
            .submit(
                opened.session_id.clone(),
                opened.boot_id.clone(),
                next(&opened),
                WizardIpcMessage::ChannelOverride {
                    channel: ChannelRecommendation::Cli,
                },
            )
            .await
            .unwrap(),
    );
    let reopened = snapshot(client.open_or_resume().await.unwrap());
    assert_eq!(reopened.session_id, opened.session_id);
    assert_eq!(reopened.boot_id, opened.boot_id);
    assert_eq!(reopened.accepted_sequence, accepted.accepted_sequence);

    assert_eq!(
        rejection(
            client
                .submit(
                    opened.session_id.clone(),
                    WizardBootId(format!("{}-stale", opened.boot_id.0)),
                    next(&accepted),
                    WizardIpcMessage::ChannelOverride {
                        channel: ChannelRecommendation::Cli
                    }
                )
                .await
                .unwrap()
        ),
        WizardRejectionCode::StaleBoot
    );
    assert_eq!(
        rejection(
            client
                .submit(
                    WizardSessionId("wrong-session".to_owned()),
                    opened.boot_id.clone(),
                    next(&accepted),
                    WizardIpcMessage::ChannelOverride {
                        channel: ChannelRecommendation::Cli
                    }
                )
                .await
                .unwrap()
        ),
        WizardRejectionCode::WrongSession
    );
    assert_eq!(
        rejection(
            client
                .submit(
                    opened.session_id.clone(),
                    opened.boot_id.clone(),
                    accepted.accepted_sequence,
                    WizardIpcMessage::ChannelOverride {
                        channel: ChannelRecommendation::Cli
                    }
                )
                .await
                .unwrap()
        ),
        WizardRejectionCode::OutOfOrder
    );
    assert_eq!(
        rejection(
            client
                .submit(
                    opened.session_id,
                    opened.boot_id,
                    next(&accepted),
                    WizardIpcMessage::StepStarted {
                        step: WizardStepId::Provider
                    }
                )
                .await
                .unwrap()
        ),
        WizardRejectionCode::NotReady
    );

    guard.stop();
    listener_task.await.unwrap().unwrap();
    drop(guard);
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn cancellation_returns_terminal_snapshot_and_drains_listener() {
    let home = tempfile::tempdir().unwrap();
    let (listener_task, guard) = bind_and_serve(home.path()).unwrap();
    let client = WizardIpcClient::discover(home.path()).unwrap();
    let opened = snapshot(client.open_or_resume().await.unwrap());
    let next_sequence = next(&opened);
    let cancelled = snapshot(
        client
            .cancel(
                opened.session_id,
                opened.boot_id,
                next_sequence,
                WizardStepId::Welcome,
            )
            .await
            .unwrap(),
    );

    assert_eq!(cancelled.terminal, WizardTerminalState::Cancelled);
    assert!(home.path().join(".gui-init").join("pending.json").is_file());
    assert!(!home.path().join(".initialized").exists());
    tokio::time::timeout(std::time::Duration::from_secs(1), listener_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(guard);
    assert!(WizardIpcClient::discover(home.path()).is_err());
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn prepared_config_hash_commits_marker_then_returns_completed_and_drains() {
    let home = tempfile::tempdir().unwrap();
    let config = b"operator_id: alice\n";
    std::fs::write(home.path().join("freedom.yaml"), config).unwrap();
    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(config).into();
    let (listener_task, guard) = bind_and_serve(home.path()).unwrap();
    let client = WizardIpcClient::discover(home.path()).unwrap();
    let opened = snapshot(client.open_or_resume().await.unwrap());
    let next_sequence = next(&opened);
    let completed = snapshot(
        client
            .prepare_for_commit(opened.session_id, opened.boot_id, next_sequence, digest)
            .await
            .unwrap(),
    );

    assert_eq!(completed.terminal, WizardTerminalState::Completed);
    assert!(home.path().join(".initialized").is_file());
    assert!(!home.path().join(".gui-init").join("pending.json").exists());
    tokio::time::timeout(std::time::Duration::from_secs(1), listener_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(guard);
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn restart_resumes_pending_transaction_but_rejects_old_boot() {
    let home = tempfile::tempdir().unwrap();
    let (first_task, first_guard) = bind_and_serve(home.path()).unwrap();
    let first_client = WizardIpcClient::discover(home.path()).unwrap();
    let first = snapshot(first_client.open_or_resume().await.unwrap());
    first_guard.stop();
    first_task.await.unwrap().unwrap();
    drop(first_guard);

    let (second_task, second_guard) = bind_and_serve(home.path()).unwrap();
    let second_client = WizardIpcClient::discover(home.path()).unwrap();
    let second = snapshot(second_client.open_or_resume().await.unwrap());
    assert_eq!(second.session_id, first.session_id);
    assert_ne!(second.boot_id, first.boot_id);
    assert_eq!(
        rejection(
            second_client
                .wait_for_change(first.session_id, first.boot_id, first.accepted_sequence)
                .await
                .unwrap()
        ),
        WizardRejectionCode::StaleBoot
    );

    let next_sequence = next(&second);
    let _ = second_client
        .cancel(
            second.session_id,
            second.boot_id,
            next_sequence,
            WizardStepId::Welcome,
        )
        .await
        .unwrap();
    second_task.await.unwrap().unwrap();
    drop(second_guard);
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn second_bootstrap_bind_is_refused_while_the_first_owner_holds_the_pid_lease() {
    let home = tempfile::tempdir().unwrap();
    let (listener_task, guard) = bind_and_serve(home.path()).unwrap();

    assert!(
        bind_and_serve(home.path()).is_err(),
        "a second bootstrap endpoint must not publish beside the active native PID owner"
    );

    guard.stop();
    listener_task.await.unwrap().unwrap();
    drop(guard);
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn idle_long_poll_returns_before_the_client_deadline() {
    let home = tempfile::tempdir().unwrap();
    let (listener_task, guard) = bind_and_serve(home.path()).unwrap();
    let client = WizardIpcClient::discover(home.path()).unwrap();
    let opened = snapshot(client.open_or_resume().await.unwrap());

    let idle = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        client.wait_for_change(
            opened.session_id.clone(),
            opened.boot_id.clone(),
            opened.accepted_sequence,
        ),
    )
    .await
    .expect("server long-poll timeout must precede the five-second client deadline")
    .unwrap();
    let idle = snapshot(idle);
    assert_eq!(idle.session_id, opened.session_id);
    assert_eq!(idle.boot_id, opened.boot_id);
    assert_eq!(idle.accepted_sequence, opened.accepted_sequence);

    guard.stop();
    listener_task.await.unwrap().unwrap();
    drop(guard);
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn long_poll_receives_the_next_accepted_mutation() {
    let home = tempfile::tempdir().unwrap();
    let (listener_task, guard) = bind_and_serve(home.path()).unwrap();
    let client = std::sync::Arc::new(WizardIpcClient::discover(home.path()).unwrap());
    let opened = snapshot(client.open_or_resume().await.unwrap());
    let wait_client = std::sync::Arc::clone(&client);
    let wait_session = opened.session_id.clone();
    let wait_boot = opened.boot_id.clone();
    let after_sequence = opened.accepted_sequence;
    let waiter = tokio::spawn(async move {
        wait_client
            .wait_for_change(wait_session, wait_boot, after_sequence)
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let next_sequence = next(&opened);
    let accepted = snapshot(
        client
            .submit(
                opened.session_id,
                opened.boot_id,
                next_sequence,
                WizardIpcMessage::ChannelOverride {
                    channel: ChannelRecommendation::Cli,
                },
            )
            .await
            .unwrap(),
    );
    let observed = snapshot(waiter.await.unwrap().unwrap());
    assert_eq!(observed.accepted_sequence, accepted.accepted_sequence);

    guard.stop();
    listener_task.await.unwrap().unwrap();
    drop(guard);
}
