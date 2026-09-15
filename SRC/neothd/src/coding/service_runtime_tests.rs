use super::*;

use std::sync::mpsc;
use std::time::Duration;

struct ThreadMutexBlocker {
    release: Option<mpsc::Sender<()>>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ThreadMutexBlocker {
    fn hold(control: Arc<ServiceControl>) -> Self {
        let (locked_tx, locked_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::channel();
        let join = std::thread::spawn(move || {
            let thread_guard = control
                .thread
                .lock()
                .expect("coding service thread mutex poisoned");
            let _ = locked_tx.send(());
            let _ = release_rx.recv();
            drop(thread_guard);
        });
        locked_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("test blocker must acquire the service thread mutex");
        Self {
            release: Some(release_tx),
            join: Some(join),
        }
    }

    fn release_and_join(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(join) = self.join.take() {
            join.join().expect("test blocker thread must exit cleanly");
        }
    }
}

impl Drop for ThreadMutexBlocker {
    fn drop(&mut self) {
        self.release_and_join();
    }
}

fn service_config(root: &std::path::Path, config_path: std::path::PathBuf) -> CodingServiceConfig {
    CodingServiceConfig {
        database_path: root.join("views.db"),
        code_map_database_path: root.join("code_map.db"),
        neoth_home: root.join("neoth-home"),
        freedom_config_path: config_path,
        // The runtime must never use this cached value for a new run.
        freedom_config: crate::config::FreedomConfig::default(),
    }
}

fn start_request(root: &std::path::Path) -> CodingStartRequest {
    CodingStartRequest::new(
        "public runtime lifecycle fixture".to_owned(),
        root.to_path_buf(),
        "service-runtime-test".to_owned(),
        true,
        false,
        false,
    )
    .expect("fixture start request must be valid")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_start_reloads_exact_config_path_and_never_uses_cached_fallback() {
    let root = tempfile::tempdir().expect("fixture directory");
    let config_path = root.path().join("freedom.yaml");
    let database_path = root.path().join("views.db");
    let service = CodingService::spawn(service_config(root.path(), config_path.clone()))
        .expect("public service runtime starts without reading run config");

    let missing = service
        .start(start_request(root.path()))
        .await
        .err()
        .expect("missing exact run config must reject public start");
    let missing_text = format!("{missing:#}");
    assert!(missing_text.contains("reload coding configuration"));
    assert!(missing_text.contains(&config_path.display().to_string()));
    assert!(
        !database_path.exists(),
        "config admission failure must precede database/provider creation"
    );

    std::fs::write(&config_path, "autonomy: invalid-first-runtime-config\n")
        .expect("write first invalid config");
    let first = service
        .start(start_request(root.path()))
        .await
        .err()
        .expect("first malformed config must reject public start");
    let first_text = format!("{first:#}");
    assert!(first_text.contains("invalid-first-runtime-config"));
    assert!(!database_path.exists());

    std::fs::write(&config_path, "autonomy: invalid-second-runtime-config\n")
        .expect("replace config with distinct invalid bytes");
    let second = service
        .start(start_request(root.path()))
        .await
        .err()
        .expect("changed malformed config must reject public start");
    let second_text = format!("{second:#}");
    assert!(second_text.contains("invalid-second-runtime-config"));
    assert!(!second_text.contains("invalid-first-runtime-config"));
    assert!(
        !database_path.exists(),
        "each config failure must happen before a database/provider side effect"
    );

    service.shutdown_and_join().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_and_repeated_public_shutdown_join_runtime_thread_and_close_admission() {
    let root = tempfile::tempdir().expect("fixture directory");
    let service = CodingService::spawn(service_config(
        root.path(),
        root.path().join("freedom.yaml"),
    ))
    .expect("public service runtime starts");

    let concurrent = service.clone();
    let (first, second) = tokio::join!(service.shutdown_and_join(), concurrent.shutdown_and_join());
    first.expect("first public shutdown must join runtime thread");
    second.expect("concurrent public shutdown must wait for the same join");
    service
        .shutdown_and_join()
        .await
        .expect("repeated public shutdown must preserve completed state");

    assert!(service.control.shutdown_finished.load(Ordering::Acquire));
    assert!(
        service
            .control
            .thread
            .lock()
            .expect("coding service thread mutex poisoned")
            .is_none(),
        "a completed shutdown must have consumed the joined runtime thread"
    );
    let restart = service
        .start(start_request(root.path()))
        .await
        .err()
        .expect("public start must reject after shutdown admission closes");
    assert!(format!("{restart:#}").contains("shutting down"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_public_shutdown_caller_leaves_guardian_to_complete_owned_join() {
    let root = tempfile::tempdir().expect("fixture directory");
    let service = CodingService::spawn(service_config(
        root.path(),
        root.path().join("freedom.yaml"),
    ))
    .expect("public service runtime starts");
    let mut blocker = ThreadMutexBlocker::hold(Arc::clone(&service.control));

    let initiating_service = service.clone();
    let initiator = tokio::spawn(async move { initiating_service.shutdown_and_join().await });
    let guardian_ready = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if service
                .control
                .shutdown_guard_started
                .load(Ordering::Acquire)
                && service.control.shutdown_drained.load(Ordering::Acquire)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;

    initiator.abort();
    let aborted = initiator.await;
    blocker.release_and_join();

    let completion =
        tokio::time::timeout(Duration::from_secs(2), service.shutdown_and_join()).await;
    assert!(
        guardian_ready.is_ok(),
        "shutdown guardian must begin independently"
    );
    assert!(aborted.is_err() && aborted.unwrap_err().is_cancelled());
    completion
        .expect("second public caller must observe guardian completion")
        .expect("guardian-owned shutdown must join the runtime cleanly");
    assert!(service.control.shutdown_finished.load(Ordering::Acquire));
    assert!(
        service
            .control
            .thread
            .lock()
            .expect("coding service thread mutex poisoned")
            .is_none(),
        "guardian completion must include the actual runtime thread join"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audited_coding_worker_one_shot_wal_binds_to_selected_home() {
    let root = tempfile::tempdir().expect("fixture directory");
    let selected_home = root.path().join("selected-neoth-home");
    let config = crate::config::FreedomConfig {
        autonomy: crate::permissions::AutonomyLevel::Full,
        provider_kind: Some(crate::cli::init::ProviderKind::OpenaiCompat),
        provider_endpoint: Some("http://127.0.0.1:9".to_owned()),
        provider_model: Some("gpt-4o".to_owned()),
        ..Default::default()
    };
    let worker = build_audited_worker(&config, &selected_home, root.path().join("views.db"), None)
        .await
        .expect("construct real selected-home audited coding worker");
    let audit = worker
        .audit
        .lock()
        .expect("audited worker audit mutex")
        .take()
        .expect("one-shot audit owner");
    let provider_owner = worker
        .provider_owner
        .lock()
        .expect("audited worker provider owner mutex")
        .take()
        .expect("provider owner");
    drop(worker);
    audit
        .finish(provider_owner)
        .await
        .expect("finish selected-home one-shot audit");
    assert!(
        selected_home
            .join("wal")
            .read_dir()
            .expect("selected-home WAL exists")
            .next()
            .is_some(),
        "the one-shot coding audit must live beside the selected service home"
    );
}
