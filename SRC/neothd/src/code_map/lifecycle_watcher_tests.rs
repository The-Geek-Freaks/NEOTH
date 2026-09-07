//! Acceptance coverage for the daemon-owned code-map watcher boundary.
//!
//! These tests intentionally use temporary physical repositories and the
//! public(crate) lifecycle/watcher API. They do not inject synthetic notify
//! events: a changed durable generation proves that the real watcher or its
//! periodic strong reconciliation reached the lifecycle core.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::code_map::lifecycle_watcher::{CodeMapLifecycleWatcher, CodeMapLifecycleWatchers};
use crate::code_map::{CodeMapLifecycleState, LifecycleGeneration, inspect};
use crate::config::CodeMapLifecycleConfig;

const EVENT_DEBOUNCE: Duration = Duration::from_millis(150);
const EVENT_RECONCILIATION: Duration = Duration::from_secs(3);
const PERIODIC_RECONCILIATION: Duration = Duration::from_millis(150);
const CONFIG_RECONCILIATION_SECS: u64 = 30;
const WAIT_TIMEOUT: Duration = Duration::from_secs(8);

fn generation(database: &Path, root: &Path) -> LifecycleGeneration {
    match inspect(database, root).state {
        CodeMapLifecycleState::Fresh { snapshot }
        | CodeMapLifecycleState::Stale { snapshot }
        | CodeMapLifecycleState::Incomplete { snapshot } => snapshot,
        CodeMapLifecycleState::Refreshing {
            prior: Some(snapshot),
            ..
        } => snapshot,
        state => panic!("expected an indexed lifecycle snapshot, found {state:?}"),
    }
}

fn wait_for_generation_after(database: &Path, root: &Path, previous: i64) -> LifecycleGeneration {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        let snapshot = generation(database, root);
        if snapshot.index_generation > previous {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for code-map generation after {previous}; current generation is {}",
            snapshot.index_generation
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn managed_config(root: PathBuf) -> CodeMapLifecycleConfig {
    CodeMapLifecycleConfig {
        enabled: true,
        managed_roots: vec![root],
        debounce_millis: EVENT_DEBOUNCE.as_millis().try_into().unwrap(),
        reconciliation_interval_secs: CONFIG_RECONCILIATION_SECS,
    }
}

#[test]
fn first_start_indexes_the_explicit_physical_root() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().join("repo");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
    let database = workspace.path().join("instance/code_map.db");

    let mut watcher = CodeMapLifecycleWatcher::start(
        database.clone(),
        root.clone(),
        EVENT_DEBOUNCE,
        EVENT_RECONCILIATION,
        None,
        0,
    )
    .unwrap();

    let first = generation(&database, &root);
    assert_eq!(first.index_generation, 1);
    assert_eq!(first.index_generation, first.graph_generation);
    assert!(database.is_file());
    watcher.shutdown().unwrap();
}

#[test]
fn a_burst_of_real_filesystem_changes_coalesces_to_one_generation() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("lib.rs"), "pub fn seed() {}\n").unwrap();
    let database = workspace.path().join("instance/code_map.db");
    let mut watcher = CodeMapLifecycleWatcher::start(
        database.clone(),
        root.clone(),
        EVENT_DEBOUNCE,
        EVENT_RECONCILIATION,
        None,
        0,
    )
    .unwrap();
    let initial = generation(&database, &root);

    // Every write is inside one debounce window; notifications may be noisy,
    // but the worker must refresh from the final dirty deadline only once.
    for value in 0..4 {
        fs::write(
            root.join("lib.rs"),
            format!("pub fn changed_{value}() {{}}\n"),
        )
        .unwrap();
    }
    let refreshed = wait_for_generation_after(&database, &root, initial.index_generation);
    thread::sleep(EVENT_DEBOUNCE + Duration::from_millis(175));
    let settled = generation(&database, &root);
    assert_eq!(refreshed.index_generation, initial.index_generation + 1);
    assert_eq!(settled.index_generation, refreshed.index_generation);
    assert_eq!(settled.graph_generation, settled.index_generation);
    watcher.shutdown().unwrap();
}

#[test]
fn edit_add_and_remove_rebuild_the_managed_root_without_touching_a_sibling() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().join("managed");
    let sibling = workspace.path().join("unmanaged");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&sibling).unwrap();
    fs::write(root.join("lib.rs"), "pub fn first() {}\n").unwrap();
    fs::write(sibling.join("lib.rs"), "pub fn sibling() {}\n").unwrap();
    let database = workspace.path().join("instance/code_map.db");
    let mut watcher = CodeMapLifecycleWatcher::start(
        database.clone(),
        root.clone(),
        EVENT_DEBOUNCE,
        EVENT_RECONCILIATION,
        None,
        0,
    )
    .unwrap();
    let first = generation(&database, &root);

    fs::write(root.join("lib.rs"), "pub fn edited() {}\n").unwrap();
    let edited = wait_for_generation_after(&database, &root, first.index_generation);
    fs::write(root.join("added.rs"), "pub fn added() {}\n").unwrap();
    let added = wait_for_generation_after(&database, &root, edited.index_generation);
    fs::remove_file(root.join("added.rs")).unwrap();
    let removed = wait_for_generation_after(&database, &root, added.index_generation);

    assert!(edited.index_generation > first.index_generation);
    assert!(added.index_generation > edited.index_generation);
    assert!(removed.index_generation > added.index_generation);
    assert!(matches!(
        inspect(&database, &sibling).state,
        CodeMapLifecycleState::Unmapped
    ));
    watcher.shutdown().unwrap();
}

#[test]
fn periodic_reconciliation_detects_a_change_even_when_event_delivery_is_not_used_as_proof() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("lib.rs"), "pub fn before() {}\n").unwrap();
    let database = workspace.path().join("instance/code_map.db");
    let mut watcher = CodeMapLifecycleWatcher::start(
        database.clone(),
        root.clone(),
        EVENT_DEBOUNCE,
        PERIODIC_RECONCILIATION,
        None,
        0,
    )
    .unwrap();
    let initial = generation(&database, &root);

    // This exercise deliberately asserts only a durable generation change.
    // Whether the platform delivers a notify event is immaterial: the short
    // strong-reconciliation cadence is the missed-event correctness path.
    fs::write(root.join("lib.rs"), "pub fn reconciled() {}\n").unwrap();
    let reconciled = wait_for_generation_after(&database, &root, initial.index_generation);
    assert_eq!(reconciled.graph_generation, reconciled.index_generation);
    assert!(reconciled.index_generation > initial.index_generation);
    watcher.shutdown().unwrap();
}

#[test]
fn disabling_or_removing_a_root_cancels_and_joins_before_returning() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("lib.rs"), "pub fn live() {}\n").unwrap();
    let database = workspace.path().join("instance/code_map.db");
    let config = managed_config(root.clone());
    let mut watchers = CodeMapLifecycleWatchers::start(&database, &config).unwrap();
    let canonical_root = fs::canonicalize(&root).unwrap();
    assert_eq!(
        watchers.roots().collect::<Vec<_>>(),
        vec![canonical_root.as_path()]
    );

    let started = Instant::now();
    watchers.shutdown().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "watcher shutdown must cancel and join bounded work"
    );
    assert!(watchers.is_disabled());
    assert!(watchers.roots().next().is_none());

    let disabled = CodeMapLifecycleConfig::default();
    let mut replacement = CodeMapLifecycleWatchers::start(&database, &disabled).unwrap();
    assert!(replacement.is_disabled());
    replacement.shutdown().unwrap();
}

#[test]
fn rejected_lifecycle_candidate_leaves_the_accepted_watcher_set_and_epoch_intact() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("lib.rs"), "pub fn accepted() {}\n").unwrap();
    let database = workspace.path().join("instance/code_map.db");
    let accepted = managed_config(root.clone());
    let mut watchers = CodeMapLifecycleWatchers::start(&database, &accepted).unwrap();
    let before = generation(&database, &root);

    // Simulate reload validation before watcher replacement. The malformed
    // candidate cannot be accepted, so the existing watcher remains owned by
    // the prior snapshot and its generation must never roll back.
    let invalid = CodeMapLifecycleConfig {
        enabled: true,
        managed_roots: Vec::new(),
        ..CodeMapLifecycleConfig::default()
    };
    assert!(invalid.validate().is_err());
    let canonical_root = fs::canonicalize(&root).unwrap();
    assert_eq!(
        watchers.roots().collect::<Vec<_>>(),
        vec![canonical_root.as_path()]
    );

    fs::write(root.join("lib.rs"), "pub fn still_accepted() {}\n").unwrap();
    let after = wait_for_generation_after(&database, &root, before.index_generation);
    assert!(after.index_generation > before.index_generation);
    assert!(after.graph_generation >= before.graph_generation);
    watchers.shutdown().unwrap();
}
