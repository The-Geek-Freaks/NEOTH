#![cfg(test)]

//! Production-path weekly reflection settlement and recovery regressions.

use std::path::{Path, PathBuf};

use super::*;
use crate::proactive::ProactiveQueue;
use crate::reflection::weekly_archive::{
    open_weekly_archive_session, WeeklyArchiveCandidate, WeeklyArchiveIntent,
};

const MONDAY: i64 = 1_700_438_400; // 2023-11-20T00:00:00Z
const SUNDAY: i64 = MONDAY - 86_400;

struct TestHome {
    _root: crate::test_env::CanonicalTempDir,
    path: PathBuf,
}

impl TestHome {
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
        #[cfg(not(any(unix, windows)))]
        let path = {
            let path = root.path().join("private-home");
            std::fs::create_dir(&path).unwrap();
            path
        };
        Self { _root: root, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn queue_path(home: &Path) -> PathBuf {
    home.join("proactive_queue.json")
}

fn intent_path(home: &Path, week: &str) -> PathBuf {
    home.join("reflections").join("weekly-intents").join(format!("{week}.json"))
}

fn archive_path(home: &Path, week: &str) -> PathBuf {
    home.join("reflections").join(format!("{week}.jsonl"))
}

fn insert_topic(home: &Path, now_unix: i64, event_id: i64, text: &str) {
    let conn = crate::memory::store::open(&home.join("views.db")).unwrap();
    conn.execute(
        "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            event_id,
            crate::wal::events::EVENT_TYPE_RAW_TEXT as i64,
            now_unix * 1_000_000_000 - 3_600_000_000_000i64,
            text,
            format!("weekly-{event_id}"),
        ],
    )
    .unwrap();
}

fn create_intent_only(home: &Path, week: &str, generated_ts_unix: i64, topic: &str) -> WeeklyArchiveIntent {
    let mut session = open_weekly_archive_session(home, week).unwrap();
    let body = crate::reflection::build_reflection_item(
        week,
        &[topic.to_owned()],
        generated_ts_unix,
    )
    .unwrap()
    .body;
    session
        .load_or_create_intent(WeeklyArchiveCandidate {
            generated_ts_unix,
            topics: vec![topic.to_owned()],
            body,
        })
        .unwrap()
}

fn queue_items(home: &Path) -> Vec<crate::proactive::ProactiveItem> {
    ProactiveQueue::load_from(&queue_path(home)).unwrap().peek().to_vec()
}

#[test]
fn weekly_first_tick_archives_queues_and_persists_state() {
    let home = TestHome::new();
    insert_topic(home.path(), MONDAY, 1, "kubernetes kubernetes rollout planning");
    let week = iso_week_tag_from_unix(MONDAY);

    assert!(run_reflection_tick_once(home.path(), MONDAY, 0).unwrap());

    let archive = std::fs::read_to_string(archive_path(home.path(), &week)).unwrap();
    assert_eq!(archive.lines().count(), 1);
    assert!(archive.contains("kubernetes"));
    let queue = queue_items(home.path());
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].dedup_key, format!("reflection:weekly:{week}"));
    assert_eq!(load_tick_state(home.path()).unwrap().last_emitted_unix, MONDAY);
}

#[test]
fn weekly_intent_only_retry_succeeds_without_database() {
    let home = TestHome::new();
    let week = iso_week_tag_from_unix(MONDAY);
    let frozen = create_intent_only(home.path(), &week, MONDAY, "frozen-topic");
    assert!(!home.path().join("views.db").exists());

    assert!(run_reflection_tick_once(home.path(), MONDAY, 86_400).unwrap());

    assert!(archive_path(home.path(), &week).exists());
    assert_eq!(queue_items(home.path()), vec![frozen.to_proactive_item(MONDAY)]);
    assert_eq!(load_tick_state(home.path()).unwrap().last_emitted_unix, MONDAY);
}

#[test]
fn weekly_archive_before_queue_failure_retries_frozen_intent_after_topics_change() {
    let home = TestHome::new();
    let week = iso_week_tag_from_unix(MONDAY);
    insert_topic(home.path(), MONDAY, 1, "kubernetes kubernetes original topic");
    std::fs::create_dir(queue_path(home.path())).unwrap();

    assert!(run_reflection_tick_once(home.path(), MONDAY, 0).is_err());
    let frozen: WeeklyArchiveIntent = serde_json::from_slice(
        &std::fs::read(intent_path(home.path(), &week)).unwrap(),
    )
    .unwrap();
    assert!(archive_path(home.path(), &week).exists());
    assert!(!tick_state_path(home.path()).exists());

    insert_topic(home.path(), MONDAY, 2, "terraform terraform changed topic");
    std::fs::remove_dir(queue_path(home.path())).unwrap();
    assert!(run_reflection_tick_once(home.path(), MONDAY + 1, 0).unwrap());

    let queue = queue_items(home.path());
    assert_eq!(queue, vec![frozen.to_proactive_item(frozen.generated_ts_unix)]);
    let archive = std::fs::read_to_string(archive_path(home.path(), &week)).unwrap();
    assert!(archive.contains("kubernetes"));
    assert!(!archive.contains("terraform"));
}

#[test]
fn weekly_queue_then_state_failure_recovers_after_drain_without_duplicate() {
    let home = TestHome::new();
    let week = iso_week_tag_from_unix(MONDAY);
    insert_topic(home.path(), MONDAY, 1, "observability observability tracing");
    std::fs::create_dir_all(tick_state_path(home.path())).unwrap();

    assert!(run_reflection_tick_once(home.path(), MONDAY, 0).is_err());
    assert_eq!(queue_items(home.path()).len(), 1);
    let mut queue = ProactiveQueue::load_from(&queue_path(home.path())).unwrap();
    assert_eq!(queue.drain(MONDAY, 3).len(), 1);
    queue.save_to(&queue_path(home.path())).unwrap();

    std::fs::remove_dir(tick_state_path(home.path())).unwrap();
    assert!(!run_reflection_tick_once(home.path(), MONDAY + 1, 0).unwrap());
    assert!(queue_items(home.path()).is_empty(), "drained receipt must prevent requeue");
    assert_eq!(load_tick_state(home.path()).unwrap().last_emitted_unix, MONDAY + 1);
    assert_eq!(
        std::fs::read_to_string(archive_path(home.path(), &week)).unwrap().lines().count(),
        1,
    );
}

#[test]
fn weekly_legacy_same_key_body_conflict_preserves_queued_item() {
    let home = TestHome::new();
    let week = iso_week_tag_from_unix(MONDAY);
    let intent = create_intent_only(home.path(), &week, MONDAY, "canonical-topic");
    let mut conflicting = intent.to_proactive_item(MONDAY);
    conflicting.body = "legacy conflicting body".to_owned();
    let mut queue = ProactiveQueue::new();
    queue.enqueue(conflicting.clone()).unwrap();
    queue.save_to(&queue_path(home.path())).unwrap();

    assert!(run_reflection_tick_once(home.path(), MONDAY, 0).is_err());
    assert_eq!(queue_items(home.path()), vec![conflicting]);
    assert!(!tick_state_path(home.path()).exists());
}

#[test]
fn weekly_oldest_sunday_intent_recovers_on_monday_without_current_candidate_or_database() {
    let home = TestHome::new();
    let sunday_week = iso_week_tag_from_unix(SUNDAY);
    let monday_week = iso_week_tag_from_unix(MONDAY);
    assert_ne!(sunday_week, monday_week);
    let old = create_intent_only(home.path(), &sunday_week, SUNDAY, "sunday-backlog");
    assert!(!home.path().join("views.db").exists());

    assert!(run_reflection_tick_once(home.path(), MONDAY, 86_400).unwrap());

    assert!(archive_path(home.path(), &sunday_week).exists());
    assert!(!intent_path(home.path(), &monday_week).exists());
    assert_eq!(queue_items(home.path()), vec![old.to_proactive_item(SUNDAY)]);
}

#[test]
fn weekly_malformed_oldest_intent_cannot_be_bypassed_by_current_week() {
    let home = TestHome::new();
    let sunday_week = iso_week_tag_from_unix(SUNDAY);
    let monday_week = iso_week_tag_from_unix(MONDAY);
    insert_topic(home.path(), MONDAY, 1, "current-topic current-topic production");
    std::fs::create_dir_all(intent_path(home.path(), &sunday_week).parent().unwrap()).unwrap();
    std::fs::write(intent_path(home.path(), &sunday_week), b"{malformed intent").unwrap();

    assert!(run_reflection_tick_once(home.path(), MONDAY, 0).is_err());
    assert!(!intent_path(home.path(), &monday_week).exists());
    assert!(!archive_path(home.path(), &monday_week).exists());
    assert!(!queue_path(home.path()).exists());
}

#[test]
fn weekly_matching_old_receipt_skips_to_current_week_production() {
    let home = TestHome::new();
    let sunday_week = iso_week_tag_from_unix(SUNDAY);
    let monday_week = iso_week_tag_from_unix(MONDAY);
    let old = create_intent_only(home.path(), &sunday_week, SUNDAY, "settled-sunday");
    let mut old_session = open_weekly_archive_session(home.path(), &sunday_week).unwrap();
    old_session.append_once(&old).unwrap();
    drop(old_session);
    ProactiveQueue::modify(&queue_path(home.path()), |queue| {
        let result = queue.enqueue_weekly_reflection_once(&old.to_proactive_item(SUNDAY), &old.producer_key);
        (result.as_ref().is_ok_and(|inserted| *inserted), result)
    })
    .unwrap()
    .unwrap();
    insert_topic(home.path(), MONDAY, 1, "current-production current-production topic");

    assert!(run_reflection_tick_once(home.path(), MONDAY, 0).unwrap());
    assert!(archive_path(home.path(), &sunday_week).exists());
    assert!(archive_path(home.path(), &monday_week).exists());
    assert_eq!(queue_items(home.path()).len(), 2);
}

#[test]
fn weekly_no_source_no_topics_and_window_suppression_preserve_weekly_data() {
    let no_source = TestHome::new();
    let week = iso_week_tag_from_unix(MONDAY);
    assert!(!run_reflection_tick_once(no_source.path(), MONDAY, 0).unwrap());
    assert!(!intent_path(no_source.path(), &week).exists());
    assert!(!archive_path(no_source.path(), &week).exists());
    assert!(!queue_path(no_source.path()).exists());

    let no_topics = TestHome::new();
    crate::memory::store::open(&no_topics.path().join("views.db")).unwrap();
    assert!(!run_reflection_tick_once(no_topics.path(), MONDAY, 0).unwrap());
    assert!(!intent_path(no_topics.path(), &week).exists());
    assert!(!archive_path(no_topics.path(), &week).exists());
    assert!(!queue_path(no_topics.path()).exists());

    let suppressed = TestHome::new();
    insert_topic(suppressed.path(), MONDAY, 1, "windowed windowed topic");
    save_tick_state(
        suppressed.path(),
        &SubconsciousTickState { last_emitted_unix: MONDAY },
    )
    .unwrap();
    assert!(!run_reflection_tick_once(suppressed.path(), MONDAY + 1, 86_400).unwrap());
    assert!(!intent_path(suppressed.path(), &week).exists());
    assert!(!archive_path(suppressed.path(), &week).exists());
    assert!(!queue_path(suppressed.path()).exists());
}

#[test]
fn weekly_repeat_writes_independent_fresh_staged_observation_without_duplicate_queue() {
    let home = TestHome::new();
    insert_topic(home.path(), MONDAY, 1, "staging staging observation");

    assert!(run_reflection_tick_once(home.path(), MONDAY, 0).unwrap());
    assert!(!run_reflection_tick_once(home.path(), MONDAY + 1, 0).unwrap());

    assert_eq!(queue_items(home.path()).len(), 1);
    let observations = crate::reflection::load_staged_observations(home.path());
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].generated_ts_unix, MONDAY);
    assert_eq!(observations[1].generated_ts_unix, MONDAY + 1);
    assert!(observations.iter().all(|observation| observation.surface_only));
}
