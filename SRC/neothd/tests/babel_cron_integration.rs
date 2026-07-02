//! GOLD-DELTA-12 — Babel observer end-to-end integration.
//!
//! Exercises the REAL daemon path: `spawn_babel_cron_loop` → WAL segment
//! scan → frame mapping → window close → SQLite row / SSE fan-out.
//!
//! Windows only close when time passes their boundary, so the tests use
//! the payload-timestamp lever: the cron attributes events by their
//! payload `ts_unix`, and an event stamped far in the future forces every
//! window containing earlier events to close on the next tick — no
//! 300-second waits. Segments are hand-fabricated (deterministic bytes,
//! same pattern as `memory_wal_rotation.rs`); they are written AFTER the
//! spawn because the observer fast-forwards its cursors at boot
//! (observe-from-boot, no backfill).

use std::sync::Arc;
use std::time::Duration;

use neothd::analytics::babel::config::BabelConfig;
use neothd::coding::feed::FeedEntry;
use neothd::daemon::babel_cron::spawn_babel_cron_loop;
use neothd::memory::store::ViewsExecutor;
use neothd::permissions::AutonomyLevel;
use neothd::wal::builder::make_header;
use neothd::wal::events::{
    EVENT_TYPE_AGENT_DISPATCHED, EVENT_TYPE_MCP_TOOL_CALLED, EVENT_TYPE_PROVIDER_RESPONSE,
};
use neothd::wal::frame::encode_frame;
use neothd::wal::segment_header::SegmentHeader;

fn frame(event_type: u8, payload: serde_json::Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(&payload).expect("serialize payload");
    let header = make_header(event_type, &bytes);
    encode_frame(&header, &bytes)
}

fn segment_bytes(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = SegmentHeader::new(0, 1, 0, 0, [0u8; 16]).to_le_bytes().to_vec();
    for f in frames {
        out.extend_from_slice(f);
    }
    out
}

/// Wait for the observer's spawn-time cursor fast-forward to finish before
/// writing frames it must see. The wal dir is empty at spawn, so the
/// fast-forward is sub-millisecond — 1.5s is a generous margin.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(1500)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn babel_spawn_returns_none_when_disabled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let views = ViewsExecutor::open(&dir.path().join("views.db"), 1).expect("views");
    let cfg = BabelConfig { enabled: false, ..BabelConfig::default() };
    let handle = spawn_babel_cron_loop(
        cfg,
        AutonomyLevel::Standard,
        dir.path().to_path_buf(),
        views,
        None,
    );
    assert!(handle.is_none(), "disabled observer must not spawn a task");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn babel_cron_emits_window_row_in_sqlite() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_dir = dir.path().join("wal");
    std::fs::create_dir_all(&wal_dir).expect("wal dir");
    let views_path = dir.path().join("views.db");
    let views = ViewsExecutor::open(&views_path, 1).expect("views");

    let cfg = BabelConfig { tick_interval_secs: 1, ..BabelConfig::default() };
    let handle = spawn_babel_cron_loop(
        cfg,
        AutonomyLevel::Standard,
        wal_dir.clone(),
        views,
        None,
    )
    .expect("enabled observer spawns");
    settle().await;

    let now = neothd::time::now_unix_i64();
    let frames = vec![
        frame(
            EVENT_TYPE_AGENT_DISPATCHED,
            serde_json::json!({"agent_name": "a1", "ts_unix": now}),
        ),
        frame(
            EVENT_TYPE_MCP_TOOL_CALLED,
            serde_json::json!({
                "server_id": "srv", "tool": "bash", "arguments_hash": "h1",
                "content_bytes": 3, "is_error": false, "ts_unix": now + 5,
            }),
        ),
        // Far-future event: every window holding the two events above must
        // close on the tick that ingests this frame.
        frame(
            EVENT_TYPE_AGENT_DISPATCHED,
            serde_json::json!({"agent_name": "a2", "ts_unix": now + 4000}),
        ),
    ];
    std::fs::write(wal_dir.join("000001.wal"), segment_bytes(&frames)).expect("write segment");

    let conn = neothd::memory::store::open(&views_path).expect("open views reader");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut count = 0i64;
    while std::time::Instant::now() < deadline {
        // unwrap_or(0) is deliberate: the observer creates the babel tables
        // at spawn, so the first polls can race "no such table" — that is a
        // not-yet state, not a failure.
        count = conn
            .query_row("SELECT COUNT(*) FROM idx_babel_windows", [], |r| r.get(0))
            .unwrap_or(0);
        if count >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    handle.abort();
    assert!(count >= 1, "window row appears in idx_babel_windows (got {count})");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn babel_threshold_breach_reaches_sse_feed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_dir = dir.path().join("wal");
    std::fs::create_dir_all(&wal_dir).expect("wal dir");
    let views = ViewsExecutor::open(&dir.path().join("views.db"), 1).expect("views");

    let (tx, mut rx) = tokio::sync::broadcast::channel::<FeedEntry>(32);
    let cfg = BabelConfig {
        tick_interval_secs: 1,
        threshold: 0.0, // any emitted b_mult crosses
        epsilon_calibrated: Some(0.01),
        ..BabelConfig::default()
    };
    let handle = spawn_babel_cron_loop(
        cfg,
        AutonomyLevel::Standard,
        wal_dir.clone(),
        views,
        Some(Arc::new(tx)),
    )
    .expect("enabled observer spawns");
    settle().await;

    let now = neothd::time::now_unix_i64();
    let frames = vec![
        // a > 0 (agent dispatched) and v > 0 (output tokens) make the
        // buffer ratios defined, so b_mult emits — 0.0 >= threshold 0.0.
        frame(
            EVENT_TYPE_AGENT_DISPATCHED,
            serde_json::json!({"agent_name": "a1", "ts_unix": now}),
        ),
        frame(
            EVENT_TYPE_PROVIDER_RESPONSE,
            serde_json::json!({"output_tokens": 120, "ts_unix": now + 5}),
        ),
        frame(
            EVENT_TYPE_AGENT_DISPATCHED,
            serde_json::json!({"agent_name": "a2", "ts_unix": now + 4000}),
        ),
    ];
    std::fs::write(wal_dir.join("000001.wal"), segment_bytes(&frames)).expect("write segment");

    let breach = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match rx.recv().await {
                Ok(entry) if entry.message.contains("THRESHOLD BREACH") => return entry,
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(e) => panic!("SSE channel closed before breach arrived: {e}"),
            }
        }
    })
    .await
    .expect("threshold breach reaches the SSE feed within 20s");
    handle.abort();
    assert_eq!(breach.actor, "babel");
    assert!(breach.message.contains("15-min"), "breach names the window: {}", breach.message);
}
