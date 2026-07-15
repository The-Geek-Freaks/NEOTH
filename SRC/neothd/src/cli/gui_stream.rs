//! `neoth gui-stream` — persistent newline-delimited-JSON (NDJSON)
//! request/response channel for the `neothd-gui` desktop app.
//!
//! ## Why this exists (B — persistent-stdio-stream, Session 30)
//!
//! The GUI's Code-Sessions board previously refreshed by spawning FOUR
//! cold `neoth` subprocesses every 2 seconds (`kanban list` →
//! `kanban show` → `kanban watch` → `hemispheres show`). Each spawn
//! pays the full process cold-start tax: fork/exec, dynamic linking,
//! Rust runtime init, `freedom.yaml` parse, fresh `views.db` open. A
//! 4-lens senior-dev gremium (Session 30) chose this design over a
//! `serve --gui-ipc` Unix-socket / Windows-named-pipe JSON-RPC layer
//! because:
//!
//!   * It REUSES the channel the GUI already trusts — `Command` +
//!     `thread::spawn` + NDJSON, proven across 15+ call sites — with
//!     ZERO new dependencies and ZERO new platform-specific transport
//!     code (no dual UDS/named-pipe impls).
//!   * The process lifecycle IS the connection lifecycle: the GUI owns
//!     the child, so a crash is caught at the `Child` handle (EOF) and
//!     degrades gracefully to the legacy one-shot path — no reconnect
//!     state machine, no exponential backoff.
//!   * It has NO inbound listener, so — unlike a localhost socket /
//!     loosely-DACL'd named pipe — there is no endpoint another local
//!     process can connect to. The channel is a child's stdin/stdout,
//!     writable only by the same-user GUI that spawned it.
//!
//! ## Protocol
//!
//! The GUI writes one JSON request per line to this process's stdin and
//! reads one JSON response line from stdout. The loop runs until stdin
//! reaches EOF (the GUI closing the pipe / dropping the child).
//!
//! Request : `{"id": <u64>, "method": "board" | "ping"}`
//! Response: `{"id": <u64>, "ok": true,  "board": { ... }}`        (board)
//!           `{"id": <u64>, "ok": true,  "pong": true}`            (ping)
//!           `{"id": <u64>, "ok": false, "error": "<reason>"}`     (error)
//! Push    : `{"push": true, "board": { ... }}`   (spontaneous, no id —
//!             emitted when views.db mtime changes; GOLD-ADAPT-TRAIL-02)
//!           `{"push": true, "channel_feed": [...]}`  (DES-10: live channel
//!             activity — metadata only: direction/channel/peer/bytes/ts.
//!             No message body; WAL stores hashed text by design.)
//!
//! READ-ONLY by design: the channel serves board queries only. Every
//! state mutation (kanban move/review/comment/assign, preset apply,
//! chat) stays on its existing gated subprocess path, so this surface
//! never bypasses the `CommandSource` privilege ceiling (ADV-09/ADV-15).

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;
use rusqlite::Connection;
use serde::Deserialize;
use tokio::io::AsyncBufReadExt as _;

use crate::config::FreedomConfig;
use crate::memory::store as memstore;

#[derive(Args, Debug, Clone)]
pub struct GuiStreamArgs {
    /// Override the `views.db` path. Defaults to `~/.neoth/views.db`.
    /// The GUI passes nothing — the default mirrors what the one-shot
    /// `kanban` subcommands resolve.
    #[arg(long, value_name = "PATH")]
    pub db: Option<std::path::PathBuf>,
}

/// One parsed request line. `id` is echoed back so the client can match
/// responses to requests (it sends one at a time today, but echoing the
/// id keeps the protocol robust if that ever changes).
#[derive(Debug, Deserialize)]
struct GuiRequest {
    #[serde(default)]
    id: u64,
    method: String,
}

pub async fn run_gui_stream(args: GuiStreamArgs) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(memstore::default_path);
    let conn = open_warm_conn(&db_path)?;
    // Missing freedom.yaml uses the safe first-run defaults. Existing malformed
    // policy is surfaced so the board cannot display a fabricated default
    // posture while the operator's real configuration is unreadable.
    let cfg = FreedomConfig::load_from_default_path_or_default()?;
    // Mirror the GUI's `kanban watch` call (no `--wal-dir` → default dir).
    let wal_dir = FreedomConfig::default_wal_dir();

    tracing::info!(
        db = %db_path.display(),
        wal_dir = %wal_dir.display(),
        "gui-stream: warm channel open, awaiting NDJSON requests on stdin"
    );

    // GOLD-ADAPT-TRAIL-02: track views.db mtime for spontaneous push.
    // When the mtime changes (indexer committed new frames), emit a push
    // frame WITHOUT waiting for the GUI to request a board update.
    let mut db_mtime = std::fs::metadata(&db_path).and_then(|m| m.modified()).ok();

    // DES-10: channel-feed cursor — segment identity plus byte offset of the
    // last frame we emitted. The offset is segment-local and must reset when
    // the writer rotates to a new WAL segment.
    let mut channel_cursor = ChannelFeedCursor::default();

    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut line = String::new();
    // TRAIL-02: 200ms tick for mtime-polling. Cheap: one stat(2) call per tick.
    let mut push_tick = tokio::time::interval(std::time::Duration::from_millis(200));
    // The first tick fires immediately — consume it so the first poll happens
    // after the initial warm-up, not before the GUI sends its first request.
    push_tick.tick().await;

    loop {
        line.clear();
        tokio::select! {
            // biased: prefer processing a pending stdin line over the mtime-poll
            // arm so a burst of requests doesn't starve behind ticker wakeups.
            biased;

            result = reader.read_line(&mut line) => {
                let n = result.context("gui-stream: read request line from stdin")?;
                if n == 0 {
                    // EOF — the GUI closed the pipe. Clean shutdown.
                    tracing::info!("gui-stream: stdin EOF, exiting");
                    break;
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let response = handle_request_line(trimmed, &conn, &wal_dir, &cfg);
                // One response line per request. Flush so the GUI's blocking
                // `read_line` unblocks immediately rather than waiting on the
                // OS pipe buffer.
                writeln!(out, "{response}").context("gui-stream: write response")?;
                out.flush().context("gui-stream: flush response")?;
            }

            // GOLD-ADAPT-TRAIL-02: mtime-poll arm — spontaneous push when
            // views.db is updated by the indexer (no GUI request needed).
            _ = push_tick.tick() => {
                let new_mtime = std::fs::metadata(&db_path)
                    .and_then(|m| m.modified())
                    .ok();
                if new_mtime.is_some() && new_mtime != db_mtime {
                    db_mtime = new_mtime;
                    match crate::cli::kanban::assemble_gui_board(&conn, &wal_dir, &cfg) {
                        Ok(board) => {
                            let push = serde_json::json!({"push": true, "board": board});
                            writeln!(out, "{push}").context("gui-stream: write push frame")?;
                            out.flush().context("gui-stream: flush push frame")?;
                        }
                        Err(e) => {
                            // Non-fatal: log and continue. The GUI's next
                            // explicit `board` request will get the fresh data.
                            tracing::warn!(error = %e, "gui-stream: push board assembly failed");
                        }
                    }
                }

                // DES-10: channel-activity feed — poll WAL for new channel
                // frames since the last tick. Metadata only; no message body.
                let feed = poll_channel_feed(&wal_dir, &mut channel_cursor);
                if !feed.is_empty() {
                    let push = serde_json::json!({"push": true, "channel_feed": feed});
                    writeln!(out, "{push}").context("gui-stream: write channel_feed push")?;
                    out.flush().context("gui-stream: flush channel_feed push")?;
                }
            }
        }
    }
    Ok(())
}

/// Open the `views.db` read connection ONCE, kept warm for the channel
/// lifetime. `memstore::open` already sets `journal_mode=WAL` (readers
/// never block the concurrent `kanban move` writer); the `busy_timeout`
/// is insurance against the brief exclusive window of a WAL checkpoint.
fn open_warm_conn(db_path: &Path) -> Result<Connection> {
    let conn = memstore::open(db_path).context("gui-stream: open views.db")?;
    crate::coding::store::ensure_schema(&conn).context("gui-stream: ensure kanban schema")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .context("gui-stream: set busy_timeout")?;
    Ok(conn)
}

/// Parse one NDJSON request line and produce the response line. Pure
/// w.r.t. its inputs (the `conn`/`wal_dir`/`cfg`) — no global state — so
/// the request→response shaping is unit-testable against an in-memory db.
fn handle_request_line(
    line: &str,
    conn: &Connection,
    wal_dir: &Path,
    cfg: &FreedomConfig,
) -> String {
    let req: GuiRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            // id unknown — echo 0 and surface the parse error.
            return error_response(0, &format!("malformed request: {e}"));
        }
    };
    match req.method.as_str() {
        "ping" => serde_json::json!({ "id": req.id, "ok": true, "pong": true }).to_string(),
        // Daemon→GUI activity push: the most-recent (≤30s) WAL event mapped to a
        // Buddy mood, so the orb reflects what the daemon is doing right now
        // (memory, audit, consent, channel ingress, provider fallback, cluster).
        "activity" => {
            let (activity, caption) = assemble_activity(wal_dir);
            serde_json::json!({
                "id": req.id, "ok": true, "activity": activity, "caption": caption,
            })
            .to_string()
        }
        "board" => match crate::cli::kanban::assemble_gui_board(conn, wal_dir, cfg) {
            Ok(board) => serde_json::json!({
                "id": req.id,
                "ok": true,
                "board": board,
            })
            .to_string(),
            Err(e) => error_response(req.id, &format!("board assembly failed: {e}")),
        },
        other => error_response(req.id, &format!("unknown method '{other}'")),
    }
}

/// The most-recent WAL event in the live segment, mapped to a Buddy
/// `(activity, caption)`. Returns `idle` if the last event is older than 30s
/// (so a long-quiet daemon doesn't pin a stale mood) or the WAL is unreadable.
fn assemble_activity(wal_dir: &Path) -> (String, String) {
    let idle = || ("idle".to_string(), "ready".to_string());
    let Some(seg) = latest_segment(wal_dir) else {
        return idle();
    };
    let Ok(bytes) = std::fs::read(&seg) else {
        return idle();
    };
    let mut last_event: u8 = 0;
    let mut last_ns: u128 = 0;
    let _ = crate::wal::scan::for_each_frame(&bytes, |_, dec| {
        last_event = dec.header.event_type;
        last_ns = dec.header.hlc.physical_ns() as u128;
        Ok(())
    });
    if last_ns == 0 {
        return idle();
    }
    let now_ns = crate::time::now_unix_ns() as u128;
    // 30s freshness window — only reflect activity the daemon did recently.
    if now_ns.saturating_sub(last_ns) > 30_000_000_000 {
        return idle();
    }
    let (a, c) = activity_for_event(last_event);
    (a.to_string(), c.to_string())
}

// ── DES-10: channel-activity feed ────────────────────────────────────────────

/// Map a channel `event_type` byte to a direction string for the GUI feed.
/// Returns `None` for non-channel event types (caller skips them).
fn channel_event_direction(event_type: u8) -> Option<&'static str> {
    use crate::wal::events as ev;
    match event_type {
        ev::EVENT_TYPE_CHANNEL_INGRESS => Some("in"),
        ev::EVENT_TYPE_CHANNEL_EGRESS | ev::EVENT_TYPE_CHANNEL_SEND => Some("out"),
        ev::EVENT_TYPE_PROACTIVE_SENT => Some("proactive"),
        ev::EVENT_TYPE_CHANNEL_GATE_REJECTED | ev::EVENT_TYPE_CHANNEL_PRIVILEGE_BLOCKED => {
            Some("blocked")
        }
        _ => None,
    }
}

/// Scan the latest WAL segment for channel-activity frames newer than the
/// segment-local cursor. Resets the byte offset when the latest segment path
/// changes, then advances it to the highest offset seen. Returns at most 50
/// items per tick so a burst doesn't flood the pipe.
///
/// Payload fields extracted (all optional — tolerate missing gracefully):
/// - `channel`  : adapter name (telegram/whatsapp/…)
/// - `sender_id`: plain on ingress frames; absent/omitted on egress/proactive
/// - `recipient_hash` / `to_hash`: short prefix of hash for egress/proactive
/// - `bytes`    : message byte count
/// - `ts_unix`  : unix second timestamp from the frame payload
///
/// We use `dec.header.hlc.physical_ns()` as the fallback `ts_unix` when the
/// payload lacks a `ts_unix` field (nanoseconds → seconds).
///
/// READ-ONLY; no state mutation; never emits message text (WAL stores hashes).
#[derive(Debug, Default)]
struct ChannelFeedCursor {
    segment: Option<std::path::PathBuf>,
    offset: usize,
}

fn poll_channel_feed(wal_dir: &Path, cursor: &mut ChannelFeedCursor) -> Vec<serde_json::Value> {
    const MAX_BATCH: usize = 50;

    let Some(seg_path) = latest_segment(wal_dir) else {
        return Vec::new();
    };
    if cursor.segment.as_ref() != Some(&seg_path) {
        cursor.segment = Some(seg_path.clone());
        cursor.offset = 0;
    }
    let Ok(bytes) = std::fs::read(&seg_path) else {
        return Vec::new();
    };

    let mut events: Vec<serde_json::Value> = Vec::new();
    let last_offset = cursor.offset;
    let mut new_offset = last_offset;

    let _ = crate::wal::scan::for_each_frame(&bytes, |frame_offset, dec| {
        // Stop advancing once this tick's output batch is full. The next poll
        // resumes at the first unprocessed frame instead of silently dropping
        // the tail of a burst.
        if events.len() >= MAX_BATCH {
            return Ok(());
        }

        // Advance our high-water mark regardless of event type so we never
        // re-scan frames we've already passed on this segment.
        if frame_offset > new_offset {
            new_offset = frame_offset;
        }

        // Skip frames we have already emitted.
        if frame_offset <= last_offset {
            return Ok(());
        }

        let Some(direction) = channel_event_direction(dec.header.event_type) else {
            return Ok(());
        };

        // Parse payload JSON; tolerate non-JSON payloads (some events use
        // binary or empty bodies — just produce a minimal metadata record).
        let payload: serde_json::Value = serde_json::from_slice(dec.payload)
            .unwrap_or(serde_json::Value::Object(Default::default()));

        let channel = payload
            .get("channel")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // peer: sender_id on ingress; short hash prefix on egress/proactive.
        let peer = if direction == "in" {
            payload
                .get("sender_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        } else {
            // recipient_hash or to_hash — take first 8 chars as display hint.
            let hash = payload
                .get("recipient_hash")
                .or_else(|| payload.get("to_hash"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            hash.chars().take(8).collect()
        };

        let bytes_count = payload.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);

        let ts_unix = payload
            .get("ts_unix")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| dec.header.hlc.physical_ns() / 1_000_000_000);

        events.push(serde_json::json!({
            "event_id":  frame_offset,
            "direction": direction,
            "channel":   channel,
            "peer":      peer,
            "bytes":     bytes_count,
            "ts_unix":   ts_unix,
        }));

        Ok(())
    });

    cursor.offset = new_offset;
    events
}

// ─────────────────────────────────────────────────────────────────────────────

/// Highest-numbered `*.wal` segment in `wal_dir` (the live one).
fn latest_segment(wal_dir: &Path) -> Option<std::path::PathBuf> {
    let mut segs: Vec<std::path::PathBuf> = std::fs::read_dir(wal_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "wal").unwrap_or(false))
        .collect();
    segs.sort();
    segs.pop()
}

/// Map a WAL `event_type` byte to a Buddy `(mood, caption)` (mirrors the GUI's
/// `buddy_activity::GuiActivity` vocabulary). Unmapped events → idle.
fn activity_for_event(event_type: u8) -> (&'static str, &'static str) {
    use crate::wal::events as ev;
    match event_type {
        ev::EVENT_TYPE_PROVIDER_REQUEST => ("working", "on it"),
        ev::EVENT_TYPE_PROVIDER_RESPONSE => ("success", "done"),
        ev::EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED => ("intense", "fallback"),
        ev::EVENT_TYPE_RAW_TEXT => ("thinking", "thinking…"),
        ev::EVENT_TYPE_REFUSAL_OBSERVED => ("alert", "refusal"),
        ev::EVENT_TYPE_CHANNEL_INGRESS => ("notification", "new activity"),
        ev::EVENT_TYPE_CHANNEL_EGRESS => ("working", "replying"),
        ev::EVENT_TYPE_CONSENT_DECISION => ("consent", "consent"),
        ev::EVENT_TYPE_AUDIT_RPC_ACCEPT | ev::EVENT_TYPE_COMPACTION_MARKER => {
            ("audit", "verifying")
        }
        ev::EVENT_TYPE_WORKER_DIED => ("error", "worker died"),
        ev::EVENT_TYPE_CLUSTER_PEER_CONNECTED => ("connected", "peer joined"),
        ev::EVENT_TYPE_CLUSTER_TASK_ACCEPTED => ("agents", "agents deployed"),
        ev::EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED => ("parallel", "syncing"),
        ev::EVENT_TYPE_MEMORY_TRANSFER_EXPORTED => ("memory", "remembering"),
        _ => ("idle", "ready"),
    }
}

/// Build a `{"id":.., "ok":false, "error":".."}` response line.
fn error_response(id: u64, reason: &str) -> String {
    serde_json::json!({ "id": id, "ok": false, "error": reason }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::store;
    use crate::coding::types::Hemisphere;
    use crate::wal::HeaderBuilder;
    use crate::wal::frame::encode_frame;
    use crate::wal::segment_header::{SEGMENT_HEADER_V2_LEN, SegmentHeaderV2};

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        store::ensure_schema(&conn).unwrap();
        conn
    }

    fn parse(resp: &str) -> serde_json::Value {
        serde_json::from_str(resp).unwrap()
    }

    #[test]
    fn malformed_line_yields_ok_false_with_id_zero() {
        let conn = fresh_conn();
        let cfg = FreedomConfig::default();
        let wal = std::path::PathBuf::from(".");
        let resp = handle_request_line("not json at all", &conn, &wal, &cfg);
        let v = parse(&resp);
        assert_eq!(v["ok"], false);
        assert_eq!(v["id"], 0);
        assert!(
            v["error"].as_str().unwrap().contains("malformed"),
            "got: {resp}"
        );
    }

    #[test]
    fn unknown_method_is_rejected_not_panicked() {
        let conn = fresh_conn();
        let cfg = FreedomConfig::default();
        let wal = std::path::PathBuf::from(".");
        let resp = handle_request_line(r#"{"id":7,"method":"nuke"}"#, &conn, &wal, &cfg);
        let v = parse(&resp);
        assert_eq!(v["ok"], false);
        assert_eq!(v["id"], 7);
        assert!(v["error"].as_str().unwrap().contains("unknown method"));
    }

    #[test]
    fn activity_maps_high_signal_events_and_defaults_idle() {
        use crate::wal::events as ev;
        assert_eq!(
            activity_for_event(ev::EVENT_TYPE_PROVIDER_REQUEST).0,
            "working"
        );
        assert_eq!(
            activity_for_event(ev::EVENT_TYPE_CONSENT_DECISION).0,
            "consent"
        );
        assert_eq!(
            activity_for_event(ev::EVENT_TYPE_CHANNEL_INGRESS).0,
            "notification"
        );
        assert_eq!(
            activity_for_event(ev::EVENT_TYPE_AUDIT_RPC_ACCEPT).0,
            "audit"
        );
        assert_eq!(
            activity_for_event(ev::EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED).0,
            "intense"
        );
        assert_eq!(activity_for_event(0x00).0, "idle");
        // every mapped caption is non-empty
        for et in [0x01u8, 0x20, 0x21, 0x32, 0x65, 0xAE, 0xEB] {
            assert!(!activity_for_event(et).1.is_empty());
        }
    }

    #[test]
    fn activity_method_on_empty_wal_dir_is_idle() {
        let conn = fresh_conn();
        let cfg = FreedomConfig::default();
        let tmp = std::env::temp_dir().join("neoth_gui_activity_test_empty");
        let _ = std::fs::create_dir_all(&tmp);
        let resp = handle_request_line(r#"{"id":9,"method":"activity"}"#, &conn, &tmp, &cfg);
        let v = parse(&resp);
        assert_eq!(v["ok"], true, "got: {resp}");
        assert_eq!(v["activity"], "idle");
    }

    #[test]
    fn ping_echoes_id_and_pongs() {
        let conn = fresh_conn();
        let cfg = FreedomConfig::default();
        let wal = std::path::PathBuf::from(".");
        let resp = handle_request_line(r#"{"id":42,"method":"ping"}"#, &conn, &wal, &cfg);
        let v = parse(&resp);
        assert_eq!(v["ok"], true);
        assert_eq!(v["id"], 42);
        assert_eq!(v["pong"], true);
    }

    #[test]
    fn board_on_empty_db_reports_no_active_session() {
        let conn = fresh_conn();
        let cfg = FreedomConfig::default();
        let wal = std::path::PathBuf::from(".");
        let resp = handle_request_line(r#"{"id":1,"method":"board"}"#, &conn, &wal, &cfg);
        let v = parse(&resp);
        assert_eq!(v["ok"], true, "got: {resp}");
        assert_eq!(v["id"], 1);
        assert!(
            v["board"]["summary"]
                .as_str()
                .unwrap()
                .contains("No active session"),
            "got: {resp}"
        );
        assert!(v["board"]["tasks"].as_array().unwrap().is_empty());
        assert!(v["board"]["feed"].as_array().unwrap().is_empty());
    }

    #[test]
    fn board_with_session_returns_tasks_bucketable_by_status() {
        let conn = fresh_conn();
        let session_id =
            store::insert_session(&conn, 1, "build a thing", "h", "cli", None).unwrap();
        let t1 = store::insert_task(&conn, session_id, 10, "task one", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, t1, Hemisphere::Left, None, None).unwrap();
        let _t2 =
            store::insert_task(&conn, session_id, 20, "task two", None, "logic", None).unwrap();

        let cfg = FreedomConfig::default();
        let wal = std::path::PathBuf::from(".");
        let resp = handle_request_line(r#"{"id":3,"method":"board"}"#, &conn, &wal, &cfg);
        let v = parse(&resp);
        assert_eq!(v["ok"], true, "got: {resp}");
        let summary = v["board"]["summary"].as_str().unwrap();
        assert!(summary.contains("build a thing"), "got: {summary}");
        let tasks = v["board"]["tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 2);
        // Every task row must carry the four fields the GUI buckets on.
        for t in tasks {
            assert!(t["task_id"].is_i64());
            assert!(t["title"].is_string());
            assert!(t["hemisphere"].is_string());
            assert!(t["status"].is_string());
        }
    }

    #[test]
    fn cerebellum_bound_true_when_single_provider_fallback_set() {
        let mut cfg = FreedomConfig::default();
        // Any `provider_kind` means single-mode fallback binds every role.
        cfg.provider_kind = Some(crate::cli::init::ProviderKind::ClaudeCli);
        let conn = fresh_conn();
        let wal = std::path::PathBuf::from(".");
        let resp = handle_request_line(r#"{"id":1,"method":"board"}"#, &conn, &wal, &cfg);
        let v = parse(&resp);
        assert_eq!(v["board"]["cerebellum_bound"], true, "got: {resp}");
    }

    // ── DES-10 tests ──────────────────────────────────────────────────────────

    #[test]
    fn channel_event_direction_maps_all_covered_types() {
        use crate::wal::events as ev;
        assert_eq!(
            channel_event_direction(ev::EVENT_TYPE_CHANNEL_INGRESS),
            Some("in")
        );
        assert_eq!(
            channel_event_direction(ev::EVENT_TYPE_CHANNEL_EGRESS),
            Some("out")
        );
        assert_eq!(
            channel_event_direction(ev::EVENT_TYPE_CHANNEL_SEND),
            Some("out")
        );
        assert_eq!(
            channel_event_direction(ev::EVENT_TYPE_PROACTIVE_SENT),
            Some("proactive")
        );
        assert_eq!(
            channel_event_direction(ev::EVENT_TYPE_CHANNEL_GATE_REJECTED),
            Some("blocked")
        );
        assert_eq!(
            channel_event_direction(ev::EVENT_TYPE_CHANNEL_PRIVILEGE_BLOCKED),
            Some("blocked")
        );
        // Non-channel events → None
        assert_eq!(
            channel_event_direction(ev::EVENT_TYPE_PROVIDER_REQUEST),
            None
        );
        assert_eq!(channel_event_direction(ev::EVENT_TYPE_RAW_TEXT), None);
        assert_eq!(channel_event_direction(0x00), None);
    }

    /// Build a minimal uncompressed WAL segment from a slice of raw frame bytes.
    fn make_segment(frames: &[u8]) -> Vec<u8> {
        // segment_id=1, epoch=1, prev_hmac_tag=0, flags=0 (uncompressed v2)
        let hdr = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], 0);
        let mut seg = hdr.to_le_bytes().to_vec();
        seg.extend_from_slice(frames);
        seg
    }

    /// Build a raw encoded frame with the given event_type and JSON payload.
    fn make_frame(event_type: u8, payload: &[u8]) -> Vec<u8> {
        let h = HeaderBuilder::new(event_type, payload).build();
        encode_frame(&h, payload)
    }

    #[test]
    fn poll_channel_feed_returns_ingress_and_egress_skips_non_channel() {
        use crate::wal::events as ev;

        let ingress_payload =
            br#"{"channel":"telegram","sender_id":"u123","bytes":42,"ts_unix":1700000001}"#;
        let egress_payload =
            br#"{"channel":"telegram","recipient_hash":"abcdef1234567890","bytes":18,"ts_unix":1700000002}"#;
        // A non-channel frame that must be skipped.
        let noise_payload = b"raw text noise";

        let f_ingress = make_frame(ev::EVENT_TYPE_CHANNEL_INGRESS, ingress_payload);
        let f_noise = make_frame(ev::EVENT_TYPE_RAW_TEXT, noise_payload);
        let f_egress = make_frame(ev::EVENT_TYPE_CHANNEL_EGRESS, egress_payload);

        let mut frames = Vec::new();
        frames.extend_from_slice(&f_ingress);
        frames.extend_from_slice(&f_noise);
        frames.extend_from_slice(&f_egress);

        let seg = make_segment(&frames);

        // Write segment to a temp dir so poll_channel_feed can find it.
        let tmp = std::env::temp_dir().join("neoth_des10_feed_test");
        let _ = std::fs::create_dir_all(&tmp);
        // Name must sort after any leftover segments → use a high prefix.
        let seg_path = tmp.join("99999.wal");
        std::fs::write(&seg_path, &seg).unwrap();

        let mut cursor = ChannelFeedCursor::default();
        let feed = poll_channel_feed(&tmp, &mut cursor);

        // Clean up before asserting (don't leave state for other tests).
        let _ = std::fs::remove_file(&seg_path);

        // Must have exactly 2 channel events; the noise frame is excluded.
        assert_eq!(feed.len(), 2, "got: {feed:?}");

        // First item: ingress → direction "in", peer = sender_id
        assert_eq!(feed[0]["direction"], "in");
        assert_eq!(feed[0]["channel"], "telegram");
        assert_eq!(feed[0]["peer"], "u123");
        assert_eq!(feed[0]["bytes"], 42);
        assert_eq!(feed[0]["ts_unix"], 1700000001u64);
        assert!(feed[0]["event_id"].is_u64());

        // Second item: egress → direction "out", peer = first 8 chars of hash
        assert_eq!(feed[1]["direction"], "out");
        assert_eq!(feed[1]["peer"], "abcdef12");
        assert_eq!(feed[1]["bytes"], 18);

        // Cursor must have advanced past both frames.
        assert!(cursor.offset >= SEGMENT_HEADER_V2_LEN + f_ingress.len() + f_noise.len());
    }

    #[test]
    fn poll_channel_feed_cursor_prevents_duplicate_emission() {
        use crate::wal::events as ev;

        let payload = br#"{"channel":"slack","sender_id":"S01","bytes":5,"ts_unix":1700000010}"#;
        let frame = make_frame(ev::EVENT_TYPE_CHANNEL_INGRESS, payload);
        let seg = make_segment(&frame);

        let tmp = std::env::temp_dir().join("neoth_des10_cursor_test");
        let _ = std::fs::create_dir_all(&tmp);
        let seg_path = tmp.join("99998.wal");
        std::fs::write(&seg_path, &seg).unwrap();

        let mut cursor = ChannelFeedCursor::default();

        // First poll — must return the frame.
        let first = poll_channel_feed(&tmp, &mut cursor);
        assert_eq!(first.len(), 1);

        // Second poll with the same segment bytes — cursor already past the frame.
        let second = poll_channel_feed(&tmp, &mut cursor);
        let _ = std::fs::remove_file(&seg_path);

        assert!(second.is_empty(), "duplicate emission: {second:?}");
    }

    #[test]
    fn poll_channel_feed_resets_offset_after_segment_rotation() {
        use crate::wal::events::EVENT_TYPE_CHANNEL_INGRESS;

        let dir = tempfile::tempdir().unwrap();
        let first_path = dir.path().join("000001.wal");
        let second_path = dir.path().join("000002.wal");
        let first_frame = make_frame(
            EVENT_TYPE_CHANNEL_INGRESS,
            br#"{"channel":"telegram","sender_id":"first","bytes":200}"#,
        );
        let mut first_frames = first_frame.clone();
        first_frames.extend_from_slice(&first_frame);
        std::fs::write(&first_path, make_segment(&first_frames)).unwrap();

        let mut cursor = ChannelFeedCursor::default();
        assert_eq!(poll_channel_feed(dir.path(), &mut cursor).len(), 2);
        let old_offset = cursor.offset;

        let rotated_frame = make_frame(
            EVENT_TYPE_CHANNEL_INGRESS,
            br#"{"channel":"signal","sender_id":"rotated","bytes":1}"#,
        );
        std::fs::write(&second_path, make_segment(&rotated_frame)).unwrap();
        let feed = poll_channel_feed(dir.path(), &mut cursor);

        assert_eq!(feed.len(), 1, "first frame in rotated segment was skipped");
        assert_eq!(feed[0]["peer"], "rotated");
        assert!(cursor.offset < old_offset, "offset must be segment-local");
        assert_eq!(cursor.segment.as_deref(), Some(second_path.as_path()));
    }

    #[test]
    fn poll_channel_feed_batch_limit_resumes_without_dropping_tail() {
        use crate::wal::events::EVENT_TYPE_CHANNEL_INGRESS;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000001.wal");
        let frame = make_frame(
            EVENT_TYPE_CHANNEL_INGRESS,
            br#"{"channel":"telegram","sender_id":"burst","bytes":1}"#,
        );
        let mut frames = Vec::new();
        for _ in 0..51 {
            frames.extend_from_slice(&frame);
        }
        std::fs::write(path, make_segment(&frames)).unwrap();

        let mut cursor = ChannelFeedCursor::default();
        assert_eq!(poll_channel_feed(dir.path(), &mut cursor).len(), 50);
        assert_eq!(
            poll_channel_feed(dir.path(), &mut cursor).len(),
            1,
            "the frame after MAX_BATCH must be emitted on the next poll"
        );
        assert!(poll_channel_feed(dir.path(), &mut cursor).is_empty());
    }

    #[test]
    fn poll_channel_feed_on_empty_wal_dir_returns_empty() {
        let tmp = std::env::temp_dir().join("neoth_des10_empty_test");
        let _ = std::fs::create_dir_all(&tmp);
        // Ensure there are no .wal files in this dir.
        if let Ok(rd) = std::fs::read_dir(&tmp) {
            for e in rd.flatten() {
                if e.path().extension().map(|x| x == "wal").unwrap_or(false) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        let mut cursor = ChannelFeedCursor::default();
        let feed = poll_channel_feed(&tmp, &mut cursor);
        assert!(feed.is_empty());
        assert_eq!(cursor.offset, 0);
        assert!(cursor.segment.is_none());
    }
}
