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
//!
//! READ-ONLY by design: the channel serves board queries only. Every
//! state mutation (kanban move/review/comment/assign, preset apply,
//! chat) stays on its existing gated subprocess path, so this surface
//! never bypasses the `CommandSource` privilege ceiling (ADV-09/ADV-15).

use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;
use rusqlite::Connection;
use serde::Deserialize;

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
    // Best-effort config load — a missing/garbled freedom.yaml must not
    // take down the board (the db is independent of it). `unwrap_or_default`
    // gives a defaults-config; the GUI's own one-shot fallback covers any
    // truly-degraded case.
    let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();
    // Mirror the GUI's `kanban watch` call (no `--wal-dir` → default dir).
    let wal_dir = FreedomConfig::default_wal_dir();

    tracing::info!(
        db = %db_path.display(),
        wal_dir = %wal_dir.display(),
        "gui-stream: warm channel open, awaiting NDJSON requests on stdin"
    );

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .context("gui-stream: read request line from stdin")?;
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
}
