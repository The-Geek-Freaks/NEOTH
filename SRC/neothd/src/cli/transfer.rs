//! A3-01 — `neoth transfer --dest <pubkey>`: export a recipient-encrypted,
//! operator-signed memory bundle to another NEOTH instance.
//!
//! The bundle is sealed with [`crate::memory::transfer_bundle`] (ephemeral
//! X25519 ECDH → HKDF-SHA256 → AES-256-GCM, ed25519-signed with the operator's
//! WAL signing key). Only the holder of the recipient's X25519 secret can
//! decrypt; only the operator's key could have signed it. The plaintext memory
//! never leaves this process unencrypted — the file on disk is ciphertext.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Args;
use rusqlite::Connection;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::memory::transfer_bundle::{self, parse_b64_32};

/// Default look-back window for the hot-tier memory export (days).
const DEFAULT_WINDOW_DAYS: u32 = 7;

#[derive(Args, Debug, Clone)]
pub struct TransferArgs {
    /// Recipient's X25519 public key (base64). The bundle is encrypted so only
    /// the holder of the matching secret can read it.
    #[arg(long)]
    pub dest: String,
    /// Output path for the bundle JSON. Default:
    /// `~/.neoth/exports/transfer-<unix>.json`.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Look-back window in days for the hot-tier memory to export. Default 7.
    #[arg(long)]
    pub days: Option<u32>,
    /// Show what WOULD be exported (recipient, event count, bundle size) without
    /// writing the file or emitting the audit frame.
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run_transfer(args: TransferArgs, output: OutputFormat) -> Result<()> {
    let dest = parse_b64_32(&args.dest, "--dest pubkey")
        .context("invalid --dest: expected a base64 X25519 public key (32 bytes)")?;
    let home = FreedomConfig::default_neoth_home();
    let days = args.days.unwrap_or(DEFAULT_WINDOW_DAYS);

    let (payload, event_count) = collect_memory_payload(&home, days)?;
    let signing_key = crate::wal::signing::load_or_init_signing_key(
        &crate::wal::signing::default_signing_key_path(),
    )
    .context("load operator signing key")?;
    let ts_unix = now_unix();
    let bundle = transfer_bundle::encrypt_for(&payload, &dest, &signing_key, ts_unix)?;
    let bundle_json = serde_json::to_vec_pretty(&bundle)?;

    if args.dry_run {
        render(&args.dest, event_count, bundle_json.len(), None, output);
        return Ok(());
    }

    let out_path = args
        .out
        .clone()
        .unwrap_or_else(|| home.join("exports").join(format!("transfer-{ts_unix}.json")));
    write_atomic(&out_path, &bundle_json).context("write transfer bundle")?;
    emit_transfer_exported(&args.dest, bundle_json.len(), event_count, days);
    render(&args.dest, event_count, bundle_json.len(), Some(&out_path), output);
    Ok(())
}

/// Collect a JSON dump of the last `days` of hot-tier `idx_episode` rows.
/// Missing `views.db` → empty payload (a fresh install has nothing to transfer).
fn collect_memory_payload(home: &Path, days: u32) -> Result<(Vec<u8>, usize)> {
    let db_path = home.join("views.db");
    if !db_path.exists() {
        let empty = serde_json::to_vec(&serde_json::json!({
            "schema": "neoth-memory-transfer-v1",
            "window_days": days,
            "events": [],
        }))?;
        return Ok((empty, 0));
    }
    let conn = Connection::open(&db_path).context("open views.db")?;
    collect_from_conn(&conn, days, now_ns())
}

/// Pure core: read `idx_episode` rows newer than `now_ns - days` from an open
/// connection. Split out so it's unit-testable with an in-memory db.
fn collect_from_conn(conn: &Connection, days: u32, now_ns: i64) -> Result<(Vec<u8>, usize)> {
    let cutoff = now_ns.saturating_sub((days as i64).saturating_mul(86_400 * 1_000_000_000));
    let mut stmt = conn.prepare(
        "SELECT event_id, ts_ns, text, importance FROM idx_episode \
         WHERE ts_ns >= ?1 ORDER BY ts_ns ASC",
    )?;
    let rows = stmt.query_map([cutoff], |r| {
        Ok(serde_json::json!({
            "event_id": r.get::<_, i64>(0)?,
            "ts_ns": r.get::<_, i64>(1)?,
            "text": r.get::<_, String>(2)?,
            "importance": r.get::<_, f64>(3)?,
        }))
    })?;
    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }
    let count = events.len();
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": "neoth-memory-transfer-v1",
        "window_days": days,
        "events": events,
    }))?;
    Ok((payload, count))
}

/// Best-effort `0xF5 MEMORY_TRANSFER_EXPORTED` audit. Skipped when a daemon owns
/// the WAL (one-shot would race its segment) — mirrors the `neoth dream now`
/// pattern. Records only metadata (recipient + size + counts), never plaintext.
fn emit_transfer_exported(dest_b64: &str, bundle_bytes: usize, events: usize, days: u32) {
    let pidfile = crate::daemon::pidfile::default_pidfile();
    if matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    ) {
        tracing::info!(
            "transfer: daemon live — skipping one-shot 0xF5 audit to avoid a writer race"
        );
        return;
    }
    let segment = FreedomConfig::default_wal_dir().join("000001.wal");
    if let Some(parent) = segment.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let (writer, _join) = match crate::wal::writer::spawn(segment) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "transfer: WAL writer spawn failed; 0xF5 not recorded");
            return;
        }
    };
    let payload = serde_json::to_vec(&serde_json::json!({
        "dest_pubkey_b64": dest_b64,
        "bundle_bytes": bundle_bytes,
        "events_exported": events,
        "window_days": days,
        "ts_unix": now_unix(),
    }))
    .unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_MEMORY_TRANSFER_EXPORTED,
        &payload,
    )
    .build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(error = %e, "transfer: 0xF5 frame append failed (audit gap)");
    }
}

/// Atomic write via `.tmp` + rename (Windows-safe: remove target first).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn render(dest: &str, events: usize, bytes: usize, out: Option<&Path>, output: OutputFormat) {
    let dest_short = &dest[..dest.len().min(16)];
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "dest_pubkey": dest,
                "events_exported": events,
                "bundle_bytes": bytes,
                "out": out.map(|p| p.display().to_string()),
                "dry_run": out.is_none(),
            })
        ),
        OutputFormat::Table => match out {
            None => println!(
                "[dry-run] would export {events} event(s) → {bytes}-byte sealed bundle for {dest_short}…"
            ),
            Some(p) => {
                println!("✓ Exported {events} event(s) → {bytes}-byte sealed bundle for {dest_short}…");
                println!("  → {}", p.display());
            }
        },
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn seed(conn: &Connection, rows: &[(i64, i64, &str, f64)]) {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS idx_episode ( \
                event_id INTEGER PRIMARY KEY, ts_ns INTEGER NOT NULL, \
                text TEXT NOT NULL, importance REAL DEFAULT 0.5)",
        )
        .unwrap();
        let mut stmt = conn
            .prepare("INSERT INTO idx_episode (event_id, ts_ns, text, importance) VALUES (?1,?2,?3,?4)")
            .unwrap();
        for (id, ts, text, imp) in rows {
            stmt.execute(rusqlite::params![id, ts, text, imp]).unwrap();
        }
    }

    #[test]
    fn collect_from_conn_dumps_rows_in_window() {
        let conn = Connection::open_in_memory().unwrap();
        let now = 100 * 86_400 * 1_000_000_000i64;
        seed(
            &conn,
            &[
                (1, now - 1_000_000_000, "recent", 0.9),
                (2, now - 2 * 86_400 * 1_000_000_000, "two days ago", 0.5),
            ],
        );
        let (payload, count) = collect_from_conn(&conn, 7, now).unwrap();
        assert_eq!(count, 2);
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(v["events"].as_array().unwrap().len(), 2);
        assert_eq!(v["schema"], "neoth-memory-transfer-v1");
        assert_eq!(v["window_days"], 7);
    }

    #[test]
    fn collect_from_conn_excludes_rows_outside_window() {
        let conn = Connection::open_in_memory().unwrap();
        let now = 100 * 86_400 * 1_000_000_000i64;
        seed(
            &conn,
            &[
                (1, now - 1_000_000_000, "inside", 0.9),
                (2, now - 30 * 86_400 * 1_000_000_000, "30 days ago", 0.5),
            ],
        );
        let (_payload, count) = collect_from_conn(&conn, 7, now).unwrap();
        assert_eq!(count, 1, "the 30-day-old row is outside the 7-day window");
    }

    #[test]
    fn collect_memory_payload_missing_db_is_empty() {
        let dir = tempdir().unwrap();
        let (payload, count) = collect_memory_payload(dir.path(), 7).unwrap();
        assert_eq!(count, 0);
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(v["events"].as_array().unwrap().is_empty());
    }

    #[test]
    fn write_atomic_round_trips_and_leaves_no_tmp() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("exports").join("b.json");
        write_atomic(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        assert!(!path.with_extension("json.tmp").exists());
        // Overwrite works (Windows-safe path).
        write_atomic(&path, b"world").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"world");
    }

    /// End-to-end: collect → encrypt → decrypt recovers the same memory dump.
    #[test]
    fn transfer_payload_round_trips_through_the_bundle() {
        use crate::memory::transfer_bundle::{decrypt_with, encrypt_for};
        use ed25519_dalek::SigningKey;
        use x25519_dalek::{PublicKey, StaticSecret};

        let conn = Connection::open_in_memory().unwrap();
        let now = 100 * 86_400 * 1_000_000_000i64;
        seed(&conn, &[(1, now - 1_000_000_000, "secret note", 0.9)]);
        let (payload, _count) = collect_from_conn(&conn, 7, now).unwrap();

        let rx_secret = [7u8; 32];
        let rx_pub = PublicKey::from(&StaticSecret::from(rx_secret)).to_bytes();
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let bundle = encrypt_for(&payload, &rx_pub, &sk, 1).unwrap();
        let recovered = decrypt_with(&bundle, &rx_secret).unwrap();
        assert_eq!(recovered, payload);
        let v: serde_json::Value = serde_json::from_slice(&recovered).unwrap();
        assert_eq!(v["events"][0]["text"], "secret note");
    }
}
