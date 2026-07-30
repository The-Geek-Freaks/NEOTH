//! A3-01 — `neoth transfer`: recipient-encrypted, operator-signed memory
//! bundles between NEOTH instances.
//!
//! Subcommands:
//!   - `export --dest <x25519_pub_b64>` — seal the last N days of hot-tier
//!     memory FOR a recipient (ephemeral X25519 ECDH → HKDF-SHA256 →
//!     AES-256-GCM, ed25519-signed). Size-capped + audited (`0xF5`).
//!   - `verify <bundle>` — check a received bundle's schema + recipient +
//!     signature WITHOUT decrypting (safe on an untrusted file). Five distinct
//!     verdicts.
//!   - `inspect <bundle>` — print a bundle's metadata (no decrypt).
//!   - `import <bundle>` — decrypt with the operator's managed transfer key +
//!     recover the memory dump.
//!
//! The operator's X25519 receiving keypair is auto-managed at
//! `~/.neoth/wal/transfer.key` (DAU-safe, zero interaction). Share its public
//! half via `neoth identity pubkey`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use rusqlite::Connection;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::memory::transfer_bundle::{self, TransferBundle, VerifyVerdict, parse_b64_32};

/// Default look-back window for the hot-tier memory export (days).
const DEFAULT_WINDOW_DAYS: u32 = 7;

#[derive(Args, Debug, Clone)]
pub struct TransferArgs {
    #[command(subcommand)]
    pub action: TransferAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TransferAction {
    /// Export a recipient-encrypted, signed memory bundle.
    Export {
        /// Recipient's X25519 public key (base64) — from their
        /// `neoth identity pubkey`.
        #[arg(long)]
        dest: String,
        /// Output path. Default `~/.neoth/exports/transfer-<unix>.json`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Look-back window in days. Default 7.
        #[arg(long)]
        days: Option<u32>,
        /// Show what WOULD be exported without writing or auditing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Verify a received bundle (schema + recipient + signature) WITHOUT
    /// decrypting. `--pubkey` pins the expected sender's ed25519 key for true
    /// attribution.
    Verify {
        /// Path to the `.json` bundle.
        file: PathBuf,
        /// Expected sender's ed25519 public key (base64) to verify against.
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Print a bundle's metadata (schema, recipient, signer, sizes) — no decrypt.
    Inspect {
        /// Path to the `.json` bundle.
        file: PathBuf,
    },
    /// Decrypt a received bundle with the managed transfer key + recover the
    /// memory dump (written to `--out` or `~/.neoth/imports/`).
    Import {
        /// Path to the `.json` bundle.
        file: PathBuf,
        /// Where to write the recovered plaintext JSON. Default
        /// `~/.neoth/imports/import-<unix>.json`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Expected sender's ed25519 public key (base64) — import refuses a
        /// bundle that doesn't verify against it when given.
        #[arg(long)]
        pubkey: Option<String>,
    },
}

pub async fn run_transfer(args: TransferArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        TransferAction::Export {
            dest,
            out,
            days,
            dry_run,
        } => run_export(dest, out, days, dry_run, output).await,
        TransferAction::Verify { file, pubkey } => run_verify(file, pubkey, output),
        TransferAction::Inspect { file } => run_inspect(file, output),
        TransferAction::Import { file, out, pubkey } => run_import(file, out, pubkey, output),
    }
}

// ── export ───────────────────────────────────────────────────────────────────

async fn run_export(
    dest_b64: String,
    out: Option<PathBuf>,
    days: Option<u32>,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    let dest = parse_b64_32(&dest_b64, "--dest pubkey")
        .context("invalid --dest: expected a base64 X25519 public key (32 bytes)")?;
    let home = FreedomConfig::default_neoth_home();
    let cfg = FreedomConfig::load_from_default_path_or_default()?;
    let caps = &cfg.transfer;
    let days = days.unwrap_or(DEFAULT_WINDOW_DAYS);

    let (payload, event_count) = collect_memory_payload(&home, days)?;
    // Size caps (#3): refuse a runaway export BEFORE encrypting.
    if event_count > caps.max_events {
        anyhow::bail!(
            "export refused: {event_count} events exceeds transfer.max_events={} \
             — narrow the window with --days or raise the cap",
            caps.max_events
        );
    }
    if payload.len() > caps.max_plaintext_bytes {
        anyhow::bail!(
            "export refused: {} plaintext bytes exceeds transfer.max_plaintext_bytes={}",
            payload.len(),
            caps.max_plaintext_bytes
        );
    }

    let signing_key = crate::wal::signing::load_or_init_signing_key(
        &crate::wal::signing::default_signing_key_path(),
    )
    .context("load operator signing key")?;
    let ts_unix = now_unix();
    let bundle = transfer_bundle::encrypt_for(&payload, &dest, &signing_key, ts_unix)?;
    let bundle_json = serde_json::to_vec_pretty(&bundle)?;
    if bundle_json.len() > caps.max_bundle_bytes {
        anyhow::bail!(
            "export refused: {} bundle bytes exceeds transfer.max_bundle_bytes={}",
            bundle_json.len(),
            caps.max_bundle_bytes
        );
    }

    if dry_run {
        render_export(&dest_b64, event_count, bundle_json.len(), None, output);
        return Ok(());
    }

    // Audit pre-flight (#1): under required-audit, a live daemon whose audit-RPC
    // listener is unreachable means the export would go un-audited — refuse.
    let pidfile = home.join("neothd.pid");
    let daemon_live = crate::daemon::pidfile::live_daemon_pid(&pidfile)
        .with_context(|| format!("inspect daemon ownership via {}", pidfile.display()))?
        .is_some();
    crate::daemon::audit_rpc::enforce_required_audit(
        cfg.audit_rpc.required_for_oneshot_permission_events,
        daemon_live,
        &home,
    )
    .context("transfer export refused: required audit cannot be written")?;

    let out_path = out.unwrap_or_else(|| {
        home.join("exports")
            .join(format!("transfer-{ts_unix}.json"))
    });
    write_atomic(&out_path, &bundle_json).context("write transfer bundle")?;
    emit_transfer_exported(
        &home,
        daemon_live,
        &dest_b64,
        bundle_json.len(),
        event_count,
        days,
        cfg.audit_rpc.required_for_oneshot_permission_events,
    )
    .await
    .context("transfer bundle was written, but its required export audit did not complete")?;
    render_export(
        &dest_b64,
        event_count,
        bundle_json.len(),
        Some(&out_path),
        output,
    );
    Ok(())
}

/// `0xF5 MEMORY_TRANSFER_EXPORTED` audit. When a daemon owns the WAL, FORWARD
/// over the same-user OS audit-RPC channel (#1 — `0xF5` is allowlisted) instead of
/// silently skipping; otherwise open a one-shot writer. Metadata only (recipient
/// + sizes + counts), never plaintext.
async fn emit_transfer_exported(
    home: &Path,
    daemon_live: bool,
    dest_b64: &str,
    bundle_bytes: usize,
    events: usize,
    days: u32,
    required: bool,
) -> Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "dest_pubkey_b64": dest_b64,
        "bundle_bytes": bundle_bytes,
        "events_exported": events,
        "window_days": days,
        "ts_unix": now_unix(),
    }))
    .unwrap_or_default();
    if daemon_live {
        if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
            home,
            crate::wal::events::EVENT_TYPE_MEMORY_TRANSFER_EXPORTED,
            &payload,
        )
        .await
        {
            if required {
                return Err(anyhow::anyhow!(
                    "required 0xF5 audit forward was not acknowledged by the live daemon: {e}"
                ));
            }
            tracing::warn!(error = %e, "transfer: 0xF5 forward skipped (daemon listener unreachable)");
        }
        return Ok(());
    }
    let wal_dir = home.join("wal");
    if let Err(e) = std::fs::create_dir_all(&wal_dir) {
        if required {
            return Err(e).with_context(|| {
                format!(
                    "create required transfer audit WAL directory {}",
                    wal_dir.display()
                )
            });
        }
        tracing::warn!(
            error = %e,
            wal_dir = %wal_dir.display(),
            "transfer: WAL directory unavailable; 0xF5 not recorded"
        );
        return Ok(());
    }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "transfer-export");
    let (writer, completion) =
        match crate::wal::writer::spawn_for_home_with_completion(segment, home.to_path_buf()) {
            Ok(pair) => pair,
            Err(e) => {
                if required {
                    return Err(e).context("spawn required home-bound transfer audit WAL writer");
                }
                tracing::warn!(error = %e, "transfer: WAL writer spawn failed; 0xF5 not recorded");
                return Ok(());
            }
        };
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_MEMORY_TRANSFER_EXPORTED,
        &payload,
    )
    .build();
    let append_result = writer.append(header, payload).await;
    drop(writer);
    let completion_result = completion.wait().await;
    if required {
        return match (append_result, completion_result) {
            (Ok(_), Ok(())) => Ok(()),
            (Err(append), Ok(())) => {
                Err(append).context("append required 0xF5 transfer audit frame")
            }
            (Ok(_), Err(shutdown)) => {
                Err(shutdown).context("finalize required transfer audit WAL writer")
            }
            (Err(append), Err(shutdown)) => Err(anyhow::anyhow!(
                "{append}; additionally failed to finalize required transfer audit WAL: \
                 {shutdown}"
            )),
        };
    }
    if let Err(e) = append_result {
        tracing::warn!(error = %e, "transfer: 0xF5 frame append failed (audit gap)");
    }
    if let Err(e) = completion_result {
        tracing::warn!(error = %e, "transfer: 0xF5 WAL writer finalization failed (audit gap)");
    }
    Ok(())
}

// ── verify / inspect / import ─────────────────────────────────────────────────

/// Read + parse a bundle file, refusing one larger than the configured bundle
/// cap (a hostile/oversized file can't force a huge allocation).
fn read_bundle(file: &Path) -> Result<TransferBundle> {
    let cfg = FreedomConfig::load_from_default_path_or_default()?;
    let meta =
        std::fs::metadata(file).with_context(|| format!("stat bundle {}", file.display()))?;
    if meta.len() as usize > cfg.transfer.max_bundle_bytes {
        anyhow::bail!(
            "bundle {} is {} bytes — exceeds transfer.max_bundle_bytes={}",
            file.display(),
            meta.len(),
            cfg.transfer.max_bundle_bytes
        );
    }
    let bytes = std::fs::read(file).with_context(|| format!("read bundle {}", file.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse bundle {}", file.display()))
}

fn parse_expected_sender(pubkey: Option<&str>) -> Result<Option<[u8; 32]>> {
    match pubkey {
        Some(p) => Ok(Some(
            parse_b64_32(p, "--pubkey").context("invalid --pubkey: expected base64 ed25519 key")?,
        )),
        None => Ok(None),
    }
}

fn verdict_str(v: &VerifyVerdict) -> &'static str {
    match v {
        VerifyVerdict::SelfConsistent => "self_consistent",
        VerifyVerdict::VerifiedAgainstExpected => "verified_against_pinned_sender",
        VerifyVerdict::SignatureMismatch => "signature_mismatch",
        VerifyVerdict::WrongRecipient => "wrong_recipient",
        VerifyVerdict::UnsupportedSchema(_) => "unsupported_schema",
    }
}

fn run_verify(file: PathBuf, pubkey: Option<String>, output: OutputFormat) -> Result<()> {
    let bundle = read_bundle(&file)?;
    let expected = parse_expected_sender(pubkey.as_deref())?;
    // Recipient check against the operator's own transfer pubkey.
    let my_secret =
        transfer_bundle::load_or_init_transfer_key(&transfer_bundle::default_transfer_key_path())
            .context("load transfer key")?;
    // my_secret is Zeroizing<[u8;32]>; auto-deref coerces to &[u8;32].
    let my_pub = transfer_bundle::transfer_pubkey_b64(&my_secret);
    let my_pub_bytes = parse_b64_32(&my_pub, "transfer pubkey")?;
    let verdict = transfer_bundle::verify_bundle(&bundle, Some(&my_pub_bytes), expected.as_ref());
    let ok = matches!(
        verdict,
        VerifyVerdict::SelfConsistent | VerifyVerdict::VerifiedAgainstExpected
    );
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "verdict": verdict_str(&verdict),
                "verified": ok,
                "signer_pubkey": bundle.signer_pubkey_b64,
            })
        ),
        OutputFormat::Table => {
            let detail = match &verdict {
                VerifyVerdict::SelfConsistent => {
                    "✓ self-consistent (no post-sign tamper) — NOT identity-proven (no --pubkey)"
                        .to_string()
                }
                VerifyVerdict::VerifiedAgainstExpected => {
                    "✓ verified against the pinned sender pubkey — true attribution".to_string()
                }
                VerifyVerdict::SignatureMismatch => {
                    "✗ signature mismatch — tampered or signed by a different key".to_string()
                }
                VerifyVerdict::WrongRecipient => {
                    "✗ wrong recipient — this bundle is addressed to a different key".to_string()
                }
                VerifyVerdict::UnsupportedSchema(v) => {
                    format!("✗ unsupported schema version {v} — this build can't read it")
                }
            };
            println!("{detail}");
        }
    }
    if !ok {
        // Non-zero exit so a script can gate on verification.
        anyhow::bail!("bundle verification failed: {}", verdict_str(&verdict));
    }
    Ok(())
}

fn run_inspect(file: PathBuf, output: OutputFormat) -> Result<()> {
    let bundle = read_bundle(&file)?;
    let cipher_bytes = bundle.ciphertext_b64.len() * 3 / 4; // approx decoded size
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "schema_version": bundle.schema_version,
                "dest_pubkey_b64": bundle.dest_pubkey_b64,
                "signer_pubkey_b64": bundle.signer_pubkey_b64,
                "ciphertext_bytes_approx": cipher_bytes,
                "ts_unix": bundle.ts_unix,
            })
        ),
        OutputFormat::Table => {
            println!("schema_version : {}", bundle.schema_version);
            println!("recipient (dest): {}", bundle.dest_pubkey_b64);
            println!("signer (ed25519): {}", bundle.signer_pubkey_b64);
            println!("ciphertext     : ~{cipher_bytes} bytes (encrypted — run `import` to read)");
            println!("ts_unix        : {}", bundle.ts_unix);
        }
    }
    Ok(())
}

fn run_import(
    file: PathBuf,
    out: Option<PathBuf>,
    pubkey: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let bundle = read_bundle(&file)?;
    let cfg = FreedomConfig::load_from_default_path_or_default()?;
    let my_secret =
        transfer_bundle::load_or_init_transfer_key(&transfer_bundle::default_transfer_key_path())
            .context("load transfer key")?;
    // my_secret is Zeroizing<[u8;32]>; auto-deref coerces to &[u8;32].
    let my_pub_bytes = parse_b64_32(&transfer_bundle::transfer_pubkey_b64(&my_secret), "pub")?;
    let expected = parse_expected_sender(pubkey.as_deref())?;

    // Verify FIRST — refuse to decrypt a wrong-recipient / unsupported / (when
    // a sender is pinned) unverified bundle.
    let verdict = transfer_bundle::verify_bundle(&bundle, Some(&my_pub_bytes), expected.as_ref());
    match &verdict {
        VerifyVerdict::SelfConsistent if expected.is_none() => {}
        VerifyVerdict::VerifiedAgainstExpected => {}
        other => anyhow::bail!(
            "import refused: {} — run `neoth transfer verify` for details",
            verdict_str(other)
        ),
    }

    let recovered = transfer_bundle::decrypt_with(&bundle, &my_secret)
        .context("decrypt failed (wrong key or tampered ciphertext)")?;
    if recovered.len() > cfg.transfer.max_plaintext_bytes {
        anyhow::bail!(
            "import refused: recovered {} bytes exceeds transfer.max_plaintext_bytes={}",
            recovered.len(),
            cfg.transfer.max_plaintext_bytes
        );
    }
    let event_count = serde_json::from_slice::<serde_json::Value>(&recovered)
        .ok()
        .and_then(|v| v["events"].as_array().map(|a| a.len()))
        .unwrap_or(0);

    let home = FreedomConfig::default_neoth_home();
    let out_path = out.unwrap_or_else(|| {
        home.join("imports")
            .join(format!("import-{}.json", now_unix()))
    });
    write_atomic(&out_path, &recovered).context("write recovered bundle")?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "verdict": verdict_str(&verdict),
                "events_recovered": event_count,
                "bytes": recovered.len(),
                "out": out_path.display().to_string(),
            })
        ),
        OutputFormat::Table => {
            println!(
                "✓ imported {event_count} event(s) ({}) [{}]",
                recovered.len(),
                verdict_str(&verdict)
            );
            println!("  → {}", out_path.display());
            println!(
                "  (recovered to a file; merging into the live recall store is a follow-on slice)"
            );
        }
    }
    Ok(())
}

// ── shared helpers ────────────────────────────────────────────────────────────

/// Collect a JSON dump of the last `days` of hot-tier `idx_episode` rows.
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

/// Pure core: read `idx_episode` rows newer than `now_ns - days`.
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

fn render_export(
    dest: &str,
    events: usize,
    bytes: usize,
    out: Option<&Path>,
    output: OutputFormat,
) {
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
                println!(
                    "✓ Exported {events} event(s) → {bytes}-byte sealed bundle for {dest_short}…"
                );
                println!("  → {}", p.display());
            }
        },
    }
}

fn now_unix() -> u64 {
    crate::time::now_unix_secs()
}

fn now_ns() -> i64 {
    crate::time::now_unix_ns_i64()
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
            .prepare(
                "INSERT INTO idx_episode (event_id, ts_ns, text, importance) VALUES (?1,?2,?3,?4)",
            )
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
        assert_eq!(count, 1);
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
    }

    #[test]
    fn read_bundle_refuses_oversized_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("big.json");
        // 20 MiB of zeros — over the 16 MiB default bundle cap.
        std::fs::write(&path, vec![b'0'; 20 * 1024 * 1024]).unwrap();
        let err = read_bundle(&path).unwrap_err();
        assert!(err.to_string().contains("max_bundle_bytes"), "got: {err}");
    }

    #[test]
    fn verdict_str_covers_all_five() {
        use VerifyVerdict::*;
        assert_eq!(verdict_str(&SelfConsistent), "self_consistent");
        assert_eq!(
            verdict_str(&VerifiedAgainstExpected),
            "verified_against_pinned_sender"
        );
        assert_eq!(verdict_str(&SignatureMismatch), "signature_mismatch");
        assert_eq!(verdict_str(&WrongRecipient), "wrong_recipient");
        assert_eq!(verdict_str(&UnsupportedSchema(2)), "unsupported_schema");
    }

    /// End-to-end: export-shape → verify (wrong/right recipient) → import recovers.
    #[test]
    fn export_verify_import_round_trip_via_bundle() {
        use crate::memory::transfer_bundle::{encrypt_for, transfer_pubkey_b64};
        use ed25519_dalek::SigningKey;

        let conn = Connection::open_in_memory().unwrap();
        let now = 100 * 86_400 * 1_000_000_000i64;
        seed(&conn, &[(1, now - 1_000_000_000, "secret note", 0.9)]);
        let (payload, _c) = collect_from_conn(&conn, 7, now).unwrap();

        let rx_secret = [7u8; 32];
        let rx_pub = parse_b64_32(&transfer_pubkey_b64(&rx_secret), "p").unwrap();
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let bundle = encrypt_for(&payload, &rx_pub, &sk, 1).unwrap();

        // verify_bundle: right recipient + no pin → self-consistent.
        assert_eq!(
            transfer_bundle::verify_bundle(&bundle, Some(&rx_pub), None),
            VerifyVerdict::SelfConsistent
        );
        // wrong recipient.
        let other = parse_b64_32(&transfer_pubkey_b64(&[9u8; 32]), "p").unwrap();
        assert_eq!(
            transfer_bundle::verify_bundle(&bundle, Some(&other), None),
            VerifyVerdict::WrongRecipient
        );
        // decrypt recovers.
        let recovered = transfer_bundle::decrypt_with(&bundle, &rx_secret).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&recovered).unwrap();
        assert_eq!(v["events"][0]["text"], "secret note");
    }
}
