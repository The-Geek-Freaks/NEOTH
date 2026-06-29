//! `neoth migrate` — explicit schema migration runner.
//!
//! `neoth serve` runs migrations automatically on startup (see
//! `memory::store::open`). This command exposes the same path for
//! operators who want to migrate offline (without booting the daemon),
//! inspect the migration plan, or pin a specific target version for
//! rollback testing.
//!
//! Subcommands:
//!   `list`         — print every registered migration + current db version
//!   `run`          — apply migrations up to the current `SCHEMA_VERSION`
//!   `run --to N`   — apply migrations only up to version N (advanced)
//!   `--dry-run`    — print the plan without touching the database
//!   `wal --to-v2`  — re-encode v1 WAL segments as v2 compressed (zstd-3)
//!
//! The dispatcher in `memory::migrations` is the source of truth for schema
//! migrations; this command is a thin operator handle over it.
//!
//! ## WAL migration (`wal --to-v2`)
//!
//! Workstream F (CT-10/E-20/V1x-06): re-encodes every v1 segment in the
//! operator's WAL directory as v2 (zstd-3 compressed). Safe to interrupt —
//! each segment is written atomically (temp file + rename). Reader handles
//! mixed v1+v2 directories so a partially-migrated WAL is always valid.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use rusqlite::Connection;

use crate::cli::OutputFormat;
use crate::memory::migrations;
use crate::memory::store;
use crate::wal::compress::compress_frames;
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::{
    ParsedSegmentHeader, SEGMENT_FLAG_COMPRESSED, SEGMENT_FORMAT_VERSION_V1, SEGMENT_HEADER_LEN,
    SegmentHeaderV3, parse_segment_header,
};

#[derive(Args, Debug, Clone)]
pub struct MigrateArgs {
    #[command(subcommand)]
    pub action: MigrateAction,
    /// Override the views.db path (mostly for tests).
    #[arg(long, value_name = "PATH", global = true)]
    pub db: Option<PathBuf>,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MigrateAction {
    /// List registered migrations + current db version.
    List,
    /// Apply migrations up to the highest registered version (or `--to N`).
    Run {
        /// Stop at this schema version (advanced; default = run to latest).
        #[arg(long, value_name = "N")]
        to: Option<i64>,
        /// Print the plan without modifying the database.
        #[arg(long)]
        dry_run: bool,
    },
    /// V03-04: revert `~/.neoth/` from a `neoth backup` tarball. Defaults
    /// to the most-recent backup in `~/.neoth/backups/`; pass `--from
    /// <path>` to pick a specific one. Use when a schema migration made
    /// views.db inconsistent and you want to fall back to a known-good
    /// snapshot.
    Rollback {
        /// Specific backup tarball to restore. Defaults to the
        /// newest-mtime file matching `neoth-*.tar.gz` under
        /// `~/.neoth/backups/`.
        #[arg(long, value_name = "PATH")]
        from: Option<std::path::PathBuf>,
        /// Override `~/.neoth/` target dir (mostly for tests).
        #[arg(long, value_name = "DIR")]
        home: Option<std::path::PathBuf>,
        /// Overwrite the target dir even if it's non-empty. Required when
        /// the daemon has live files (the common case post-migration).
        #[arg(long)]
        force: bool,
    },
    /// Workstream F (CT-10/E-20/V1x-06) — re-encode WAL segments.
    ///
    /// `neoth migrate wal --to-v2` walks every `*.wal` file in `<wal-dir>`
    /// (default `~/.neoth/wal/`), re-encodes each v1 segment as a v2
    /// zstd-3 compressed segment, and atomically renames it in place.
    ///
    /// Already-v2 segments are skipped. Safe to interrupt — each rename
    /// is atomic; a partially-migrated directory is always valid since the
    /// reader handles mixed v1+v2 segments.
    Wal {
        /// Re-encode all v1 segments as v2 zstd-3 compressed.
        #[arg(long)]
        to_v2: bool,
        /// Override the WAL directory (default `~/.neoth/wal/`).
        #[arg(long, value_name = "DIR")]
        wal_dir: Option<PathBuf>,
        /// Print which segments would be re-encoded without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
}

pub async fn run_migrate(args: MigrateArgs) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    match args.action {
        MigrateAction::List => list(&db_path, args.output),
        MigrateAction::Run { to, dry_run } => run(&db_path, to, dry_run, args.output),
        MigrateAction::Rollback { from, home, force } => {
            rollback(from, home, force, args.output).await
        }
        MigrateAction::Wal {
            to_v2,
            wal_dir,
            dry_run,
        } => {
            if !to_v2 {
                anyhow::bail!(
                    "`neoth migrate wal` requires --to-v2. \
                     Future sub-flags may add other actions."
                );
            }
            let dir = wal_dir.unwrap_or_else(default_wal_dir);
            migrate_wal_to_v2(&dir, dry_run, args.output)
        }
    }
}

/// Default WAL directory: `~/.neoth/wal/`.
fn default_wal_dir() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home().join("wal")
}

/// Write a v3-header + compressed body to `tmp_path`. Called by
/// `migrate_wal_to_v2` before the atomic rename. Handles mode 0600 on unix.
/// GOLD-PROG-12: migrated segments always use V3 headers (with epoch=0, since
/// they have never been finalized with epoch tracking).
fn write_v2_tmp(
    tmp_path: &std::path::Path,
    v2_hdr: &SegmentHeaderV3,
    compressed: &[u8],
) -> Result<()> {
    use std::io::Write;
    let mut f = open_tmp_file(tmp_path)?;
    f.write_all(&v2_hdr.to_le_bytes())
        .with_context(|| format!("write v3 header to {}", tmp_path.display()))?;
    f.write_all(compressed)
        .with_context(|| format!("write compressed body to {}", tmp_path.display()))?;
    f.sync_all()
        .with_context(|| format!("sync {}", tmp_path.display()))?;
    Ok(())
}

/// Open a file for writing with mode 0600 on unix, default perms on Windows.
fn open_tmp_file(path: &std::path::Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))
    }
}

/// Workstream F — re-encode all v1 WAL segments in `wal_dir` as v2 zstd-3.
///
/// For each `*.wal` file:
///   1. Parse the header to detect version.
///   2. Skip if already v2.
///   3. Collect all frames from the v1 body.
///   4. Compress the raw frame bytes with zstd-3.
///   5. Write v2-header + compressed bytes to a `.tmp` sibling.
///   6. Atomic rename onto the original path.
///
/// Returns `Ok(n)` where `n` is the count of segments successfully re-encoded.
fn migrate_wal_to_v2(wal_dir: &std::path::Path, dry_run: bool, output: OutputFormat) -> Result<()> {
    if !wal_dir.exists() {
        anyhow::bail!(
            "WAL directory {} does not exist. \
             Run `neoth serve` first or pass --wal-dir.",
            wal_dir.display()
        );
    }

    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(wal_dir)
        .with_context(|| format!("read WAL dir {}", wal_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("wal"))
        .collect();
    entries.sort();

    let mut migrated = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    for path in &entries {
        let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;

        let parsed = match parse_segment_header(&raw) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "WARN: {} — cannot parse header: {e}; skipping",
                    path.display()
                );
                errors += 1;
                continue;
            }
        };

        if parsed.segment_format_version() != SEGMENT_FORMAT_VERSION_V1 {
            // Already v2 or v3 (or future version) — skip.
            // GOLD-PROG-12: V3 segments are already at the current format.
            // V2 segments on disk are left as-is (their epoch=0 is correctly
            // returned by ParsedSegmentHeader::compaction_epoch() via the
            // accessor — they have never been finalized with epoch tracking).
            skipped += 1;
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {}
                OutputFormat::Table => {
                    println!(
                        "  skip (already v{}) {}",
                        parsed.segment_format_version(),
                        path.display()
                    );
                }
            }
            continue;
        }

        // Extract raw frame bytes (everything after the 60-byte v1 header).
        let frames_raw = &raw[SEGMENT_HEADER_LEN..];

        // Validate that frames are parseable (sanity check, not full walk).
        if !frames_raw.is_empty() {
            if let Err(e) = decode_frame(frames_raw) {
                eprintln!(
                    "WARN: {} — first frame unparseable: {e}; skipping to avoid data loss",
                    path.display()
                );
                errors += 1;
                continue;
            }
        }

        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {}
            OutputFormat::Table => {
                let action = if dry_run { "would encode" } else { "encoding" };
                println!(
                    "  {action} {} ({} raw bytes)",
                    path.display(),
                    frames_raw.len()
                );
            }
        }

        if dry_run {
            migrated += 1;
            continue;
        }

        // Compress.
        let compressed =
            compress_frames(frames_raw).with_context(|| format!("compress {}", path.display()))?;

        // Build V3 header preserving original metadata. compaction_epoch=0
        // because this segment has never been finalized with epoch tracking
        // (GOLD-PROG-12). The reader returns epoch=0 for un-tracked segments.
        let v2_hdr = match parsed {
            ParsedSegmentHeader::V1(h) => SegmentHeaderV3::new(
                h.generation,
                h.segment_seq,
                h.first_event_id,
                h.segment_start_ts_ns,
                h.node_id,
                SEGMENT_FLAG_COMPRESSED,
                0, // compaction_epoch: first-ever migration, no prior finalize
            ),
            ParsedSegmentHeader::V2(_) | ParsedSegmentHeader::V3(_) => {
                unreachable!("already filtered above")
            }
        };

        // Write to .tmp sibling then atomic rename onto original.
        // Mode 0600 on unix; Windows inherits parent DACL (migration is a
        // one-shot offline tool, not the hot writer path).
        let tmp = path.with_extension("wal.tmp");
        write_v2_tmp(&tmp, &v2_hdr, &compressed)
            .with_context(|| format!("write tmp {}", tmp.display()))?;

        // Atomic rename.
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;

        migrated += 1;
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {}
            OutputFormat::Table => {
                println!(
                    "  done {} raw={} compressed={} ratio={:.1}%",
                    path.display(),
                    frames_raw.len(),
                    compressed.len(),
                    compressed.len() as f64 / frames_raw.len().max(1) as f64 * 100.0,
                );
            }
        }
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "dry_run": dry_run,
                    "migrated": migrated,
                    "skipped": skipped,
                    "errors": errors,
                    "wal_dir": wal_dir.display().to_string(),
                })
            );
        }
        OutputFormat::Table => {
            let action = if dry_run { "would migrate" } else { "migrated" };
            println!(
                "\n{action} {migrated} segment(s), skipped {skipped}, errors {errors} — {}",
                wal_dir.display()
            );
        }
    }
    Ok(())
}

/// V03-04 2026-05-17: restore the operator's `~/.neoth/` from a
/// `neoth backup`-generated tarball. Thin convenience wrapper over
/// `daemon::backup::restore_backup` — distinct from `neoth restore`
/// in that it auto-discovers the latest backup when `--from` isn't
/// passed, which is the common "I messed up the migration, just
/// revert" path.
async fn rollback(
    from: Option<std::path::PathBuf>,
    home: Option<std::path::PathBuf>,
    force: bool,
    output: OutputFormat,
) -> Result<()> {
    let home = home.unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);
    let archive = match from {
        Some(p) => p,
        None => {
            let backup_dir = home.join("backups");
            find_latest_backup(&backup_dir).with_context(|| {
                format!(
                    "no `neoth-*.tar.gz` found under {}. Pass --from <path> \
                     or run `neoth backup` first.",
                    backup_dir.display()
                )
            })?
        }
    };
    let n = crate::daemon::backup::restore_backup(&archive, &home, force)
        .with_context(|| format!("restore from {}", archive.display()))?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "rolled_back_from": archive.display().to_string(),
                    "restored_into": home.display().to_string(),
                    "entries": n,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "rolled back {} entry/entries into {} from {}",
                n,
                home.display(),
                archive.display(),
            );
        }
    }
    Ok(())
}

/// Find the most-recent-mtime file matching `neoth-*.tar.gz` under
/// `backup_dir`. Returns `Err` when the dir doesn't exist OR contains
/// no matching files (operator hasn't run `neoth backup` yet).
fn find_latest_backup(backup_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    if !backup_dir.exists() {
        anyhow::bail!("backup dir {} does not exist", backup_dir.display());
    }
    let mut newest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(backup_dir)
        .with_context(|| format!("read_dir {}", backup_dir.display()))?
    {
        let entry = entry.with_context(|| "read backup dir entry")?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !(name.starts_with("neoth-") && name.ends_with(".tar.gz")) {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .with_context(|| format!("stat {}", path.display()))?;
        match &newest {
            Some((best_ts, _)) if *best_ts >= mtime => {}
            _ => newest = Some((mtime, path)),
        }
    }
    newest
        .map(|(_, p)| p)
        .ok_or_else(|| anyhow::anyhow!("no neoth-*.tar.gz files found"))
}

fn list(db_path: &std::path::Path, output: OutputFormat) -> Result<()> {
    let current = current_version(db_path);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let registry: Vec<_> = migrations::MIGRATIONS
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "from": m.from,
                        "to": m.to,
                        "description": m.description,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "db_path": db_path.display().to_string(),
                    "current_version": current,
                    "target_version": store::SCHEMA_VERSION,
                    "migrations": registry,
                })
            );
        }
        OutputFormat::Table => {
            println!("# db at {}: schema v{}", db_path.display(), current);
            println!("# target version: v{}", store::SCHEMA_VERSION);
            if migrations::MIGRATIONS.is_empty() {
                println!("(no migrations registered)");
                return Ok(());
            }
            for m in migrations::MIGRATIONS {
                let marker = if m.to <= current {
                    "[applied]"
                } else {
                    "[pending]"
                };
                println!("  {marker} v{}→v{}  {}", m.from, m.to, m.description);
            }
        }
    }
    Ok(())
}

fn run(
    db_path: &std::path::Path,
    explicit_to: Option<i64>,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    let target = explicit_to.unwrap_or(store::SCHEMA_VERSION);
    let current = current_version(db_path);
    if current >= target {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "no_op": true,
                        "current": current,
                        "target": target,
                    })
                );
            }
            OutputFormat::Table => {
                println!("schema is at v{current}; target v{target} already reached. No-op.");
            }
        }
        return Ok(());
    }

    let plan: Vec<_> = migrations::MIGRATIONS
        .iter()
        .filter(|m| m.from >= current && m.to <= target)
        .collect();

    if dry_run {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let rows: Vec<_> = plan
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "from": m.from,
                            "to": m.to,
                            "description": m.description,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::json!({
                        "dry_run": true,
                        "current": current,
                        "target": target,
                        "plan": rows,
                    })
                );
            }
            OutputFormat::Table => {
                println!(
                    "# dry-run: would migrate v{current} → v{target} via {} step(s):",
                    plan.len()
                );
                for m in &plan {
                    println!("  v{}→v{}  {}", m.from, m.to, m.description);
                }
            }
        }
        return Ok(());
    }

    // Real run. Open + migrate.
    let mut conn = Connection::open(db_path)
        .with_context(|| format!("open {} for migration", db_path.display()))?;
    let reached = migrations::migrate(&mut conn, current, target)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "applied": plan.len(),
                    "from": current,
                    "to": reached,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "migrated v{current} → v{reached} ({} step(s) applied)",
                plan.len()
            );
        }
    }
    Ok(())
}

fn current_version(db_path: &std::path::Path) -> i64 {
    let Ok(conn) = Connection::open(db_path) else {
        return 0;
    };
    migrations::current_version(&conn).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── Workstream F (CT-10/E-20/V1x-06): WAL migrate wal --to-v2 ──────────

    /// Helper: write a minimal v1 WAL segment (header + raw frames) to `path`.
    fn write_v1_segment(path: &std::path::Path, payload: &[u8]) {
        use crate::wal::frame::encode_frame;
        use crate::wal::header::EventHeaderV2;
        use crate::wal::header::{CRC_LEN, HEADER_BODY_LEN, PREAMBLE_LEN};
        use crate::wal::hlc::Hlc;
        use crate::wal::segment_header::SegmentHeader;
        use crate::wal::types::{EventFlags, EventId, Importance, NodeId, SessionId};
        use std::io::Write;

        let hdr = EventHeaderV2 {
            wal_format_version: EventHeaderV2::WAL_FORMAT_VERSION,
            event_schema_version: EventHeaderV2::EVENT_SCHEMA_VERSION,
            event_type: 0x01,
            event_subtype: 0,
            flags: EventFlags::empty(),
            header_len: HEADER_BODY_LEN as u16,
            reserved_len: 0,
            total_len: (PREAMBLE_LEN + HEADER_BODY_LEN + payload.len() + CRC_LEN) as u32,
            payload_len: payload.len() as u32,
            generation: 1,
            event_id: EventId(1),
            hlc: Hlc::new(1_700_000_000_000_000_000, 1).unwrap(),
            importance: Importance::new(0.5).unwrap(),
            scope: crate::wal::types::WalScope::UNSET,
            category: crate::wal::types::WalCategory::UNSET,
            session_id: SessionId([0u8; 16]),
            node_id: NodeId([0u8; 16]),
            payload_hash: 0,
        };
        let seg_hdr = SegmentHeader::new(0, 1, 1, 1_700_000_000_000_000_000, [0u8; 16]);
        let frame = encode_frame(&hdr, payload);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        f.write_all(&seg_hdr.to_le_bytes()).unwrap();
        f.write_all(&frame).unwrap();
    }

    #[test]
    fn migrate_wal_to_v2_converts_v1_segment() {
        use crate::wal::compress::decompress_frames;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::{
            ParsedSegmentHeader, SEGMENT_HEADER_V3_LEN, parse_segment_header,
        };

        let dir = tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg = wal_dir.join("000001.wal");
        write_v1_segment(&seg, b"migration-payload");

        // Sanity: starts as v1.
        let before = std::fs::read(&seg).unwrap();
        let p_before = parse_segment_header(&before).unwrap();
        assert!(matches!(p_before, ParsedSegmentHeader::V1(_)));

        // Run migration.
        migrate_wal_to_v2(&wal_dir, false, OutputFormat::Table).unwrap();

        // After: must be v3 + compressed (GOLD-PROG-12: migration emits V3).
        let after = std::fs::read(&seg).unwrap();
        let p_after = parse_segment_header(&after).unwrap();
        assert!(
            matches!(p_after, ParsedSegmentHeader::V3(_)),
            "segment must be v3 after migration (GOLD-PROG-12); got {p_after:?}"
        );
        assert!(
            p_after.is_compressed(),
            "segment must have COMPRESSED flag set"
        );
        assert_eq!(
            p_after.compaction_epoch(),
            0,
            "migrated segment epoch must be 0 (no prior finalize)"
        );

        // Frames must decompress to the original payload.
        let raw = decompress_frames(&after[SEGMENT_HEADER_V3_LEN..]).unwrap();
        let decoded = decode_frame(&raw).unwrap();
        assert_eq!(decoded.payload, b"migration-payload");
    }

    #[test]
    fn migrate_wal_to_v2_skips_already_v2_segment() {
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::SegmentHeaderV2;
        use std::io::Write;

        let dir = tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg = wal_dir.join("000001.wal");

        // Write a v2 segment manually.
        let raw_frames = b"some-frames";
        let compressed = compress_frames(raw_frames).unwrap();
        let v2_hdr = SegmentHeaderV2::new(
            0,
            1,
            0,
            1_700_000_000_000_000_000,
            [0u8; 16],
            SEGMENT_FLAG_COMPRESSED,
        );
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&seg)
                .unwrap();
            f.write_all(&v2_hdr.to_le_bytes()).unwrap();
            f.write_all(&compressed).unwrap();
        }
        let size_before = std::fs::metadata(&seg).unwrap().len();

        // Run migration — must skip.
        migrate_wal_to_v2(&wal_dir, false, OutputFormat::Table).unwrap();

        // File must be unchanged.
        let size_after = std::fs::metadata(&seg).unwrap().len();
        assert_eq!(size_before, size_after, "v2 segment must not be re-encoded");
    }

    #[test]
    fn migrate_wal_dry_run_does_not_write() {
        use crate::wal::segment_header::parse_segment_header;

        let dir = tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg = wal_dir.join("000001.wal");
        write_v1_segment(&seg, b"dry-run-payload");
        let before = std::fs::read(&seg).unwrap();
        let p_before = parse_segment_header(&before).unwrap();

        migrate_wal_to_v2(&wal_dir, true /* dry_run */, OutputFormat::Table).unwrap();

        let after = std::fs::read(&seg).unwrap();
        assert_eq!(before, after, "dry-run must not modify the segment");
        // Still v1.
        let p_after = parse_segment_header(&after).unwrap();
        assert_eq!(
            p_before.segment_format_version(),
            p_after.segment_format_version()
        );
    }

    #[test]
    fn migrate_wal_to_v2_mixed_dir_v1_skips_v2() {
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{
            ParsedSegmentHeader, SegmentHeaderV2, parse_segment_header,
        };
        use std::io::Write;
        // Note: V2 segments are still on disk in mixed dirs — the skip logic handles
        // both V2 and V3 (GOLD-PROG-12). V1 segments get migrated to V3.

        let dir = tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();

        // Write one v1 segment.
        let seg1 = wal_dir.join("000001.wal");
        write_v1_segment(&seg1, b"v1-payload");

        // Write one v2 segment.
        let seg2 = wal_dir.join("000002.wal");
        let raw = b"v2-frames";
        let comp = compress_frames(raw).unwrap();
        let v2h = SegmentHeaderV2::new(
            0,
            2,
            0,
            1_700_000_000_000_000_000,
            [0u8; 16],
            SEGMENT_FLAG_COMPRESSED,
        );
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&seg2)
                .unwrap();
            f.write_all(&v2h.to_le_bytes()).unwrap();
            f.write_all(&comp).unwrap();
        }
        let seg2_before = std::fs::read(&seg2).unwrap();

        migrate_wal_to_v2(&wal_dir, false, OutputFormat::Table).unwrap();

        // seg1 must now be v2.
        let b1 = std::fs::read(&seg1).unwrap();
        // GOLD-PROG-12: V1 → V3 migration (V3 header, epoch=0).
        assert!(matches!(
            parse_segment_header(&b1).unwrap(),
            ParsedSegmentHeader::V3(_)
        ));

        // seg2 must be unchanged.
        let b2 = std::fs::read(&seg2).unwrap();
        assert_eq!(b2, seg2_before, "v2 segment must not be touched");
    }

    #[test]
    fn migrate_wal_errors_on_missing_dir() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("no-such-wal-dir");
        let err = migrate_wal_to_v2(&missing, false, OutputFormat::Table).unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "expected does-not-exist error; got: {err}"
        );
    }

    // ── V03-04 2026-05-17: migrate rollback ───────────────────────────

    #[test]
    fn find_latest_backup_picks_newest_mtime() {
        let dir = tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        // Create three files in increasing-mtime order so the test is
        // deterministic across filesystem mtime resolutions.
        for (i, name) in ["neoth-001.tar.gz", "neoth-002.tar.gz", "neoth-003.tar.gz"]
            .iter()
            .enumerate()
        {
            let path = backup_dir.join(name);
            std::fs::write(&path, b"dummy").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            let _ = i;
        }
        let picked = find_latest_backup(&backup_dir).unwrap();
        assert_eq!(picked.file_name().unwrap(), "neoth-003.tar.gz");
    }

    #[test]
    fn find_latest_backup_skips_non_neoth_archives() {
        let dir = tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        std::fs::write(backup_dir.join("notes.tar.gz"), b"x").unwrap();
        std::fs::write(backup_dir.join("README.md"), b"y").unwrap();
        std::fs::write(backup_dir.join("neoth-001.tar.gz"), b"z").unwrap();
        let picked = find_latest_backup(&backup_dir).unwrap();
        assert_eq!(picked.file_name().unwrap(), "neoth-001.tar.gz");
    }

    #[test]
    fn find_latest_backup_errors_on_empty_dir() {
        let dir = tempdir().unwrap();
        let backup_dir = dir.path().join("empty-backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        let err = find_latest_backup(&backup_dir).unwrap_err();
        assert!(err.to_string().contains("no neoth-"));
    }

    #[test]
    fn find_latest_backup_errors_on_missing_dir() {
        let dir = tempdir().unwrap();
        let nope = dir.path().join("does-not-exist");
        let err = find_latest_backup(&nope).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn rollback_errors_when_no_backup_found() {
        // Fresh home dir with no `backups/` subdir → bail with actionable
        // pointer naming `neoth backup`.
        let dir = tempdir().unwrap();
        let args = MigrateArgs {
            action: MigrateAction::Rollback {
                from: None,
                home: Some(dir.path().to_path_buf()),
                force: false,
            },
            db: None,
            output: OutputFormat::Table,
        };
        let err = run_migrate(args).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("neoth backup") || msg.contains("no `neoth-"),
            "expected actionable pointer, got: {msg}"
        );
    }

    #[tokio::test]
    async fn list_on_fresh_db_reports_version_0() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("fresh.db");
        let args = MigrateArgs {
            action: MigrateAction::List,
            db: Some(db),
            output: OutputFormat::Table,
        };
        // Just ensure it doesn't error; full output capture would need
        // stdout redirection.
        run_migrate(args).await.unwrap();
    }

    #[tokio::test]
    async fn dry_run_does_not_modify_db() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v3.db");
        // Bootstrap a v3 stamp.
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO meta (key, value) VALUES ('schema_version', '3');",
            )
            .unwrap();
        }
        let args = MigrateArgs {
            action: MigrateAction::Run {
                to: Some(store::SCHEMA_VERSION),
                dry_run: true,
            },
            db: Some(db.clone()),
            output: OutputFormat::Table,
        };
        run_migrate(args).await.unwrap();
        // Stamp should still read 3.
        let conn = Connection::open(&db).unwrap();
        let v = migrations::current_version(&conn).unwrap();
        assert_eq!(v, 3, "dry-run must not change the stamp");
    }

    #[tokio::test]
    async fn run_reaches_target() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        // Open via store so all tables exist + the stamp is current.
        let _conn = store::open(&db).unwrap();
        // Force the stamp back to v3 to simulate an upgrade scenario.
        {
            let c = Connection::open(&db).unwrap();
            c.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '3')",
                [],
            )
            .unwrap();
        }
        let args = MigrateArgs {
            action: MigrateAction::Run {
                to: None,
                dry_run: false,
            },
            db: Some(db.clone()),
            output: OutputFormat::Table,
        };
        run_migrate(args).await.unwrap();
        let c = Connection::open(&db).unwrap();
        assert_eq!(
            migrations::current_version(&c).unwrap(),
            store::SCHEMA_VERSION,
        );
    }

    #[tokio::test]
    async fn run_is_noop_when_already_current() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("current.db");
        let _ = store::open(&db).unwrap(); // stamps SCHEMA_VERSION
        let args = MigrateArgs {
            action: MigrateAction::Run {
                to: None,
                dry_run: false,
            },
            db: Some(db),
            output: OutputFormat::Table,
        };
        run_migrate(args).await.unwrap();
    }

    #[test]
    fn current_version_returns_zero_for_missing_db() {
        let dir = tempdir().unwrap();
        let v = super::current_version(&dir.path().join("absent.db"));
        assert_eq!(v, 0);
    }
}
