//! `neoth wal` — read-only WAL segment inspector. Phase 33c follow-up.
//!
//! Two subcommands:
//!   `stats <segment>` — count frames per event-type, total bytes, header
//!                       validity. Pairs with `neoth events` (registry) for
//!                       "what's actually in this segment".
//!   `show <segment>`  — pretty-print every frame: offset, code, payload-len,
//!                       importance, ts_ns, hash. `--limit N` for quick peeks.
//!
//! Pure read-only over `wal/*.wal` files. No DB access. No daemon
//! required — operator can run this against a backup tarball's segments
//! before restoring.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::{SEGMENT_HEADER_LEN, SegmentHeader};

#[derive(Args, Debug, Clone)]
pub struct WalArgs {
    #[command(subcommand)]
    pub action: WalAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum WalAction {
    /// Count frames per event type + report header validity + total bytes.
    Stats {
        /// Path to the segment file (`~/.neoth/wal/NNNNNN.wal`).
        segment: PathBuf,
    },
    /// Pretty-print frames from a segment.
    Show {
        /// Path to the segment file.
        segment: PathBuf,
        /// Print at most this many frames (default 50).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Skip this many frames before printing.
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
}

pub async fn run_wal(args: WalArgs) -> Result<()> {
    match args.action {
        WalAction::Stats { segment } => stats(&segment, args.output),
        WalAction::Show {
            segment,
            limit,
            skip,
        } => show(&segment, limit, skip, args.output),
    }
}

/// Full result of a stats walk over one segment.
#[derive(Debug, Clone)]
pub struct SegmentStats {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub segment_seq: Option<u64>,
    pub header_ok: bool,
    pub header_error: Option<String>,
    pub frame_count: usize,
    pub bad_frames: usize,
    pub per_event: BTreeMap<u8, usize>,
}

pub fn collect_stats(segment: &std::path::Path) -> Result<SegmentStats> {
    let bytes = std::fs::read(segment).with_context(|| format!("read {}", segment.display()))?;
    let size = bytes.len() as u64;
    let mut stats = SegmentStats {
        path: segment.to_path_buf(),
        size_bytes: size,
        segment_seq: None,
        header_ok: false,
        header_error: None,
        frame_count: 0,
        bad_frames: 0,
        per_event: BTreeMap::new(),
    };
    if bytes.len() < SEGMENT_HEADER_LEN {
        stats.header_error = Some(format!(
            "shorter than SegmentHeader ({} < {})",
            bytes.len(),
            SEGMENT_HEADER_LEN,
        ));
        return Ok(stats);
    }
    match SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().unwrap()) {
        Ok(hdr) => {
            stats.header_ok = true;
            stats.segment_seq = Some(hdr.segment_seq);
        }
        Err(e) => {
            stats.header_error = Some(format!("{e}"));
        }
    }
    let mut cursor = SEGMENT_HEADER_LEN;
    while cursor < bytes.len() {
        match decode_frame(&bytes[cursor..]) {
            Ok(dec) => {
                stats.frame_count += 1;
                *stats.per_event.entry(dec.header.event_type).or_insert(0) += 1;
                let total = dec.header.total_len as usize;
                if total == 0 {
                    stats.bad_frames += 1;
                    break;
                }
                cursor = cursor.saturating_add(total);
            }
            Err(_) => {
                stats.bad_frames += 1;
                break;
            }
        }
    }
    Ok(stats)
}

fn stats(segment: &std::path::Path, output: OutputFormat) -> Result<()> {
    let s = collect_stats(segment)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = s
                .per_event
                .iter()
                .map(|(code, n)| {
                    serde_json::json!({
                        "code": format!("0x{code:02X}"),
                        "count": n,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "path": s.path.display().to_string(),
                    "size_bytes": s.size_bytes,
                    "segment_seq": s.segment_seq,
                    "header_ok": s.header_ok,
                    "header_error": s.header_error,
                    "frame_count": s.frame_count,
                    "bad_frames": s.bad_frames,
                    "per_event": rows,
                })
            );
        }
        OutputFormat::Table => {
            println!("# segment: {}", s.path.display());
            println!("#   size:      {} bytes", s.size_bytes);
            match (s.header_ok, s.segment_seq, &s.header_error) {
                (true, Some(seq), _) => println!("#   header:    ok (segment_seq={seq})"),
                (false, _, Some(e)) => println!("#   header:    BAD — {e}"),
                _ => println!("#   header:    BAD — unknown error"),
            }
            println!("#   frames:    {}", s.frame_count);
            if s.bad_frames > 0 {
                println!("#   bad frame: STOP — torn frame at end (op safe; daemon will recover)");
            }
            println!();
            if s.per_event.is_empty() {
                println!("  (no frames)");
            } else {
                println!("  {:<6}  {:<6}  per-event count", "code", "count");
                for (code, n) in &s.per_event {
                    println!("  0x{code:02X}    {n:<6}");
                }
            }
        }
    }
    Ok(())
}

fn show(segment: &std::path::Path, limit: usize, skip: usize, output: OutputFormat) -> Result<()> {
    let bytes = std::fs::read(segment).with_context(|| format!("read {}", segment.display()))?;
    if bytes.len() < SEGMENT_HEADER_LEN {
        anyhow::bail!(
            "file shorter than SegmentHeader ({} < {}) — not a valid segment",
            bytes.len(),
            SEGMENT_HEADER_LEN,
        );
    }
    let _seg_hdr = SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().unwrap())
        .context("parse SegmentHeader")?;

    let mut cursor = SEGMENT_HEADER_LEN;
    let mut idx = 0usize;
    let mut shown = 0usize;
    let mut rows: Vec<serde_json::Value> = Vec::new();

    while cursor < bytes.len() && shown < limit {
        let dec = match decode_frame(&bytes[cursor..]) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "frame decode stopped at offset {cursor}");
                break;
            }
        };
        let total = dec.header.total_len as usize;
        if idx >= skip {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    rows.push(serde_json::json!({
                        "offset": cursor,
                        "event_type": format!("0x{:02X}", dec.header.event_type),
                        "event_subtype": dec.header.event_subtype,
                        "payload_len": dec.header.payload_len,
                        "importance": dec.header.importance.raw(),
                        "ts_ns": dec.header.hlc.physical_ns(),
                        "event_id": dec.header.event_id.0,
                        "payload_hash": format!("{:016x}", dec.header.payload_hash),
                    }));
                }
                OutputFormat::Table => {
                    println!(
                        "  @{offset:>10}  0x{code:02X}  payload={plen}  imp={imp:.2}  ts_ns={ts}  id={id}  hash={h:016x}",
                        offset = cursor,
                        code = dec.header.event_type,
                        plen = dec.header.payload_len,
                        imp = dec.header.importance.raw(),
                        ts = dec.header.hlc.physical_ns(),
                        id = dec.header.event_id.0,
                        h = dec.header.payload_hash,
                    );
                }
            }
            shown += 1;
        }
        idx += 1;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "segment": segment.display().to_string(),
                "frames_shown": shown,
                "frames_total_walked": idx,
                "frames": rows,
            })
        );
    } else {
        println!("# {shown} frame(s) shown (skipped {skip}, walked {idx})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::HeaderBuilder;
    use crate::wal::events::EVENT_TYPE_RAW_TEXT;
    use crate::wal::frame::encode_frame;
    use crate::wal::header::EventHeaderV2;
    use crate::wal::segment_header::SegmentHeader;
    use tempfile::tempdir;

    fn write_segment(dir: &std::path::Path, seq: u64, frames: usize) -> PathBuf {
        let path = dir.join(format!("{:06}.wal", seq));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut bytes: Vec<u8> = Vec::new();
        let sh = SegmentHeader::new(0, seq, 0, now, [0u8; 16]);
        bytes.extend_from_slice(&sh.to_le_bytes());
        for i in 0..frames {
            let payload = format!("frame {i}").into_bytes();
            let header: EventHeaderV2 = HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, &payload).build();
            let frame = encode_frame(&header, &payload);
            bytes.extend_from_slice(&frame);
        }
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    #[test]
    fn stats_counts_frames_per_event_type() {
        let dir = tempdir().unwrap();
        let seg = write_segment(dir.path(), 1, 5);
        let s = collect_stats(&seg).unwrap();
        assert!(s.header_ok);
        assert_eq!(s.segment_seq, Some(1));
        assert_eq!(s.frame_count, 5);
        assert_eq!(s.bad_frames, 0);
        assert_eq!(*s.per_event.get(&EVENT_TYPE_RAW_TEXT).unwrap(), 5);
    }

    #[test]
    fn stats_handles_empty_segment_after_header() {
        let dir = tempdir().unwrap();
        let seg = write_segment(dir.path(), 7, 0);
        let s = collect_stats(&seg).unwrap();
        assert!(s.header_ok);
        assert_eq!(s.frame_count, 0);
        assert!(s.per_event.is_empty());
    }

    #[test]
    fn stats_short_file_reports_bad_header() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        std::fs::write(&seg, b"too short").unwrap();
        let s = collect_stats(&seg).unwrap();
        assert!(!s.header_ok);
        assert!(s.header_error.is_some());
        assert_eq!(s.frame_count, 0);
    }

    #[test]
    fn stats_truncated_tail_stops_cleanly() {
        let dir = tempdir().unwrap();
        let seg = write_segment(dir.path(), 1, 3);
        // Truncate to 80% of length — last frame becomes torn.
        let body = std::fs::read(&seg).unwrap();
        let cut = (body.len() as f64 * 0.8) as usize;
        std::fs::write(&seg, &body[..cut]).unwrap();
        let s = collect_stats(&seg).unwrap();
        // Some frames before the torn one must have decoded.
        assert!(s.frame_count < 3);
        assert_eq!(s.bad_frames, 1, "exactly one bad-frame stop");
    }

    #[tokio::test]
    async fn show_respects_limit_and_skip() {
        let dir = tempdir().unwrap();
        let seg = write_segment(dir.path(), 1, 10);
        // limit 3 + skip 2 should not error and should walk through.
        let args = WalArgs {
            action: WalAction::Show {
                segment: seg,
                limit: 3,
                skip: 2,
            },
            output: OutputFormat::Table,
        };
        run_wal(args).await.unwrap();
    }

    #[tokio::test]
    async fn stats_command_runs_against_real_segment() {
        let dir = tempdir().unwrap();
        let seg = write_segment(dir.path(), 1, 2);
        let args = WalArgs {
            action: WalAction::Stats { segment: seg },
            output: OutputFormat::Table,
        };
        run_wal(args).await.unwrap();
    }

    #[tokio::test]
    async fn show_errors_when_file_missing_header() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.wal");
        std::fs::write(&path, b"nope").unwrap();
        let args = WalArgs {
            action: WalAction::Show {
                segment: path,
                limit: 1,
                skip: 0,
            },
            output: OutputFormat::Table,
        };
        let r = run_wal(args).await;
        assert!(r.is_err());
    }
}
