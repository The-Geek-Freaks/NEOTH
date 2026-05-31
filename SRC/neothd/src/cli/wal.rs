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
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::wal::compress::decompress_frames;
use crate::wal::events::{event_code_from_filter, event_name_from_code};
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::{SEGMENT_HEADER_LEN, SegmentHeader, parse_segment_header};

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
    /// Pretty-print frames, newest first. With no `<segment>`, scans
    /// EVERY `~/.neoth/wal/*.wal` segment so an operator can audit the
    /// whole chain without naming a file. `--type` filters to one event
    /// type — this is how an operator proves a guarantee, e.g.
    /// `neoth wal show --type plugin_cap_denied` (every denied plugin
    /// hostcall) or `--type provider_fallback_attempted` (every 429
    /// failover).
    Show {
        /// Segment file. Omit to scan ALL `~/.neoth/wal/*.wal`.
        segment: Option<PathBuf>,
        /// Filter to ONE event type. Accepts a name (`plugin_cap_denied`),
        /// hex (`0xC7` / `c7`), or decimal. See `neoth events` for names.
        #[arg(long = "type", value_name = "TYPE")]
        event_type: Option<String>,
        /// Show at most this many (the most recent). `--last` is an alias.
        #[arg(long, visible_alias = "last", default_value_t = 50)]
        limit: usize,
        /// Skip this many of the most-recent frames before showing.
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
}

pub async fn run_wal(args: WalArgs) -> Result<()> {
    match args.action {
        WalAction::Stats { segment } => stats(&segment, args.output),
        WalAction::Show {
            segment,
            event_type,
            limit,
            skip,
        } => {
            let home = FreedomConfig::default_neoth_home();
            show(
                segment.as_deref(),
                event_type.as_deref(),
                limit,
                skip,
                &home,
                args.output,
            )
        }
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

/// One decoded frame the show pass surfaces.
struct ShownFrame {
    event_type: u8,
    event_subtype: u8,
    payload_len: u32,
    importance: f32,
    ts_ns: u64,
    event_id: u64,
    payload_hash: u64,
}

fn show(
    segment: Option<&Path>,
    type_filter: Option<&str>,
    limit: usize,
    skip: usize,
    home: &Path,
    output: OutputFormat,
) -> Result<()> {
    // Resolve the --type filter to a concrete code (fail loudly on an
    // unknown token rather than silently filtering to nothing).
    let want: Option<u8> = match type_filter {
        Some(t) => Some(event_code_from_filter(t).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown --type `{t}` — use an event name (e.g. plugin_cap_denied), \
                 a hex code (0xC7), or a decimal. `neoth events` lists the registry."
            )
        })?),
        None => None,
    };

    // Segments: an explicit path is read strictly (a bad header is an
    // error — the operator named that file); a whole-chain scan is
    // tolerant (a torn segment is skipped, like the ledger/council walkers).
    let (segments, strict) = match segment {
        Some(p) => (vec![p.to_path_buf()], true),
        None => (sorted_segments(&home.join("wal")), false),
    };

    let mut frames: Vec<ShownFrame> = Vec::new();
    let mut walked = 0usize;
    for seg in &segments {
        match read_segment_frames(seg, want, &mut frames, &mut walked) {
            Ok(()) => {}
            Err(e) if strict => return Err(e),
            Err(e) => {
                tracing::warn!(error = %e, segment = %seg.display(), "skipped unreadable segment")
            }
        }
    }

    // Newest-first: the chain is appended chronologically, so the tail is
    // the most recent. Apply `skip` from the newest end, then take `limit`.
    frames.reverse();
    let view: Vec<&ShownFrame> = frames.iter().skip(skip).take(limit).collect();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<serde_json::Value> = view
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "event_type": format!("0x{:02X}", f.event_type),
                        "event_name": event_name_from_code(f.event_type),
                        "event_subtype": f.event_subtype,
                        "payload_len": f.payload_len,
                        "importance": f.importance,
                        "ts_ns": f.ts_ns,
                        "event_id": f.event_id,
                        "payload_hash": format!("{:016x}", f.payload_hash),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "type_filter": type_filter,
                    "segments_scanned": segments.len(),
                    "frames_matched": frames.len(),
                    "frames_shown": view.len(),
                    "frames": rows,
                })
            );
        }
        OutputFormat::Table => {
            for f in &view {
                let name = event_name_from_code(f.event_type).unwrap_or("?");
                println!(
                    "  0x{code:02X} {name:<26}  id={id:<8}  ts_ns={ts}  payload={plen}  imp={imp:.2}  hash={h:016x}",
                    code = f.event_type,
                    name = name,
                    id = f.event_id,
                    ts = f.ts_ns,
                    plen = f.payload_len,
                    imp = f.importance,
                    h = f.payload_hash,
                );
            }
            let filt = type_filter
                .map(|t| format!(" (type={t})"))
                .unwrap_or_default();
            println!(
                "# {} of {} matching frame(s){filt}, newest first — scanned {} segment(s)",
                view.len(),
                frames.len(),
                segments.len(),
            );
        }
    }
    Ok(())
}

/// Sorted `*.wal` paths under `wal_dir` (zero-padded names sort
/// chronologically). Empty when the dir is missing or has none.
fn sorted_segments(wal_dir: &Path) -> Vec<PathBuf> {
    let mut segs: Vec<PathBuf> = match std::fs::read_dir(wal_dir) {
        Ok(it) => it
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
            .collect(),
        Err(_) => Vec::new(),
    };
    segs.sort();
    segs
}

/// Robust v1/v2 read of one segment: parse the header, decompress a v2
/// zstd body, then walk frames, pushing those matching `want` (or all
/// when `None`). Mirrors the ledger/council/refusal walkers.
fn read_segment_frames(
    path: &Path,
    want: Option<u8>,
    out: &mut Vec<ShownFrame>,
    walked: &mut usize,
) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let hdr = parse_segment_header(&bytes)
        .map_err(|e| anyhow::anyhow!("parse segment header {}: {e}", path.display()))?;
    let header_len = hdr.header_len();
    if bytes.len() <= header_len {
        return Ok(());
    }
    let body = &bytes[header_len..];
    let decompressed;
    let frames: &[u8] = if hdr.is_compressed() {
        decompressed = decompress_frames(body)
            .map_err(|e| anyhow::anyhow!("decompress {}: {e}", path.display()))?;
        &decompressed
    } else {
        body
    };

    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break, // torn tail — stop this segment cleanly
        };
        *walked += 1;
        if want.is_none_or(|w| dec.header.event_type == w) {
            out.push(ShownFrame {
                event_type: dec.header.event_type,
                event_subtype: dec.header.event_subtype,
                payload_len: dec.header.payload_len,
                importance: dec.header.importance.raw(),
                ts_ns: dec.header.hlc.physical_ns(),
                event_id: dec.header.event_id.0,
                payload_hash: dec.header.payload_hash,
            });
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
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
                segment: Some(seg),
                event_type: None,
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
                segment: Some(path),
                event_type: None,
                limit: 1,
                skip: 0,
            },
            output: OutputFormat::Table,
        };
        let r = run_wal(args).await;
        assert!(r.is_err());
    }

    /// Build a segment with a few RAW_TEXT frames plus one of a different
    /// type so the `--type` filter has something to discriminate.
    fn write_mixed_segment(dir: &std::path::Path, seq: u64) -> PathBuf {
        use crate::wal::events::EVENT_TYPE_BOOT;
        let path = dir.join(format!("{:06}.wal", seq));
        let now = 1_700_000_000_000_000_000u64;
        let mut bytes: Vec<u8> = Vec::new();
        let sh = SegmentHeader::new(0, seq, 0, now, [0u8; 16]);
        bytes.extend_from_slice(&sh.to_le_bytes());
        for code in [
            EVENT_TYPE_RAW_TEXT,
            EVENT_TYPE_RAW_TEXT,
            EVENT_TYPE_BOOT,
            EVENT_TYPE_RAW_TEXT,
        ] {
            let payload = b"x".to_vec();
            let header: EventHeaderV2 = HeaderBuilder::new(code, &payload).build();
            bytes.extend_from_slice(&encode_frame(&header, &payload));
        }
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    #[test]
    fn read_segment_frames_filters_by_type() {
        use crate::wal::events::EVENT_TYPE_BOOT;
        let dir = tempdir().unwrap();
        let seg = write_mixed_segment(dir.path(), 1);
        // No filter → all 4 frames.
        let mut all = Vec::new();
        let mut walked = 0;
        read_segment_frames(&seg, None, &mut all, &mut walked).unwrap();
        assert_eq!(all.len(), 4);
        // Filter to BOOT → exactly the 1 boot frame.
        let mut boots = Vec::new();
        let mut w2 = 0;
        read_segment_frames(&seg, Some(EVENT_TYPE_BOOT), &mut boots, &mut w2).unwrap();
        assert_eq!(boots.len(), 1);
        assert_eq!(boots[0].event_type, EVENT_TYPE_BOOT);
        assert_eq!(w2, 4, "walked count counts every frame, not just matches");
    }

    #[tokio::test]
    async fn show_scans_all_segments_when_no_path_given() {
        // Point home at a temp dir with two segments; `segment: None`
        // must scan both via the wal/ subdir.
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        write_segment(&wal, 1, 3);
        write_segment(&wal, 2, 2);
        // Direct call (run_wal uses the real home; here we exercise the
        // multi-segment core against an explicit home).
        show(None, None, 50, 0, home.path(), OutputFormat::Table).unwrap();
        // Unknown --type must error, not silently show nothing.
        let err = show(
            None,
            Some("not_a_type"),
            50,
            0,
            home.path(),
            OutputFormat::Table,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown --type"), "got: {err}");
    }

    #[test]
    fn sorted_segments_missing_dir_is_empty() {
        let dir = tempdir().unwrap();
        assert!(sorted_segments(&dir.path().join("nope")).is_empty());
    }
}
