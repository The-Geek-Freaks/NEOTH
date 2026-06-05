//! CH-13 / F4-01 — council-winner correlation detector (read-only fitness scan).
//!
//! The first shipped slice of the Ecology layer: a PURE, read-only pass over
//! the `0x63 COUNCIL_WINNER_SELECTED` WAL frames that surfaces "provider X won
//! N consecutive outer-council debates". A long same-winner streak is a
//! low-dissent signal — the council keeps picking the same voice, which can
//! mean the operator's pattern shifted and the debate is no longer surfacing
//! diversity (the CH-12.b feedback loop would then shorten the cooldown to
//! re-surface dissent).
//!
//! Per the CH-13 design pins this layer is **deterministic + LLM-free** — every
//! signal is a pure function over WAL data, so it stays grep-friendly and
//! replayable. This module ships the read-only scanner + its pure core; the
//! auto-scheduler (Phase 1), genealogy graph (Phase 3), and the
//! `0xEC/0xED/0xEE` ecology WAL events land as their own slices.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::wal::compress::decompress_frames;
use crate::wal::events::EVENT_TYPE_COUNCIL_WINNER_SELECTED;
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::parse_segment_header;

/// One outer-council winner, in WAL order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WinnerRecord {
    /// The winning provider id (e.g. `claude_cli`, `openai_api`, `local_qwen`).
    pub provider: String,
    /// The winning hemisphere role (`left` / `right` / `cerebellum`).
    pub role: String,
    /// The winner's selection score.
    pub score: f64,
    /// The selection mode that produced this winner (`legacy_majority` /
    /// `consensus_or_best` / `best_always`), or `unknown` for pre-mode frames.
    /// In-frame since Session 14 — carried so the winner-chain (F4-01) can report
    /// the mode mix without a second WAL walk.
    pub mode: String,
}

/// A detected run of consecutive same-provider winners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationSignal {
    pub provider: String,
    /// Number of consecutive outer-council debates this provider won.
    pub streak_len: usize,
}

/// Find every maximal run of consecutive same-provider winners whose length is
/// at least `min_streak`. PURE — the caller does the WAL IO. Records are in
/// chronological (WAL) order; a "run" is adjacency in that order.
pub fn detect_winner_streaks(records: &[WinnerRecord], min_streak: usize) -> Vec<CorrelationSignal> {
    let min_streak = min_streak.max(1);
    let mut signals = Vec::new();
    let mut i = 0usize;
    while i < records.len() {
        let provider = &records[i].provider;
        let mut j = i + 1;
        while j < records.len() && &records[j].provider == provider {
            j += 1;
        }
        let len = j - i;
        if len >= min_streak {
            signals.push(CorrelationSignal {
                provider: provider.clone(),
                streak_len: len,
            });
        }
        i = j;
    }
    signals
}

/// Read every `0x63 COUNCIL_WINNER_SELECTED` frame for an OUTER council
/// (`depth == 0` — nested sub-debates are within one run, not separate runs)
/// from the WAL, in chronological order. Tolerant: a missing dir / torn
/// segment / bad payload each skips rather than errors (a partial WAL still
/// yields every recoverable winner). Mirrors the council-history walker.
pub fn scan_winner_records(wal_dir: &Path) -> Vec<WinnerRecord> {
    let entries = match std::fs::read_dir(wal_dir) {
        Ok(it) => it,
        Err(_) => return Vec::new(),
    };
    let mut segments: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
        .collect();
    segments.sort();

    let mut out = Vec::new();
    for path in segments {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(hdr) = parse_segment_header(&bytes) else {
            continue;
        };
        let header_len = hdr.header_len();
        if bytes.len() <= header_len {
            continue;
        }
        let body = &bytes[header_len..];
        if hdr.is_compressed() {
            if let Ok(d) = decompress_frames(body) {
                walk_winner_frames(&d, &mut out);
            }
        } else {
            walk_winner_frames(body, &mut out);
        }
    }
    out
}

/// Walk one (decompressed) segment body, pushing every outer-council winner.
fn walk_winner_frames(frames: &[u8], out: &mut Vec<WinnerRecord>) {
    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        if dec.header.event_type == EVENT_TYPE_COUNCIL_WINNER_SELECTED {
            if let Some(rec) = parse_winner_payload(dec.payload) {
                out.push(rec);
            }
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
}

/// Extract a [`WinnerRecord`] from a `0x63` payload, keeping only outer-council
/// (`depth == 0`) frames. `None` for nested debates or an unparseable payload.
fn parse_winner_payload(payload: &[u8]) -> Option<WinnerRecord> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    // Default depth 0 if absent (older frames) — treat as outer.
    let depth = v.get("depth").and_then(|d| d.as_u64()).unwrap_or(0);
    if depth != 0 {
        return None;
    }
    let provider = v.get("provider").and_then(|p| p.as_str())?.to_string();
    if provider.is_empty() {
        return None;
    }
    let role = v
        .get("role")
        .and_then(|r| r.as_str())
        .unwrap_or("unknown")
        .to_string();
    let score = v.get("score").and_then(|s| s.as_f64()).unwrap_or(0.0);
    let mode = v
        .get("mode")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_string();
    Some(WinnerRecord {
        provider,
        role,
        score,
        mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(provider: &str) -> WinnerRecord {
        WinnerRecord {
            provider: provider.into(),
            role: "left".into(),
            score: 0.9,
            mode: "consensus_or_best".into(),
        }
    }

    #[test]
    fn no_streak_when_alternating() {
        let recs = vec![rec("a"), rec("b"), rec("a"), rec("b")];
        assert!(detect_winner_streaks(&recs, 2).is_empty());
    }

    #[test]
    fn single_maximal_streak() {
        let recs = vec![rec("a"), rec("a"), rec("a"), rec("b")];
        let s = detect_winner_streaks(&recs, 3);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].provider, "a");
        assert_eq!(s[0].streak_len, 3);
    }

    #[test]
    fn two_separate_streaks_and_threshold() {
        // a×3, b×1, a×2 — with min 2 → two signals (a:3, a:2); b never qualifies.
        let recs = vec![
            rec("a"),
            rec("a"),
            rec("a"),
            rec("b"),
            rec("a"),
            rec("a"),
        ];
        let s = detect_winner_streaks(&recs, 2);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].streak_len, 3);
        assert_eq!(s[1].streak_len, 2);
    }

    #[test]
    fn min_streak_floor_is_one() {
        // min_streak 0 is clamped to 1 (every record is a length-1 run).
        let recs = vec![rec("a"), rec("b")];
        let s = detect_winner_streaks(&recs, 0);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn empty_records_no_signals() {
        assert!(detect_winner_streaks(&[], 2).is_empty());
    }

    #[test]
    fn parse_payload_outer_only() {
        let outer = br#"{"depth":0,"role":"left","provider":"claude_cli","score":0.91,"mode":"best_always"}"#;
        let nested = br#"{"depth":1,"role":"right","provider":"openai_api","score":0.8}"#;
        let r = parse_winner_payload(outer).expect("outer parses");
        assert_eq!(r.provider, "claude_cli");
        assert_eq!(r.role, "left");
        assert_eq!(r.mode, "best_always", "mode is captured from the frame");
        // A pre-mode frame defaults to "unknown" rather than dropping the record.
        let no_mode = br#"{"depth":0,"role":"left","provider":"x","score":0.5}"#;
        assert_eq!(parse_winner_payload(no_mode).unwrap().mode, "unknown");
        assert!(parse_winner_payload(nested).is_none(), "nested must be skipped");
        assert!(parse_winner_payload(b"not json").is_none());
        assert!(
            parse_winner_payload(br#"{"depth":0,"provider":""}"#).is_none(),
            "empty provider skipped"
        );
    }

    #[test]
    fn scan_missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(scan_winner_records(&dir.path().join("nope")).is_empty());
    }

    #[tokio::test]
    async fn scan_reads_real_frames_end_to_end() {
        // Write three outer-council winner frames (a, a, b) through the real
        // WAL writer, then scan + detect.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, wal_join) = crate::wal::writer::spawn(seg).unwrap();
        for provider in ["a", "a", "b"] {
            let payload = serde_json::to_vec(&serde_json::json!({
                "depth": 0, "role": "left", "provider": provider, "score": 0.9
            }))
            .unwrap();
            let header = crate::wal::HeaderBuilder::new(
                EVENT_TYPE_COUNCIL_WINNER_SELECTED,
                &payload,
            )
            .build();
            writer.append(header, payload).await.unwrap();
        }
        drop(writer);
        wal_join.await.ok();

        let recs = scan_winner_records(dir.path());
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].provider, "a");
        assert_eq!(recs[2].provider, "b");
        let streaks = detect_winner_streaks(&recs, 2);
        assert_eq!(streaks.len(), 1);
        assert_eq!(streaks[0].provider, "a");
        assert_eq!(streaks[0].streak_len, 2);
    }
}
