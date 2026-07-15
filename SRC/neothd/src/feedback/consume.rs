//! G-03 consumer — reads the `0xBB OPERATOR_FEEDBACK` signals that
//! [`super::tone`] captures and turns them into an actionable aggregate.
//!
//! The capture half (a chat-turn that reads as a correction emits a `0xBB`
//! frame with `{sentiment_score, matched_patterns, prompt_hash, ts_unix}`)
//! shipped previously. This module is the CONSUMER side: it walks the WAL,
//! aggregates recent corrections into a [`FeedbackSummary`] + a coarse
//! [`FeedbackPressure`] level, and — when pushback is sustained — produces a
//! single, deduped, operator-reviewable self-dev [`SelfDevProposal`] (never
//! auto-applied). Surfaced to the operator via `neoth feedback summary` and
//! consumed by the profile-adapt cron.
//!
//! Privacy: the prompt itself is never in the WAL (hash only), so this
//! consumer only ever sees scores + matched-pattern labels + timestamps.

use std::collections::HashMap;
use std::path::Path;

use crate::profile::self_dev::{ProposalKind, SelfDevProposal};
use crate::wal::compress::decompress_frames;
use crate::wal::events::EVENT_TYPE_OPERATOR_FEEDBACK;
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::parse_segment_header;

/// Coarse pushback level over the aggregation window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackPressure {
    /// Few/no corrections — NEOTH is tracking the operator well.
    Low,
    /// A noticeable run of corrections — worth the operator's attention.
    Elevated,
    /// Sustained pushback — the adapt cron surfaces a review proposal.
    High,
}

/// Correction counts that bound each pressure level (corrections in-window).
pub const ELEVATED_AT: u32 = 3;
pub const HIGH_AT: u32 = 8;

impl FeedbackPressure {
    pub fn classify(corrections: u32) -> Self {
        if corrections >= HIGH_AT {
            FeedbackPressure::High
        } else if corrections >= ELEVATED_AT {
            FeedbackPressure::Elevated
        } else {
            FeedbackPressure::Low
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FeedbackPressure::Low => "low",
            FeedbackPressure::Elevated => "elevated",
            FeedbackPressure::High => "high",
        }
    }
}

/// Aggregated operator-feedback over a recent window.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedbackSummary {
    pub window_secs: i64,
    /// Number of `0xBB` correction frames inside the window.
    pub corrections: u32,
    /// Correction-pattern labels (from `matched_patterns`) ranked by frequency.
    pub top_patterns: Vec<(String, u32)>,
    /// Most recent correction timestamp in-window, if any.
    pub latest_unix: Option<i64>,
}

impl FeedbackSummary {
    pub fn pressure(&self) -> FeedbackPressure {
        FeedbackPressure::classify(self.corrections)
    }
}

/// Walk the WAL segments in `wal_dir`, aggregating `0xBB OPERATOR_FEEDBACK`
/// frames whose `ts_unix` falls in `[now - window_secs, now]`. Best-effort:
/// unreadable/torn segments are skipped, never fatal.
pub fn aggregate_recent_feedback(
    wal_dir: &Path,
    window_secs: i64,
    now_unix: i64,
) -> FeedbackSummary {
    let cutoff = now_unix.saturating_sub(window_secs);
    let mut corrections: u32 = 0;
    let mut latest_unix: Option<i64> = None;
    let mut pattern_counts: HashMap<String, u32> = HashMap::new();

    for seg in segment_files(wal_dir) {
        let Ok(bytes) = std::fs::read(&seg) else {
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
        let decompressed;
        let frames: &[u8] = if hdr.is_compressed() {
            match decompress_frames(body) {
                Ok(d) => {
                    decompressed = d;
                    &decompressed
                }
                Err(_) => continue,
            }
        } else {
            body
        };
        let mut cursor = 0usize;
        while cursor < frames.len() {
            let dec = match decode_frame(&frames[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            if dec.header.event_type == EVENT_TYPE_OPERATOR_FEEDBACK
                && let Some(ts) = ingest_feedback_payload(dec.payload, cutoff, &mut pattern_counts)
            {
                corrections += 1;
                latest_unix = Some(latest_unix.map_or(ts, |cur| cur.max(ts)));
            }
            cursor = cursor.saturating_add(total);
        }
    }

    let mut top_patterns: Vec<(String, u32)> = pattern_counts.into_iter().collect();
    // Frequency desc, then label asc for a stable order.
    top_patterns.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top_patterns.truncate(8);

    FeedbackSummary {
        window_secs,
        corrections,
        top_patterns,
        latest_unix,
    }
}

/// Parse one `0xBB` payload; if its `ts_unix` is within window, tally its
/// matched-pattern labels and return the timestamp. `None` ⇒ out of window or
/// unparseable.
fn ingest_feedback_payload(
    payload: &[u8],
    cutoff: i64,
    pattern_counts: &mut HashMap<String, u32>,
) -> Option<i64> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let ts = v.get("ts_unix").and_then(|t| t.as_i64())?;
    if ts < cutoff {
        return None;
    }
    if let Some(arr) = v.get("matched_patterns").and_then(|m| m.as_array()) {
        for p in arr {
            if let Some(label) = p.as_str() {
                *pattern_counts.entry(label.to_string()).or_insert(0) += 1;
            }
        }
    }
    Some(ts)
}

/// Enumerate `*.wal` files in `dir` (sorted for deterministic aggregation).
fn segment_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("wal"))
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

/// G-03 adaptation: when pushback is sustained (`High`), produce ONE
/// operator-reviewable proposal to switch to the careful `Lowkey` preset,
/// grounded in the concrete count + top pattern. Returns `None` below `High`
/// — feedback alone is too weak a signal to auto-suggest below that bar.
///
/// The id is deduped on a coarse pressure bucket so the proposal is queued at
/// most once per sustained-pushback episode (not re-queued every cron tick);
/// it re-emerges only if the operator declines it AND pushback persists into a
/// new window. NEVER auto-applied — the operator reviews via
/// `neoth self-dev review`.
pub fn propose_from_feedback(summary: &FeedbackSummary) -> Option<SelfDevProposal> {
    if summary.pressure() != FeedbackPressure::High {
        return None;
    }
    let top = summary
        .top_patterns
        .first()
        .map(|(label, _)| label.as_str())
        .unwrap_or("repeated corrections");
    // Confidence scales modestly with how far past the High bar we are, capped —
    // feedback is a weak signal, so this stays operator-review-only territory.
    let confidence = (0.4 + 0.03 * f64::from(summary.corrections.saturating_sub(HIGH_AT))).min(0.7);
    // Stable id: dedup within an episode but allow re-surfacing in a later
    // window. Bucket = corrections rounded down to the HIGH step.
    let bucket = summary.corrections / HIGH_AT;
    Some(SelfDevProposal {
        id: format!("switch_preset-fb{bucket}"),
        kind: ProposalKind::SwitchPreset,
        reason: format!(
            "{} operator corrections recently (top signal: {top}) — consider the careful Lowkey preset",
            summary.corrections
        ),
        confidence,
        target: "lowkey".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::EVENT_TYPE_OPERATOR_FEEDBACK;
    use crate::wal::{HeaderBuilder, writer};

    #[test]
    fn pressure_thresholds() {
        assert_eq!(FeedbackPressure::classify(0), FeedbackPressure::Low);
        assert_eq!(FeedbackPressure::classify(2), FeedbackPressure::Low);
        assert_eq!(FeedbackPressure::classify(3), FeedbackPressure::Elevated);
        assert_eq!(FeedbackPressure::classify(7), FeedbackPressure::Elevated);
        assert_eq!(FeedbackPressure::classify(8), FeedbackPressure::High);
        assert_eq!(FeedbackPressure::classify(99), FeedbackPressure::High);
    }

    #[test]
    fn propose_only_at_high_pressure() {
        let low = FeedbackSummary {
            window_secs: 86400,
            corrections: 4,
            top_patterns: vec![("too_verbose".into(), 4)],
            latest_unix: Some(1000),
        };
        assert!(
            propose_from_feedback(&low).is_none(),
            "elevated ⇒ no auto-proposal"
        );

        let high = FeedbackSummary {
            window_secs: 86400,
            corrections: 10,
            top_patterns: vec![("wrong_answer".into(), 6)],
            latest_unix: Some(2000),
        };
        let p = propose_from_feedback(&high).expect("high ⇒ a proposal");
        assert_eq!(p.kind, ProposalKind::SwitchPreset);
        assert_eq!(p.target, "lowkey");
        assert!(p.confidence >= 0.4 && p.confidence <= 0.7);
        assert!(
            p.reason.contains("wrong_answer"),
            "reason cites the top pattern"
        );
        // Same episode ⇒ same id (deduped).
        assert_eq!(propose_from_feedback(&high).unwrap().id, p.id);
    }

    #[tokio::test]
    async fn aggregates_only_in_window_feedback_frames() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("fb-000001.wal");
        let (w, join) = writer::spawn(seg).unwrap();

        // Two in-window corrections + one stale (out of window).
        let now = 2_000_000_000i64;
        let frames = [
            (now - 10, vec!["too_verbose", "off_topic"]),
            (now - 20, vec!["too_verbose"]),
            (now - 999_999, vec!["ancient"]), // out of a 1h window
        ];
        for (ts, pats) in frames {
            let payload = serde_json::to_vec(&serde_json::json!({
                "sentiment_score": -0.7,
                "matched_patterns": pats,
                "prompt_hash": 123u64,
                "ts_unix": ts,
            }))
            .unwrap();
            let header = HeaderBuilder::new(EVENT_TYPE_OPERATOR_FEEDBACK, &payload).build();
            w.append(header, payload).await.unwrap();
        }
        drop(w);
        let _ = join.await;

        let summary = aggregate_recent_feedback(dir.path(), 3600, now);
        assert_eq!(
            summary.corrections, 2,
            "only the 2 in-window frames counted"
        );
        // too_verbose appeared twice, off_topic once.
        assert_eq!(summary.top_patterns[0], ("too_verbose".to_string(), 2));
        assert_eq!(summary.latest_unix, Some(now - 10));
        assert_eq!(summary.pressure(), FeedbackPressure::Low);
    }
}
