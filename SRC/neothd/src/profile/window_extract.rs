//! Stage 1 — `window_extract`. Slices prior episodes around a trigger
//! event into a [`ConversationWindow`]. Pure read against `idx_episode`,
//! no LLM, no WAL writer side-effects.
//!
//! The slice rule is "N prior turn-pairs": one turn-pair = one operator
//! message + the immediately-following provider response. The DB-side
//! approximation reads the trigger row + the previous `2N` rows by
//! `event_id` (or `ts_ns` when event_id collides — should be rare since
//! event_ids are monotonic per-segment).
//!
//! Out of scope here:
//!   - Cross-channel scoping (the spec says future variants may filter
//!     by `sender_id` or `channel`). The query keeps the segments
//!     chronological and lets the attribution pass decide ineligibility.
//!   - Pinning the trigger to ground-truth or longterm rows. The
//!     attribution pipeline is designed for episodic windows; older
//!     events feed the consolidation path, not extraction.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

use crate::profile::types::{ConversationSegment, ConversationWindow, SegmentOrigin};
use crate::wal::events::{
    EVENT_TYPE_CHANNEL_EGRESS, EVENT_TYPE_CHANNEL_INGRESS, EVENT_TYPE_PROVIDER_REQUEST,
    EVENT_TYPE_PROVIDER_RESPONSE, EVENT_TYPE_RAW_TEXT,
};

/// Maximum segments returned regardless of `turns_back` — defends against
/// a misconfigured `turns_back: 9999` query from sweeping the whole
/// hot tier into memory.
const MAX_SEGMENTS: u32 = 64;

/// Build a `ConversationWindow` of the trigger row + up to `turns_back × 2`
/// preceding rows. Segments are returned oldest-first.
///
/// Returns an empty window (no segments) if the trigger event id is not
/// in `idx_episode` — this is not an error, just a "trigger pre-dates
/// the current hot tier" signal. The attribution pipeline downstream
/// will surface that case via its `require_first_person_window` check.
pub fn extract_window(
    conn: &Connection,
    trigger_event_id: i64,
    turns_back: u32,
) -> Result<ConversationWindow> {
    let cap = turns_back
        .saturating_mul(2)
        .saturating_add(1)
        .min(MAX_SEGMENTS);

    let mut stmt = conn
        .prepare(
            "SELECT event_id, event_type, ts_ns, text \
             FROM idx_episode \
             WHERE event_id <= ?1 \
             ORDER BY event_id DESC \
             LIMIT ?2",
        )
        .context("prepare window_extract query")?;
    let rows: Vec<ConversationSegment> = stmt
        .query_map(params![trigger_event_id, cap as i64], |r| {
            let event_id: i64 = r.get(0)?;
            let event_type: i64 = r.get(1)?;
            let ts_ns: i64 = r.get(2)?;
            let text: String = r.get(3)?;
            Ok(ConversationSegment {
                event_id,
                ts_ns,
                origin: classify_origin(event_type),
                text,
            })
        })
        .context("query window_extract rows")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect window_extract rows")?;

    // Reverse to oldest-first so the attribution pass + extractor see
    // chronological context.
    let mut chronological = rows;
    chronological.reverse();

    Ok(ConversationWindow {
        trigger_event_id,
        turns_back,
        segments: chronological,
    })
}

/// Map a WAL event_type to a segment origin. The pipeline cares about
/// operator-inbound vs provider-outbound; everything else is `Unknown`.
fn classify_origin(event_type: i64) -> SegmentOrigin {
    let et = event_type as u8;
    if et == EVENT_TYPE_RAW_TEXT || et == EVENT_TYPE_CHANNEL_INGRESS {
        SegmentOrigin::OperatorInbound
    } else if et == EVENT_TYPE_CHANNEL_EGRESS
        || et == EVENT_TYPE_PROVIDER_RESPONSE
        || et == EVENT_TYPE_PROVIDER_REQUEST
    {
        // PROVIDER_REQUEST text is also derived from operator content
        // but the WAL stores it pre-attribution alongside the operator's
        // raw text. Classify as Unknown so the attribution pass treats
        // it conservatively; the RAW_TEXT frame is the authoritative
        // source for user speech in this window.
        if et == EVENT_TYPE_PROVIDER_REQUEST {
            SegmentOrigin::Unknown
        } else {
            SegmentOrigin::ProviderOutbound
        }
    } else {
        SegmentOrigin::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use tempfile::tempdir;

    fn insert_episode(conn: &Connection, event_id: i64, event_type: u8, ts_ns: i64, text: &str) {
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, channel, sender_id, operator_id) \
             VALUES (?1, ?2, ?3, ?4, '', NULL, NULL, NULL)",
            params![event_id, event_type as i64, ts_ns, text],
        )
        .unwrap();
    }

    fn open_test_conn() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        (dir, conn)
    }

    #[test]
    fn extracts_trigger_plus_previous_turn_pair_in_chronological_order() {
        let (_dir, conn) = open_test_conn();
        insert_episode(&conn, 10, EVENT_TYPE_RAW_TEXT, 1, "hello earlier");
        insert_episode(&conn, 11, EVENT_TYPE_PROVIDER_RESPONSE, 2, "earlier reply");
        insert_episode(&conn, 12, EVENT_TYPE_RAW_TEXT, 3, "current ask");
        insert_episode(&conn, 13, EVENT_TYPE_PROVIDER_RESPONSE, 4, "current reply");

        let w = extract_window(&conn, 13, 1).expect("window");
        // Trigger + 2 prior = 3 segments expected.
        assert_eq!(w.segments.len(), 3);
        // Oldest-first ordering.
        assert_eq!(w.segments[0].event_id, 11);
        assert_eq!(w.segments[1].event_id, 12);
        assert_eq!(w.segments[2].event_id, 13);
        assert_eq!(w.trigger_event_id, 13);
        assert_eq!(w.turns_back, 1);
    }

    #[test]
    fn classifies_origin_from_event_type() {
        let (_dir, conn) = open_test_conn();
        insert_episode(&conn, 1, EVENT_TYPE_RAW_TEXT, 1, "operator");
        insert_episode(&conn, 2, EVENT_TYPE_CHANNEL_INGRESS, 2, "operator via tg");
        insert_episode(&conn, 3, EVENT_TYPE_PROVIDER_RESPONSE, 3, "provider");
        insert_episode(&conn, 4, EVENT_TYPE_CHANNEL_EGRESS, 4, "egress");
        insert_episode(&conn, 5, 0xFF, 5, "noise");

        let w = extract_window(&conn, 5, 5).expect("window");
        assert_eq!(w.segments.len(), 5);
        // ordered oldest-first
        assert_eq!(w.segments[0].origin, SegmentOrigin::OperatorInbound);
        assert_eq!(w.segments[1].origin, SegmentOrigin::OperatorInbound);
        assert_eq!(w.segments[2].origin, SegmentOrigin::ProviderOutbound);
        assert_eq!(w.segments[3].origin, SegmentOrigin::ProviderOutbound);
        assert_eq!(w.segments[4].origin, SegmentOrigin::Unknown);
    }

    #[test]
    fn missing_trigger_returns_empty_window_not_error() {
        let (_dir, conn) = open_test_conn();
        let w = extract_window(&conn, 99999, 2).expect("window");
        assert!(w.segments.is_empty());
        assert_eq!(w.trigger_event_id, 99999);
    }

    #[test]
    fn caps_at_max_segments_on_pathological_turns_back() {
        let (_dir, conn) = open_test_conn();
        for i in 1..=80 {
            insert_episode(&conn, i, EVENT_TYPE_RAW_TEXT, i, "x");
        }
        let w = extract_window(&conn, 80, 9999).expect("window");
        // MAX_SEGMENTS = 64
        assert_eq!(w.segments.len(), 64);
        // Most recent included
        assert_eq!(w.segments.last().unwrap().event_id, 80);
        // Oldest sliced row is 80 - 64 + 1 = 17
        assert_eq!(w.segments.first().unwrap().event_id, 17);
    }

    #[test]
    fn turns_back_zero_returns_only_trigger() {
        let (_dir, conn) = open_test_conn();
        insert_episode(&conn, 1, EVENT_TYPE_RAW_TEXT, 1, "earlier");
        insert_episode(&conn, 2, EVENT_TYPE_RAW_TEXT, 2, "trigger");
        let w = extract_window(&conn, 2, 0).expect("window");
        assert_eq!(w.segments.len(), 1);
        assert_eq!(w.segments[0].event_id, 2);
    }
}
