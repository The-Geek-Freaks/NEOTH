//! QU-08 — `idx_episode` 60-min temporal-window view (Hippocampus
//! episode summaries).
//!
//! Humans don't remember life as millisecond-precision events; they
//! remember **episodes** — a meeting, a workout, a coding session. The
//! same goes for the operator's interaction history: a 4-hour
//! debugging burst is one episode, not 40 separate messages. This view
//! groups consecutive `idx_episode` rows into temporal windows so the
//! Hippocampus recall path can surface "what was that long late-night
//! Rust session a week ago?" instead of "what was that one message at
//! 23:47:12.143?".
//!
//! ## Algorithm
//!
//! Pure-fn temporal grouping over a `ts_ns`-sorted scan. Two rows
//! belong to the same episode iff `current.ts_ns - prev.ts_ns ≤
//! window_size_ns` (60 minutes by default). Gaps wider than the
//! window start a new episode.
//!
//! Each [`EpisodeSummary`] carries:
//!   - `start_ts_ns` / `end_ts_ns` — temporal bounds.
//!   - `event_count` — how many rows fell into the window.
//!   - `dominant_event_type` — most-frequent `event_type` byte
//!     (ties broken by smallest byte for determinism).
//!   - `mean_importance` — average `importance` across events.
//!   - `event_ids` — every `event_id` in the window, in ts-ascending
//!     order, so callers can hydrate full text via a follow-up
//!     `SELECT … FROM idx_episode WHERE event_id IN (…)`.
//!
//! ## Why not a SQL view + `GROUP BY` window function?
//!
//! SQLite's window-function `LAG`/`OVER` could express the grouping
//! but the post-grouping pass to compute `dominant_event_type` and
//! collect `event_ids` per group needs row-by-row aggregation that
//! doesn't fit into a single SQL `SELECT`. The two-step (SELECT raw
//! → group in Rust) is straightforward and keeps the view portable
//! across SQLite versions that lag on window-function support.

use rusqlite::Connection;

/// Default temporal window: 60 minutes in nanoseconds.
/// `60 * 60 * 1_000_000_000`.
pub const DEFAULT_WINDOW_NS: i64 = 60 * 60 * 1_000_000_000;

/// One temporally-contiguous burst of events grouped from
/// `idx_episode`. See module-level docs for the field semantics.
#[derive(Debug, Clone, PartialEq)]
pub struct EpisodeSummary {
    pub start_ts_ns: i64,
    pub end_ts_ns: i64,
    pub event_count: usize,
    pub dominant_event_type: Option<u8>,
    pub mean_importance: f64,
    pub event_ids: Vec<i64>,
}

impl EpisodeSummary {
    /// Wall-clock duration of the episode in nanoseconds. Always
    /// `>= 0`; single-event episodes have `duration_ns == 0`.
    pub fn duration_ns(&self) -> i64 {
        self.end_ts_ns - self.start_ts_ns
    }
}

/// Raw row shape pulled from `idx_episode` before grouping. Public
/// so tests can construct synthetic rows + call [`group_episodes`]
/// without touching SQLite.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EpisodeRow {
    pub event_id: i64,
    pub event_type: u8,
    pub ts_ns: i64,
    pub importance: f64,
}

/// Errors surfaced by [`fetch_episodes`]. SQLite failures keep the
/// raw error string so the operator's `neoth memory episodes` CLI
/// can surface the underlying cause.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum EpisodeViewError {
    #[error("SQLite read failed: {0}")]
    Sqlite(String),
    #[error("window_size_ns must be > 0, got {0}")]
    InvalidWindow(i64),
    #[error("from_ns ({from}) > to_ns ({to}) — caller-side bounds bug")]
    ReversedBounds { from: i64, to: i64 },
}

/// Read every `idx_episode` row in `[from_ns, to_ns]` (inclusive),
/// group into temporal-window episodes, return the summary list
/// ordered by `start_ts_ns` ascending.
///
/// Empty result is `Ok(vec![])` — not an error — so callers can
/// dispatch "what happened last week?" queries against profiles
/// with no activity in the window.
pub fn fetch_episodes(
    conn: &Connection,
    from_ns: i64,
    to_ns: i64,
    window_size_ns: i64,
) -> Result<Vec<EpisodeSummary>, EpisodeViewError> {
    if window_size_ns <= 0 {
        return Err(EpisodeViewError::InvalidWindow(window_size_ns));
    }
    if from_ns > to_ns {
        return Err(EpisodeViewError::ReversedBounds {
            from: from_ns,
            to: to_ns,
        });
    }
    let mut stmt = conn
        .prepare(
            "SELECT event_id, event_type, ts_ns, importance \
             FROM idx_episode \
             WHERE ts_ns BETWEEN ?1 AND ?2 \
             ORDER BY ts_ns ASC, event_id ASC",
        )
        .map_err(|e| EpisodeViewError::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map(rusqlite::params![from_ns, to_ns], |row| {
            Ok(EpisodeRow {
                event_id: row.get(0)?,
                event_type: row.get::<_, i64>(1)? as u8,
                ts_ns: row.get(2)?,
                importance: row.get(3)?,
            })
        })
        .map_err(|e| EpisodeViewError::Sqlite(e.to_string()))?;
    let mut collected = Vec::new();
    for row in rows {
        collected.push(row.map_err(|e| EpisodeViewError::Sqlite(e.to_string()))?);
    }
    Ok(group_episodes(&collected, window_size_ns))
}

/// Pure-fn grouping helper — same logic [`fetch_episodes`] uses
/// post-SELECT. Public so tests can run grouping against synthetic
/// row sequences without SQLite.
///
/// Input MUST be sorted by `ts_ns` ascending; the function does not
/// re-sort. (Production callers run `ORDER BY ts_ns ASC` in the
/// SELECT; tests should pass already-sorted slices.)
pub fn group_episodes(rows: &[EpisodeRow], window_size_ns: i64) -> Vec<EpisodeSummary> {
    if rows.is_empty() || window_size_ns <= 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut current: Vec<EpisodeRow> = vec![rows[0]];
    for row in rows.iter().skip(1) {
        let prev_ts = current
            .last()
            .expect("current is non-empty by construction")
            .ts_ns;
        if row.ts_ns - prev_ts <= window_size_ns {
            current.push(*row);
        } else {
            out.push(summarise(&current));
            current = vec![*row];
        }
    }
    out.push(summarise(&current));
    out
}

fn summarise(rows: &[EpisodeRow]) -> EpisodeSummary {
    debug_assert!(!rows.is_empty(), "summarise called with empty slice");
    let start_ts_ns = rows.first().expect("non-empty").ts_ns;
    let end_ts_ns = rows.last().expect("non-empty").ts_ns;
    let event_count = rows.len();
    let mean_importance = rows.iter().map(|r| r.importance).sum::<f64>() / event_count as f64;

    // Dominant event type: most frequent, ties broken by smallest
    // byte for determinism. A small fixed-size array is faster than
    // HashMap for u8-domain (256 buckets) and avoids hash randomisation.
    let mut counts = [0u32; 256];
    for r in rows {
        counts[r.event_type as usize] += 1;
    }
    let dominant_event_type = counts
        .iter()
        .enumerate()
        .filter(|(_, c)| **c > 0)
        .max_by(|(a_byte, a_count), (b_byte, b_count)| {
            a_count.cmp(b_count).then_with(|| b_byte.cmp(a_byte)) // tie: smaller byte wins
        })
        .map(|(b, _)| b as u8);

    let event_ids: Vec<i64> = rows.iter().map(|r| r.event_id).collect();

    EpisodeSummary {
        start_ts_ns,
        end_ts_ns,
        event_count,
        dominant_event_type,
        mean_importance,
        event_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(event_id: i64, event_type: u8, ts_ns: i64, importance: f64) -> EpisodeRow {
        EpisodeRow {
            event_id,
            event_type,
            ts_ns,
            importance,
        }
    }

    const ONE_HOUR_NS: i64 = 60 * 60 * 1_000_000_000;
    const ONE_MIN_NS: i64 = 60 * 1_000_000_000;

    // ── group_episodes pure-fn tests ──────────────────────────────

    #[test]
    fn group_empty_input_returns_empty() {
        let out = group_episodes(&[], ONE_HOUR_NS);
        assert!(out.is_empty());
    }

    #[test]
    fn group_single_event_one_episode() {
        let rows = vec![r(1, 0x01, 1_000_000, 0.5)];
        let out = group_episodes(&rows, ONE_HOUR_NS);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].event_count, 1);
        assert_eq!(out[0].start_ts_ns, 1_000_000);
        assert_eq!(out[0].end_ts_ns, 1_000_000);
        assert_eq!(out[0].duration_ns(), 0);
        assert_eq!(out[0].event_ids, vec![1]);
        assert_eq!(out[0].dominant_event_type, Some(0x01));
    }

    #[test]
    fn group_events_within_window_one_episode() {
        // Three events spread across 30 minutes — all in one episode
        // when window = 60min.
        let rows = vec![
            r(1, 0x01, 0, 0.5),
            r(2, 0x01, 15 * ONE_MIN_NS, 0.6),
            r(3, 0x01, 30 * ONE_MIN_NS, 0.7),
        ];
        let out = group_episodes(&rows, ONE_HOUR_NS);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].event_count, 3);
        assert_eq!(out[0].event_ids, vec![1, 2, 3]);
        assert!((out[0].mean_importance - 0.6).abs() < 1e-9);
    }

    #[test]
    fn group_events_with_wide_gap_splits_into_two_episodes() {
        // Two events 90 minutes apart — must split when window = 60min.
        let rows = vec![r(1, 0x01, 0, 0.5), r(2, 0x02, 90 * ONE_MIN_NS, 0.5)];
        let out = group_episodes(&rows, ONE_HOUR_NS);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].event_count, 1);
        assert_eq!(out[1].event_count, 1);
        assert_eq!(out[0].event_ids, vec![1]);
        assert_eq!(out[1].event_ids, vec![2]);
    }

    #[test]
    fn group_boundary_inclusive_at_exactly_window_size() {
        // Two events exactly 60 minutes apart — boundary is inclusive
        // (`<=` not `<`), so single episode.
        let rows = vec![r(1, 0x01, 0, 0.5), r(2, 0x01, ONE_HOUR_NS, 0.5)];
        let out = group_episodes(&rows, ONE_HOUR_NS);
        assert_eq!(out.len(), 1, "boundary must be inclusive");
        assert_eq!(out[0].event_count, 2);
    }

    #[test]
    fn group_boundary_exclusive_just_past_window_size() {
        // One ns past the window → new episode.
        let rows = vec![r(1, 0x01, 0, 0.5), r(2, 0x01, ONE_HOUR_NS + 1, 0.5)];
        let out = group_episodes(&rows, ONE_HOUR_NS);
        assert_eq!(out.len(), 2, "gap > window must split");
    }

    #[test]
    fn group_dominant_event_type_is_most_frequent() {
        let rows = vec![
            r(1, 0x01, 0, 0.5),
            r(2, 0x02, ONE_MIN_NS, 0.5),
            r(3, 0x02, 2 * ONE_MIN_NS, 0.5),
            r(4, 0x01, 3 * ONE_MIN_NS, 0.5),
            r(5, 0x02, 4 * ONE_MIN_NS, 0.5),
        ];
        let out = group_episodes(&rows, ONE_HOUR_NS);
        assert_eq!(out.len(), 1);
        // 0x02 appears 3 times vs 0x01 twice → dominant is 0x02.
        assert_eq!(out[0].dominant_event_type, Some(0x02));
    }

    #[test]
    fn group_dominant_event_type_tie_breaks_to_smaller_byte() {
        // Two event types each appear twice → tie. Determinism rule:
        // smaller byte wins so a re-ordered input produces the same
        // output (recall queries can rely on the output shape).
        let rows = vec![
            r(1, 0x10, 0, 0.5),
            r(2, 0x05, ONE_MIN_NS, 0.5),
            r(3, 0x10, 2 * ONE_MIN_NS, 0.5),
            r(4, 0x05, 3 * ONE_MIN_NS, 0.5),
        ];
        let out = group_episodes(&rows, ONE_HOUR_NS);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dominant_event_type, Some(0x05));
    }

    #[test]
    fn group_mean_importance_is_arithmetic_mean() {
        let rows = vec![
            r(1, 0x01, 0, 0.2),
            r(2, 0x01, ONE_MIN_NS, 0.4),
            r(3, 0x01, 2 * ONE_MIN_NS, 0.6),
            r(4, 0x01, 3 * ONE_MIN_NS, 0.8),
        ];
        let out = group_episodes(&rows, ONE_HOUR_NS);
        assert!((out[0].mean_importance - 0.5).abs() < 1e-9);
    }

    #[test]
    fn group_zero_window_returns_empty() {
        // Defensive: a 0-ns window can't group anything sensibly.
        // Returning empty avoids the alternative (every row its own
        // 1-event episode) which would be a footgun for callers that
        // expected a sensible default.
        let rows = vec![r(1, 0x01, 0, 0.5)];
        let out = group_episodes(&rows, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn duration_ns_is_end_minus_start() {
        let rows = vec![r(1, 0x01, 1_000_000, 0.5), r(2, 0x01, 5_000_000, 0.5)];
        let out = group_episodes(&rows, ONE_HOUR_NS);
        assert_eq!(out[0].duration_ns(), 4_000_000);
    }

    // ── fetch_episodes integration tests against in-memory SQLite ─

    fn build_idx_episode_schema(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE idx_episode (
                event_id       INTEGER PRIMARY KEY,
                event_type     INTEGER NOT NULL,
                ts_ns          INTEGER NOT NULL,
                text           TEXT NOT NULL,
                text_hash      TEXT NOT NULL,
                channel        TEXT,
                sender_id      TEXT,
                operator_id    TEXT,
                importance     REAL NOT NULL DEFAULT 0.5,
                last_access_ts INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
    }

    fn insert_row(conn: &Connection, event_id: i64, event_type: u8, ts_ns: i64, importance: f64) {
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![event_id, event_type as i64, ts_ns, "x", "h", importance],
        )
        .unwrap();
    }

    #[test]
    fn fetch_episodes_round_trips_in_memory() {
        let conn = Connection::open_in_memory().unwrap();
        build_idx_episode_schema(&conn);
        insert_row(&conn, 1, 0x01, 0, 0.5);
        insert_row(&conn, 2, 0x01, 15 * ONE_MIN_NS, 0.6);
        insert_row(&conn, 3, 0x01, 3 * ONE_HOUR_NS, 0.7);
        let out = fetch_episodes(&conn, 0, 10 * ONE_HOUR_NS, ONE_HOUR_NS).unwrap();
        assert_eq!(out.len(), 2, "two episodes — first burst then gap");
        assert_eq!(out[0].event_count, 2);
        assert_eq!(out[1].event_count, 1);
        assert_eq!(out[0].event_ids, vec![1, 2]);
        assert_eq!(out[1].event_ids, vec![3]);
    }

    #[test]
    fn fetch_episodes_respects_window_bounds() {
        let conn = Connection::open_in_memory().unwrap();
        build_idx_episode_schema(&conn);
        insert_row(&conn, 1, 0x01, 0, 0.5);
        insert_row(&conn, 2, 0x01, 5 * ONE_HOUR_NS, 0.5);
        insert_row(&conn, 3, 0x01, 10 * ONE_HOUR_NS, 0.5);
        // Query window 4h..8h should only catch event 2.
        let out = fetch_episodes(&conn, 4 * ONE_HOUR_NS, 8 * ONE_HOUR_NS, ONE_HOUR_NS).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].event_ids, vec![2]);
    }

    #[test]
    fn fetch_episodes_empty_db_returns_empty() {
        let conn = Connection::open_in_memory().unwrap();
        build_idx_episode_schema(&conn);
        let out = fetch_episodes(&conn, 0, ONE_HOUR_NS, ONE_HOUR_NS).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn fetch_episodes_rejects_invalid_window() {
        let conn = Connection::open_in_memory().unwrap();
        build_idx_episode_schema(&conn);
        let err = fetch_episodes(&conn, 0, ONE_HOUR_NS, 0).unwrap_err();
        match err {
            EpisodeViewError::InvalidWindow(w) => assert_eq!(w, 0),
            other => panic!("expected InvalidWindow, got {other:?}"),
        }
        let err = fetch_episodes(&conn, 0, ONE_HOUR_NS, -1).unwrap_err();
        assert!(matches!(err, EpisodeViewError::InvalidWindow(_)));
    }

    #[test]
    fn fetch_episodes_rejects_reversed_bounds() {
        let conn = Connection::open_in_memory().unwrap();
        build_idx_episode_schema(&conn);
        let err = fetch_episodes(&conn, ONE_HOUR_NS, 0, ONE_HOUR_NS).unwrap_err();
        match err {
            EpisodeViewError::ReversedBounds { from, to } => {
                assert_eq!(from, ONE_HOUR_NS);
                assert_eq!(to, 0);
            }
            other => panic!("expected ReversedBounds, got {other:?}"),
        }
    }

    #[test]
    fn default_window_ns_is_60_minutes() {
        // Drift guard: a future const-rebase that bumps the window
        // to 90min (or down to 30min) would silently break callers
        // that import DEFAULT_WINDOW_NS without reading the comment.
        assert_eq!(DEFAULT_WINDOW_NS, 60 * 60 * 1_000_000_000);
        assert_eq!(DEFAULT_WINDOW_NS, ONE_HOUR_NS);
    }
}
