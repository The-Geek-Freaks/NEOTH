//! WAL-VIEWS-SCALE-01 — synthetic long-run scalability fixture for the
//! `views.db` episode projection + FTS query paths.
//!
//! Append-only WAL + a SQLite projection can degrade for a long-lived
//! operator (months of `idx_episode` rows, FTS index bloat). This fixture
//! seeds a configurable number of synthetic episode rows spanning a
//! configurable number of months into a REAL `views.db` (faithful schema via
//! [`crate::memory::store::open`], so the FTS triggers + indexes match
//! production), then measures:
//!
//!   1. **Projection latency** — `episode::fetch_episodes` over the full range
//!      (the Hippocampus recall path: SELECT + Rust-side temporal grouping).
//!   2. **FTS query latency** — an `idx_episode_fts MATCH` term lookup (the
//!      full-text recall path).
//!   3. **Index bloat** — the on-disk `views.db` byte size after seeding, as a
//!      proxy for storage growth per episode.
//!   4. **Rebuild path** — `INSERT INTO idx_episode_fts('rebuild')` wall-clock
//!      (the FTS compaction/rebuild operators run when the shadow tables bloat).
//!
//! ## Running
//!
//! The bench is `#[ignore]`d — it seeds tens of thousands of rows and is far
//! heavier than a unit test (and the box BSODs under parallel test load, so it
//! must never run in the default `cargo test` sweep). Run it on demand:
//!
//! ```text
//! cargo test -p neothd --lib scale_bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--nocapture` surfaces the measured latencies; the test also asserts a
//! deliberately GENEROUS ceiling on each so it doubles as a regression guard
//! (a projection that suddenly takes 10× longer fails the build) WITHOUT
//! turning a slow-CI-runner into a flake.
//!
//! ## Roadmap threshold (the "done when" deliverable)
//!
//! On the reference dev box (Windows 11, NVMe) the projection over
//! [`SEED_ROWS`] rows spanning [`SEED_MONTHS`] months completes well under
//! [`PROJECTION_CEILING_MS`]. **Optimize when** either holds in the field:
//!   - projection latency over a real operator's `views.db` exceeds ~500 ms
//!     (the point where the synchronous recall path is user-perceptible), or
//!   - `views.db` exceeds ~1 GiB / the FTS shadow tables exceed ~2× the base
//!     `idx_episode` size (rebuild cadence should then move from manual to a
//!     scheduled compaction cron).
//! Below those, the append-only-projection design needs no change.

#[cfg(test)]
mod tests {
    use crate::wal::views::episode;

    /// Synthetic rows to seed. Kept modest so the ignored bench still finishes
    /// in a few seconds on the dev box; raise locally to probe higher scales.
    const SEED_ROWS: i64 = 50_000;
    /// Calendar span the rows are spread across (dictates episode fan-out).
    const SEED_MONTHS: i64 = 6;
    /// Generous projection ceiling — a regression guard, NOT a perf SLA.
    const PROJECTION_CEILING_MS: u128 = 4_000;
    /// Generous FTS single-term ceiling.
    const FTS_CEILING_MS: u128 = 1_000;

    const NS_PER_DAY: i64 = 86_400 * 1_000_000_000;

    /// Seed `SEED_ROWS` episode rows spanning `SEED_MONTHS` into `conn`.
    /// Rows are evenly spaced in time; every 40th row carries the word
    /// "rustlang" so the FTS query has a bounded, non-trivial match set.
    fn seed_episodes(conn: &rusqlite::Connection) {
        let span_ns = SEED_MONTHS * 30 * NS_PER_DAY;
        let step = (span_ns / SEED_ROWS).max(1);
        let tx = conn.unchecked_transaction().expect("begin tx");
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO idx_episode \
                     (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                )
                .expect("prepare insert");
            for i in 0..SEED_ROWS {
                let ts = i * step;
                // Vary event_type across a small domain so dominant-type
                // grouping does real work; bias importance a little.
                let event_type = i % 7;
                let text = if i % 40 == 0 {
                    format!("synthetic episode {i} about rustlang memory recall")
                } else {
                    format!("synthetic episode {i} about daily operator activity")
                };
                let text_hash = format!("h{i:016x}");
                let importance = 0.1 + ((i % 10) as f64) / 10.0;
                stmt.execute(rusqlite::params![
                    i, event_type, ts, text, text_hash, importance
                ])
                .expect("insert row");
            }
        }
        tx.commit().expect("commit seed");
    }

    #[test]
    #[ignore = "heavy synthetic-scale bench — run explicitly with --ignored --nocapture"]
    fn views_projection_and_fts_scale_within_ceilings() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("views.db");
        // Faithful schema — real idx_episode + idx_episode_fts + triggers.
        let conn = crate::memory::store::open(&db_path).expect("open views.db");

        let seed_start = std::time::Instant::now();
        seed_episodes(&conn);
        let seed_ms = seed_start.elapsed().as_millis();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_episode", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, SEED_ROWS, "all rows seeded");

        // 1. Projection latency over the full range.
        let span_ns = SEED_MONTHS * 30 * NS_PER_DAY;
        let proj_start = std::time::Instant::now();
        let episodes = episode::fetch_episodes(&conn, 0, span_ns, episode::DEFAULT_WINDOW_NS)
            .expect("fetch_episodes");
        let proj_ms = proj_start.elapsed().as_millis();
        assert!(!episodes.is_empty(), "projection produced episodes");

        // 2. FTS query latency — a bounded-match single term.
        let fts_start = std::time::Instant::now();
        let fts_hits: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_episode_fts WHERE idx_episode_fts MATCH 'rustlang'",
                [],
                |r| r.get(0),
            )
            .expect("fts match");
        let fts_ms = fts_start.elapsed().as_millis();
        assert!(fts_hits > 0, "FTS matched the seeded term");

        // 3. Index bloat — on-disk size after a WAL checkpoint.
        conn.pragma_update(None, "wal_checkpoint", "TRUNCATE").ok();
        let db_bytes = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
        let bytes_per_row = db_bytes / (SEED_ROWS.max(1) as u64);

        // 4. FTS rebuild/compaction path wall-clock.
        let rebuild_start = std::time::Instant::now();
        conn.execute(
            "INSERT INTO idx_episode_fts(idx_episode_fts) VALUES ('rebuild')",
            [],
        )
        .expect("fts rebuild");
        let rebuild_ms = rebuild_start.elapsed().as_millis();

        println!(
            "WAL-VIEWS-SCALE-01: rows={SEED_ROWS} span={SEED_MONTHS}mo episodes={} \
             | seed={seed_ms}ms projection={proj_ms}ms fts={fts_ms}ms(hits={fts_hits}) \
             rebuild={rebuild_ms}ms | db={db_bytes}B (~{bytes_per_row}B/row)",
            episodes.len()
        );

        assert!(
            proj_ms < PROJECTION_CEILING_MS,
            "projection {proj_ms}ms exceeded ceiling {PROJECTION_CEILING_MS}ms — \
             the append-only-projection design may need optimization (see module docs)"
        );
        assert!(
            fts_ms < FTS_CEILING_MS,
            "FTS query {fts_ms}ms exceeded ceiling {FTS_CEILING_MS}ms"
        );
    }
}
