//! SQLite-backed views over the WAL.
//!
//! Schema is opened idempotently — running `neoth serve` a second time
//! against an existing `~/.neoth/views.db` adds nothing if the schema is
//! current. Schema version tracked in `meta` table; future upgrades migrate
//! in-place.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Schema version. Bump + add migration code when the columns change.
/// v2 adds FTS5 virtual table `idx_episode_fts` linked to `idx_episode`.
/// v3 adds the ctx-mode tables: `sources`, `chunks` (porter FTS5), `chunks_trigram`
///     (trigram FTS5), `vocabulary` for Levenshtein fallback (Phase 26 R-19).
/// v4 adds memory-tier views (Phase 28a R-22): `idx_consolidated` (warm,
///     7-90d, per-day summary + retained high-importance events) and
///     `idx_longterm` (cold, >90d, Hebbian-survivor only). Migration in
///     `memory::migrations` registered as v3→v4.
/// v5 adds the immutable ground-truth view (Phase 28c R-24): `idx_groundtruth`
///     with `(id, statement, source, scope, asserted_at, revoked_at)`.
///     Decay never touches this table.
/// v10 adds `idx_profile_pending` (Session 24 ADV-03 item 4): operator-
///     confirmation queue for extracted profile deltas. Rows are written
///     by Stage 5b `approval_gate` in daemon mode (no tty), resolved via
///     `neoth profile approve <id>` (apply + delete row) or
///     `decline <id>` (drop + emit 0xB7).
/// v11 adds a CHECK constraint on `idx_consolidated.day` (M-05, Session
///     24): the column held free-form TEXT pre-fix, and the warm→cold
///     SQL comparison in `consolidate::run_consolidation_pass` is a
///     string compare against `ts_to_day_string(ninety_days_ago)`.
///     Anything that wasn't `YYYY-MM-DD` shape (e.g. a hand-rolled
///     INSERT with `2026/05/25` or `May 25`) silently mis-sorted and
///     either never aged out or aged out early. The constraint pins
///     the shape + valid month/day ranges; the v10→v11 migration
///     rebuilds the table and normalises any non-conforming rows
///     in flight from `consolidated_ts`.
pub const SCHEMA_VERSION: i64 = 20;

/// `~/.neoth/views.db` resolved against HOME / USERPROFILE.
pub fn default_path() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".neoth").join("views.db")
}

/// Open or create the views database. Applies schema. Sets unix mode 0600
/// on the file. Windows DACL restriction follows the same pattern as WAL
/// segments (see `wal/win_acl.rs`).
pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir for {}", path.display()))?;
    }
    let is_new = !path.exists();
    let conn =
        Connection::open(path).with_context(|| format!("open SQLite db {}", path.display()))?;

    // Pragmas: WAL mode for concurrent read while writer is indexing,
    // synchronous=NORMAL for the right durability/perf trade-off for views
    // (the authoritative log is our own WAL; views are reconstructable).
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("set SQLite journal_mode=WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("set SQLite synchronous=NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("set SQLite foreign_keys=ON")?;
    // TRAIL-01: prevent SQLITE_BUSY under concurrent daemon access.
    conn.pragma_update(None, "busy_timeout", 5_000i64)
        .context("set SQLite busy_timeout=5000")?;
    // TRAIL-01: checkpoint every 1000 WAL frames (SQLite default=1000; explicit
    // to survive config inheritance from the process environment).
    conn.pragma_update(None, "wal_autocheckpoint", 1_000i64)
        .context("set SQLite wal_autocheckpoint=1000")?;
    // TRAIL-01: 64 MiB memory-mapped I/O — reduces syscall overhead on Windows.
    conn.pragma_update(None, "mmap_size", 67_108_864i64)
        .context("set SQLite mmap_size=64MiB")?;
    // TRAIL-01: negative = KiB; -8000 ≈ 8 MiB page cache per connection.
    conn.pragma_update(None, "cache_size", -8_000i64)
        .context("set SQLite cache_size=-8000")?;
    // TRAIL-01: temp tables/indexes go to RAM, not a temp file on disk.
    conn.pragma_update(None, "temp_store", 2i64)
        .context("set SQLite temp_store=MEMORY")?;
    // TRAIL-05: cap -wal growth to 200 MiB — guards against AV-stalled
    // checkpoints on Windows leaving the WAL file unbounded.
    conn.pragma_update(None, "journal_size_limit", 209_715_200i64)
        .context("set SQLite journal_size_limit=200MiB")?;

    // Pick #34 (Session 14, architect audit-fix): force WAL recovery
    // BEFORE any migration query runs. On Windows, a hard kill
    // (Task Manager / forced reboot / power loss) leaves the
    // `-shm` / `-wal` sidecar files in an indeterminate state. The
    // next `Connection::open()` succeeds but a stale page can cause
    // migrations to fail with an opaque SQLite error. `PRAGMA
    // wal_checkpoint(TRUNCATE)` runs the WAL recovery dance + clears
    // the sidecar, so corrupt pages surface NOW (where we can log
    // the path), not deep inside an ALTER TABLE.
    //
    // Quick `integrity_check` (single page-list pass) runs after.
    // A "corrupt" result yields a hard error with the operator-readable
    // recovery hint, instead of letting later queries fail mysteriously.
    //
    // Both pragmas are skipped on a brand-new database — there's
    // nothing to recover or check.
    if !is_new {
        let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |_| Ok(()));
        let check: String = conn
            .query_row("PRAGMA integrity_check;", [], |row| row.get(0))
            .unwrap_or_else(|_| "unknown".to_string());
        if check != "ok" {
            anyhow::bail!(
                "SQLite integrity_check on {} returned `{check}` (not `ok`). \
                 The database is corrupt — likely from a hard-kill / power-loss \
                 while NEOTH was writing. Restore from `neoth backup` or run \
                 `sqlite3 {} '.recover'` to extract recoverable data.",
                path.display(),
                path.display(),
            );
        }
    }

    if is_new {
        // Brand-new database: stamp the current schema directly. The
        // migration registry stays out of the cold-start path.
        apply_schema(&conn)?;
    } else {
        // Existing database: read the version, fast-forward via the
        // migration registry. `current_version` returns 0 when `meta`
        // is empty, in which case `apply_schema` builds the latest
        // schema and we skip migrations (legacy databases predate v1).
        let current = crate::memory::migrations::current_version(&conn)?;
        if current == 0 {
            apply_schema(&conn)?;
        } else if current < SCHEMA_VERSION {
            // `migrate` needs &mut Connection. Reborrow via a fresh
            // open of the same path — the in-memory pragmas above are
            // already applied so reconnect is cheap.
            drop(conn);
            let mut migrating = Connection::open(path)
                .with_context(|| format!("reopen for migration {}", path.display()))?;
            migrating
                .pragma_update(None, "foreign_keys", "ON")
                .context("set foreign_keys=ON during migration")?;
            crate::memory::migrations::migrate(&mut migrating, current, SCHEMA_VERSION)?;
            return Ok(migrating);
        }
        // current >= SCHEMA_VERSION: nothing to do. A higher version means
        // the operator ran a newer neothd against this db before; we
        // leave it intact and trust forward-compat at the column level.
    }

    if is_new {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        #[cfg(windows)]
        {
            let _ = crate::wal::win_acl::restrict_to_owner(path);
        }
    }

    Ok(conn)
}

/// NN-MEM-01 — pin / unpin a hot-tier episode. Pinned episodes are
/// decay-immune: the daily consolidation pass skips their importance decay
/// (`memory::consolidate`), so a critical-but-rarely-accessed memory can never
/// drop below `FORGET_FLOOR` and be forgotten. Returns the rows affected
/// (0 when `event_id` is unknown).
pub fn set_episode_pinned(
    conn: &Connection,
    event_id: i64,
    pinned: bool,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE idx_episode SET pinned = ?1 WHERE event_id = ?2",
        rusqlite::params![pinned as i64, event_id],
    )
}

/// JV-MEM-05 / JV-MEM-09 — bump a row's recall `access_count` by one in the
/// backing table for its tier (`idx_episode` hot / `idx_consolidated` warm /
/// `idx_longterm` cold). Called best-effort on every recall hit; the retrieval
/// ranker uses the count both to stretch the recency half-life
/// ([`crate::memory::tiers::effective_half_life_days`], JV-MEM-05) and to
/// re-promote a frequently-recalled aged row's ranking tier
/// ([`crate::memory::tiers::tier_for_by_access`], JV-MEM-09). Warm lookup uses
/// `COALESCE(event_id, -id)` to match both retained + synthesised summary rows
/// (mirrors [`crate::memory::tiers::hebbian_reinforce_at_tier`]). Returns the
/// rows affected (0 when the id is not a live row in that tier).
pub fn increment_access_at_tier(
    conn: &Connection,
    tier: crate::memory::tiers::Tier,
    event_id: i64,
) -> rusqlite::Result<usize> {
    use crate::memory::tiers::Tier;
    let sql = match tier {
        Tier::Hot => "UPDATE idx_episode SET access_count = access_count + 1 WHERE event_id = ?1",
        Tier::Warm => {
            "UPDATE idx_consolidated SET access_count = access_count + 1 \
             WHERE COALESCE(event_id, -id) = ?1"
        }
        Tier::Cold => "UPDATE idx_longterm SET access_count = access_count + 1 WHERE event_id = ?1",
    };
    conn.execute(sql, rusqlite::params![event_id])
}

/// RECALL-METER-01 — record one recall-latency sample, pruning to the most
/// recent ~5000 rows so the table stays bounded. Returns the rusqlite error so
/// the (one-shot recall) caller can log-and-ignore: metering must NEVER fail
/// the recall itself.
pub fn record_recall_latency(
    conn: &Connection,
    ts_unix: i64,
    latency_ms: f64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO idx_recall_latency (ts_unix, latency_ms) VALUES (?1, ?2)",
        rusqlite::params![ts_unix, latency_ms],
    )?;
    // Prune: keep only the most recent ~5000 ids. When fewer than 5000 rows
    // exist, `MAX(id) - 5000` is negative → the WHERE matches nothing.
    conn.execute(
        "DELETE FROM idx_recall_latency \
         WHERE id <= (SELECT MAX(id) FROM idx_recall_latency) - 5000",
        [],
    )?;
    Ok(())
}

/// RECALL-METER-01 — the most recent `limit` recall-latency samples (ms),
/// newest first. The daemon recall-latency cron reads this window to compute
/// p95. Empty when no recall has run yet.
pub fn recent_recall_latencies_ms(conn: &Connection, limit: usize) -> rusqlite::Result<Vec<f64>> {
    let mut stmt =
        conn.prepare("SELECT latency_ms FROM idx_recall_latency ORDER BY id DESC LIMIT ?1")?;
    let rows = stmt.query_map(rusqlite::params![limit as i64], |r| r.get::<_, f64>(0))?;
    rows.collect()
}

/// GOLD-ADAPT-MEM-15 — record one `neoth recall` outcome sample (result count,
/// reinforcement count, query tier) for the recall-quality scorecard, pruning to
/// the most recent ~5000 rows. Best-effort like [`record_recall_latency`] — the
/// caller logs-and-ignores any error; scorecard metering must NEVER fail the
/// recall itself.
pub fn record_recall_event(
    conn: &Connection,
    ts_unix: i64,
    result_count: u32,
    reinforced_count: u32,
    tier: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO idx_recall_events (ts_unix, result_count, reinforced_count, tier) \
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![ts_unix, result_count as i64, reinforced_count as i64, tier],
    )?;
    conn.execute(
        "DELETE FROM idx_recall_events \
         WHERE id <= (SELECT MAX(id) FROM idx_recall_events) - 5000",
        [],
    )?;
    Ok(())
}

/// One stored recall-outcome sample (the recent-window row of [`idx_recall_events`]).
#[derive(Debug, Clone)]
pub struct RecallEvent {
    pub ts_unix: i64,
    pub result_count: u32,
    pub reinforced_count: u32,
    pub tier: String,
}

/// GOLD-ADAPT-MEM-15 — the recent recall-outcome window (newest first), capped at
/// `limit` rows. Empty when no recall has run yet.
pub fn recent_recall_events(conn: &Connection, limit: usize) -> rusqlite::Result<Vec<RecallEvent>> {
    let mut stmt = conn.prepare(
        "SELECT ts_unix, result_count, reinforced_count, tier \
         FROM idx_recall_events ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![limit as i64], |r| {
        Ok(RecallEvent {
            ts_unix: r.get(0)?,
            result_count: r.get::<_, i64>(1)? as u32,
            reinforced_count: r.get::<_, i64>(2)? as u32,
            tier: r.get(3)?,
        })
    })?;
    rows.collect()
}

/// GOLD-ADAPT-MEM-15 — recall-quality scorecard computed over a recent window.
/// Label-free: every metric is derived from signals NEOTH already records (result
/// counts, Hebbian reinforcements as a usefulness proxy, query tier, latency). The
/// hit/empty/reinforcement rates EXCLUDE Skip-tier queries (a status/identity
/// query returning nothing is not a recall miss).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecallScorecard {
    /// Number of outcome samples actually present in the window.
    pub window: usize,
    /// Total recalls in the window (all tiers).
    pub total_recalls: u32,
    /// `false` until at least 10 non-Skip recalls exist (rates aren't trustworthy
    /// on a handful of queries — don't cry wolf on cold start).
    pub data_sufficient: bool,
    /// Fraction of non-Skip recalls that returned at least one row.
    pub hit_rate: f64,
    /// `1.0 - hit_rate`.
    pub empty_rate: f64,
    /// Mean result count over non-empty non-Skip recalls.
    pub mean_result_count: f64,
    /// Mean of `reinforced_count / result_count` over non-empty non-Skip recalls
    /// (a row surfaced + then Hebbian-reinforced is a usefulness signal).
    pub reinforcement_rate: f64,
    pub tier_skip_pct: f64,
    pub tier_single_pct: f64,
    pub tier_multi_pct: f64,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_mean_ms: f64,
    pub window_start_ts: Option<i64>,
    pub window_end_ts: Option<i64>,
}

/// Nearest-rank percentile over the samples (`pct` in `[0,1]`). Empty → 0.0.
/// Inlined here (rather than reused from the daemon cron) so `memory` keeps no
/// dependency on `daemon`.
fn percentile(latencies: &[f64], pct: f64) -> f64 {
    if latencies.is_empty() {
        return 0.0;
    }
    let mut sorted = latencies.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (((sorted.len() - 1) as f64) * pct).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Pure scorecard aggregation over the recall-outcome window + the latency
/// window. Separated from the DB read so it is unit-tested directly.
pub fn compute_scorecard(events: &[RecallEvent], latencies: &[f64]) -> RecallScorecard {
    let total = events.len() as u32;
    let skip = events.iter().filter(|e| e.tier == "skip").count();
    let single = events.iter().filter(|e| e.tier == "single").count();
    let multi = events.iter().filter(|e| e.tier == "multi").count();

    let non_skip: Vec<&RecallEvent> = events.iter().filter(|e| e.tier != "skip").collect();
    let non_empty: Vec<&&RecallEvent> = non_skip.iter().filter(|e| e.result_count >= 1).collect();

    let hit_rate = if non_skip.is_empty() {
        0.0
    } else {
        non_empty.len() as f64 / non_skip.len() as f64
    };
    let mean_result_count = if non_empty.is_empty() {
        0.0
    } else {
        non_empty.iter().map(|e| e.result_count as f64).sum::<f64>() / non_empty.len() as f64
    };
    let reinforcement_rate = if non_empty.is_empty() {
        0.0
    } else {
        non_empty
            .iter()
            .map(|e| e.reinforced_count as f64 / e.result_count as f64)
            .sum::<f64>()
            / non_empty.len() as f64
    };
    let pct = |n: usize| {
        if total == 0 {
            0.0
        } else {
            n as f64 / total as f64 * 100.0
        }
    };
    let latency_mean_ms = if latencies.is_empty() {
        0.0
    } else {
        latencies.iter().sum::<f64>() / latencies.len() as f64
    };

    RecallScorecard {
        window: events.len(),
        total_recalls: total,
        data_sufficient: non_skip.len() >= 10,
        hit_rate,
        empty_rate: if non_skip.is_empty() {
            0.0
        } else {
            1.0 - hit_rate
        },
        mean_result_count,
        reinforcement_rate,
        tier_skip_pct: pct(skip),
        tier_single_pct: pct(single),
        tier_multi_pct: pct(multi),
        latency_p50_ms: percentile(latencies, 0.50),
        latency_p95_ms: percentile(latencies, 0.95),
        latency_mean_ms,
        window_start_ts: events.iter().map(|e| e.ts_unix).min(),
        window_end_ts: events.iter().map(|e| e.ts_unix).max(),
    }
}

/// GOLD-ADAPT-MEM-15 — read the recent recall-outcome + latency windows and
/// compute the [`RecallScorecard`]. The two windows are independent id sequences
/// aligned by recency (both `ORDER BY id DESC LIMIT window`), not joined.
pub fn recall_scorecard(conn: &Connection, window: usize) -> rusqlite::Result<RecallScorecard> {
    let events = recent_recall_events(conn, window)?;
    let latencies = recent_recall_latencies_ms(conn, window)?;
    Ok(compute_scorecard(&events, &latencies))
}

fn apply_schema(conn: &Connection) -> Result<()> {
    // `meta` first — used to track schema version + WAL cursor.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- One row per WAL segment we have indexed. `next_offset` tells the
        -- indexer where to resume after a restart. Without this every
        -- `neoth serve` would re-index the whole WAL on boot.
        CREATE TABLE IF NOT EXISTS wal_cursor (
            segment_path TEXT PRIMARY KEY,
            next_offset  INTEGER NOT NULL,
            updated_ts   INTEGER NOT NULL
        );

        -- idx_episode — Hippocampus view. Every RAW_TEXT WAL event is
        -- materialised here for recall queries. event_type encoded as
        -- integer so future event types stay queryable without schema bump.
        CREATE TABLE IF NOT EXISTS idx_episode (
            event_id       INTEGER PRIMARY KEY,
            event_type     INTEGER NOT NULL,
            ts_ns          INTEGER NOT NULL,
            text           TEXT NOT NULL,
            text_hash      TEXT NOT NULL,
            channel        TEXT,
            sender_id      TEXT,
            operator_id    TEXT,
            -- Phase 28a R-22: importance materialised here so the retrieval
            -- ranker can multiply by tier_weight without re-parsing the
            -- WAL header. Daily consolidation pass updates this column.
            importance     REAL NOT NULL DEFAULT 0.5,
            -- Last successful recall hit (ns since unix epoch). Updated by
            -- Hebbian reinforce. Used by R-22 recency_penalty term.
            last_access_ts INTEGER NOT NULL DEFAULT 0,
            -- NN-MEM-01: "pinned" decay-immune flag. The daily consolidation
            -- pass skips the importance decay of pinned episodes, so a
            -- critical-but-rarely-accessed memory can never fall below
            -- FORGET_FLOOR and be forgotten. Default 0 (not pinned).
            pinned         INTEGER NOT NULL DEFAULT 0,
            -- JV-MEM-05: access_count — number of recall hits while in the hot
            -- tier. Recall increments it; the retrieval ranker stretches a
            -- frequently-accessed memory's recency half-life so it decays
            -- slower (tiers::effective_half_life_days). Default 0.
            access_count   INTEGER NOT NULL DEFAULT 0,
            -- JV-MEM-14: per-event source-trust tag (0=low external / 1=medium /
            -- 2=high operator-explicit). Set at index time from the event source;
            -- weights recall ranking (tiers::trust_weight) so operator-typed
            -- memories outrank external chatter. Default 1 (medium).
            trust          INTEGER NOT NULL DEFAULT 1
        );

        CREATE INDEX IF NOT EXISTS idx_episode_ts          ON idx_episode (ts_ns DESC);
        CREATE INDEX IF NOT EXISTS idx_episode_hash        ON idx_episode (text_hash);
        CREATE INDEX IF NOT EXISTS idx_episode_importance  ON idx_episode (importance DESC);

        -- idx_provider — every PROVIDER_REQUEST + PROVIDER_RESPONSE pair.
        -- Joined by request_event_id so `recall --provider` can show
        -- prompt → reply pairs.
        CREATE TABLE IF NOT EXISTS idx_provider (
            event_id          INTEGER PRIMARY KEY,
            event_type        INTEGER NOT NULL, -- 0x20 request, 0x21 response
            ts_ns             INTEGER NOT NULL,
            provider          TEXT NOT NULL,
            model             TEXT,
            text_hash         TEXT,
            bytes             INTEGER,
            latency_ns        INTEGER,
            input_tokens      INTEGER,
            output_tokens     INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_provider_ts ON idx_provider (ts_ns DESC);

        -- RECALL-METER-01 — per-`neoth recall` latency samples. The one-shot
        -- recall CLI records one row per query here; the daemon's recall-latency
        -- cron (MONITOR-03) reads the recent window to compute p95. Cross-process
        -- bridge: recall runs in a separate process from the daemon, so an
        -- in-memory meter wouldn't be visible — this table is the durable seam.
        -- Bounded by a prune-on-insert (keeps the most recent ~5000 samples).
        CREATE TABLE IF NOT EXISTS idx_recall_latency (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_unix    INTEGER NOT NULL,
            latency_ms REAL    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_recall_latency_id ON idx_recall_latency (id DESC);

        -- GOLD-ADAPT-MEM-15 — per-`neoth recall` outcome samples feeding the
        -- recall-quality scorecard (hit-rate / result-count / reinforcement-rate
        -- / tier mix over time). Kept SEPARATE from idx_recall_latency so the
        -- MONITOR-03 p95 latency-alert path stays untouched. `tier` is the
        -- MEM-09 RecallTier ('skip'|'single'|'multi'). Bounded by the same
        -- prune-on-insert (~5000 most-recent samples).
        CREATE TABLE IF NOT EXISTS idx_recall_events (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_unix          INTEGER NOT NULL,
            result_count     INTEGER NOT NULL,
            reinforced_count INTEGER NOT NULL,
            tier             TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_recall_events_id ON idx_recall_events (id DESC);

        -- FTS5 virtual table content-linked to idx_episode. Stores no rows
        -- of its own; SELECT through MATCH pulls the linked rows via
        -- `content_rowid=event_id`. Triggers below keep it in sync.
        CREATE VIRTUAL TABLE IF NOT EXISTS idx_episode_fts USING fts5(
            text,
            content='idx_episode',
            content_rowid='event_id'
        );

        CREATE TRIGGER IF NOT EXISTS idx_episode_ai AFTER INSERT ON idx_episode BEGIN
            INSERT INTO idx_episode_fts(rowid, text) VALUES (new.event_id, new.text);
        END;

        CREATE TRIGGER IF NOT EXISTS idx_episode_ad AFTER DELETE ON idx_episode BEGIN
            INSERT INTO idx_episode_fts(idx_episode_fts, rowid, text)
                VALUES('delete', old.event_id, old.text);
        END;

        CREATE TRIGGER IF NOT EXISTS idx_episode_au AFTER UPDATE ON idx_episode BEGIN
            INSERT INTO idx_episode_fts(idx_episode_fts, rowid, text)
                VALUES('delete', old.event_id, old.text);
            INSERT INTO idx_episode_fts(rowid, text) VALUES (new.event_id, new.text);
        END;

        -- ── Schema v3: ctx-mode tables (Phase 26 R-19) ────────────────────
        -- `sources` is the row-level catalogue. Each indexed document gets one
        -- row; chunks reference back to it via `source_id`.
        CREATE TABLE IF NOT EXISTS sources (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            label           TEXT NOT NULL UNIQUE,
            content_hash    TEXT,
            file_path       TEXT,
            content_type    TEXT,
            source_category TEXT,
            chunk_count     INTEGER NOT NULL DEFAULT 0,
            indexed_ts      INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS sources_indexed_ts ON sources (indexed_ts DESC);
        CREATE INDEX IF NOT EXISTS sources_category   ON sources (source_category);

        -- Porter-stemmed FTS5 for BM25 relevance ranking.
        CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5(
            title, content,
            source_id UNINDEXED,
            content_type UNINDEXED,
            source_category UNINDEXED,
            event_id UNINDEXED,
            file_path UNINDEXED,
            ts_ns UNINDEXED,
            tokenize='porter unicode61'
        );

        -- Trigram FTS5 for substring fallback when BM25 returns nothing.
        -- Same columns so the search layer can union/select uniformly.
        CREATE VIRTUAL TABLE IF NOT EXISTS chunks_trigram USING fts5(
            title, content,
            source_id UNINDEXED,
            content_type UNINDEXED,
            source_category UNINDEXED,
            event_id UNINDEXED,
            file_path UNINDEXED,
            ts_ns UNINDEXED,
            tokenize='trigram'
        );

        -- Vocabulary table for Levenshtein fuzzy correction. Populated by
        -- the indexer on every chunk write; queried as last fallback after
        -- BM25 and trigram return zero rows.
        CREATE TABLE IF NOT EXISTS vocabulary (
            term      TEXT PRIMARY KEY,
            frequency INTEGER NOT NULL DEFAULT 1
        );

        -- ── Schema v4: memory tiers (Phase 28a R-22) ─────────────────────
        --
        -- `idx_consolidated` is the warm tier (7-90 days). Two row shapes
        -- share one table:
        --   kind = 'summary' : per-day LLM summary block (one row per day)
        --   kind = 'retained': individual high-importance event kept verbatim
        -- This avoids a second table + UNION queries during recall.
        --
        -- `importance` is the Hebbian-reinforced score at consolidation time;
        -- it continues to decay daily per the R-24 schedule (hot 0.97 /
        -- warm 0.99 / cold 0.997) and is the field the retrieval ranker
        -- multiplies against the tier_weight.
        CREATE TABLE IF NOT EXISTS idx_consolidated (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            kind          TEXT NOT NULL CHECK (kind IN ('summary', 'retained')),
            -- M-05 (Session 24): pin ISO-8601 'YYYY-MM-DD' shape +
            -- semantic month/day ranges. The warm→cold SQL compare in
            -- `consolidate::run_consolidation_pass` is a string compare;
            -- anything that wasn't this shape silently mis-sorted and
            -- either never aged out or aged out early. `consolidate.rs`
            -- only writes through `ts_to_day_string` so production
            -- INSERTs satisfy the constraint by construction.
            day           TEXT NOT NULL CHECK (
                day GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]'
                AND CAST(substr(day, 6, 2) AS INTEGER) BETWEEN 1 AND 12
                AND CAST(substr(day, 9, 2) AS INTEGER) BETWEEN 1 AND 31
            ),
            event_id      INTEGER,                    -- NULL for summary rows
            text          TEXT NOT NULL,
            text_hash     TEXT NOT NULL,
            importance    REAL NOT NULL,
            consolidated_ts INTEGER NOT NULL,
            last_access_ts  INTEGER NOT NULL,
            -- JV-MEM-09: access_count carried from idx_episode at hot→warm
            -- consolidation so a frequently-recalled memory keeps its recall
            -- frequency after it ages out of the hot tier and can re-promote in
            -- ranking (tiers::tier_for_by_access). Default 0.
            access_count    INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_consolidated_day        ON idx_consolidated (day DESC);
        CREATE INDEX IF NOT EXISTS idx_consolidated_kind_day   ON idx_consolidated (kind, day DESC);
        CREATE INDEX IF NOT EXISTS idx_consolidated_importance ON idx_consolidated (importance DESC);
        CREATE INDEX IF NOT EXISTS idx_consolidated_event_id   ON idx_consolidated (event_id);

        -- `idx_longterm` is the cold tier (>90 days). Only events whose
        -- importance crossed PROMOTION_THRESHOLD during the 90-day boundary
        -- pass live here. Everything else is dropped from queryable views
        -- but stays in the immutable archive (~/.neoth/archive/sessions/).
        CREATE TABLE IF NOT EXISTS idx_longterm (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id        INTEGER NOT NULL UNIQUE,
            text            TEXT NOT NULL,
            text_hash       TEXT NOT NULL,
            importance      REAL NOT NULL,
            promoted_ts     INTEGER NOT NULL,
            last_access_ts  INTEGER NOT NULL,
            archive_path    TEXT,                       -- pointer back to MD file
            -- JV-MEM-09: access_count carried from idx_consolidated at warm→cold
            -- promotion (see idx_consolidated.access_count). Default 0.
            access_count    INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_longterm_importance ON idx_longterm (importance DESC);
        CREATE INDEX IF NOT EXISTS idx_longterm_event_id   ON idx_longterm (event_id);

        -- ── Schema v5: ground-truth view (Phase 28c R-24) ────────────────
        --
        -- Authoritative facts the operator (or an explicit import) hard-stored.
        -- Different scoring path from importance-driven recall: ground-truth
        -- rows ALWAYS surface in recall before any episodic row and are NEVER
        -- decayed away. Revocation is an explicit operator action that sets
        -- `revoked_at`; queries filter `WHERE revoked_at IS NULL`.
        CREATE TABLE IF NOT EXISTS idx_groundtruth (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            statement       TEXT NOT NULL,
            source          TEXT NOT NULL,
            scope           TEXT NOT NULL,
            asserted_at     INTEGER NOT NULL,
            revoked_at      INTEGER,
            -- GOLD-ADAPT-MEM-01: fact trust state machine. Only 'verified' facts
            -- are surfaced into recall/council. Existing rows migrate to
            -- 'verified' (backward-compat); new external (import/omi) facts start
            -- 'candidate' until corroborated. source_weight is a JSON {source:count}
            -- map; >=2 distinct sources auto-promotes a candidate to verified.
            fact_state      TEXT NOT NULL DEFAULT 'verified',
            source_weight   TEXT NOT NULL DEFAULT '{}',
            -- v20: GOLD-ADAPT-JV-SELF-01 confidence, NN-MEM-03 evidence backlinks
            -- (JSON [episode_id,...]), NN-MEM-04 maturity + confirmed_count.
            confidence      REAL NOT NULL DEFAULT 0.5,
            evidence        TEXT NOT NULL DEFAULT '[]',
            maturity        TEXT NOT NULL DEFAULT 'emerging',
            confirmed_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_groundtruth_scope    ON idx_groundtruth (scope);
        CREATE INDEX IF NOT EXISTS idx_groundtruth_source   ON idx_groundtruth (source);
        CREATE INDEX IF NOT EXISTS idx_groundtruth_revoked  ON idx_groundtruth (revoked_at);
        CREATE INDEX IF NOT EXISTS idx_groundtruth_state    ON idx_groundtruth (fact_state);

        -- GOLD-ADAPT-MEM-02 — contradiction ledger: pairs of ground-truth facts
        -- that disagree (same scope, same subject, opposite polarity or diverging
        -- value). Canonical fact_a_id < fact_b_id (CHECK) + a UNIQUE pair index so
        -- a pair is recorded once. The lower-credibility fact is flagged
        -- fact_state='contradicted' in idx_groundtruth (MEM-01); this ledger is the
        -- audit + the operator's dismiss decision. `forget` deletes referencing
        -- rows (the FK is intentionally NOT declared — groundtruth is revoked, not
        -- deleted, so an explicit cascade in forget.rs handles cleanup).
        CREATE TABLE IF NOT EXISTS idx_contradictions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            fact_a_id    INTEGER NOT NULL,
            fact_b_id    INTEGER NOT NULL,
            confidence   REAL    NOT NULL DEFAULT 1.0,
            detected_at  INTEGER NOT NULL,
            resolved_at  INTEGER,
            decision     TEXT    NOT NULL DEFAULT 'pending',
            CHECK (fact_a_id < fact_b_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_contradictions_pair ON idx_contradictions (fact_a_id, fact_b_id);
        CREATE INDEX IF NOT EXISTS idx_contradictions_a ON idx_contradictions (fact_a_id);
        CREATE INDEX IF NOT EXISTS idx_contradictions_b ON idx_contradictions (fact_b_id);
        -- GOLD-ADAPT-MEM-02 — composite index for the contradiction scan's
        -- same-scope active-verified fact lookup.
        CREATE INDEX IF NOT EXISTS idx_groundtruth_scope_state ON idx_groundtruth (scope, revoked_at, fact_state);

        -- ── Schema v6: embedding store (R-9 vision Phase 2b persistence) ──
        --
        -- Fixed-dim dense vectors (CLIP-image today, audio + text later)
        -- with brute-force cosine similarity in `memory::embeddings`.
        -- Vectors are L2-normalised on write so similarity is one dot
        -- product per candidate. `(source_kind, source_ref)` is unique —
        -- re-extracting the same asset overwrites the prior row.
        CREATE TABLE IF NOT EXISTS idx_embedding (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source_kind TEXT NOT NULL,
            source_ref  TEXT NOT NULL,
            model       TEXT NOT NULL,
            embedding   BLOB NOT NULL,
            dim         INTEGER NOT NULL,
            created_at  INTEGER NOT NULL,
            UNIQUE (source_kind, source_ref)
        );

        CREATE INDEX IF NOT EXISTS idx_embedding_kind     ON idx_embedding (source_kind);
        CREATE INDEX IF NOT EXISTS idx_embedding_created  ON idx_embedding (created_at DESC);

        -- ── Schema v7: idx_profile (Phase 2 SPEC_proactive_learning §1) ───
        --
        -- Materialised view of every PROFILE_DELTA WAL event the apply
        -- Effect Adapter emitted. One row per accepted claim; `superseded_at`
        -- is set when a contradicting claim with higher confidence lands so
        -- recall queries can `WHERE superseded_at IS NULL` to see the live
        -- profile state. The (field, applied_at) composite index lets the
        -- profile-summary builder pull the latest claim per field in one query.
        CREATE TABLE IF NOT EXISTS idx_profile (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            extraction_id         TEXT NOT NULL,
            event_id              INTEGER NOT NULL,
            field                 TEXT NOT NULL,
            value_json            TEXT NOT NULL,
            confidence            REAL NOT NULL,
            evidence_event_ids    TEXT NOT NULL DEFAULT '[]',
            guard_version         TEXT,
            applied_at            INTEGER NOT NULL,
            superseded_at         INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_profile_field         ON idx_profile (field);
        CREATE INDEX IF NOT EXISTS idx_profile_field_applied ON idx_profile (field, applied_at DESC);
        CREATE INDEX IF NOT EXISTS idx_profile_superseded    ON idx_profile (superseded_at);
        CREATE INDEX IF NOT EXISTS idx_profile_extraction    ON idx_profile (extraction_id);

        -- ── Schema v8: idx_profile_redactions (SPEC_profile_claim_guard H2) ─
        --
        -- Per-field redaction registry. Operator marks a field as
        -- `never_recreate=1` to forbid the extractor pipeline from ever
        -- proposing a new claim against that field — even if conversation
        -- content seemingly justifies one. Powers `neoth memory --forget`
        -- + the stage-5 guard's H2 check. `revoked_at` flips a redaction
        -- off without deleting the audit row.
        CREATE TABLE IF NOT EXISTS idx_profile_redactions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            field           TEXT NOT NULL,
            never_recreate  INTEGER NOT NULL DEFAULT 1,
            reason          TEXT,
            asserted_by     TEXT NOT NULL,
            asserted_at     INTEGER NOT NULL,
            revoked_at      INTEGER
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_redactions_field_active
            ON idx_profile_redactions (field) WHERE revoked_at IS NULL;
        CREATE INDEX IF NOT EXISTS idx_profile_redactions_revoked
            ON idx_profile_redactions (revoked_at);

        -- ── SPEC-11: cross-channel human identity (C-12/C-13) ───────────────
        --
        -- `idx_human_identity` is one row per resolved person (a stable UUID v7
        -- minted on first sight); `idx_human_identity_aliases` maps each
        -- channel-native `(channel, sender_id, chat_id)` triple to that person.
        -- The inbound handler resolves-or-creates on every message (filling
        -- `InboundMessage.human_uuid`); `neoth identity list/merge` read + merge.
        -- CREATE-IF-NOT-EXISTS → backward-safe (pre-SPEC-11 dbs gain the tables
        -- on next open with no migration step).
        CREATE TABLE IF NOT EXISTS idx_human_identity (
            uuid             TEXT NOT NULL PRIMARY KEY,
            created_at_unix  INTEGER NOT NULL,
            -- SPEC-11 merge tombstone: when set, this identity was folded into
            -- the `merged_into` uuid (its aliases were reassigned there). Kept
            -- (not deleted) so the merge is reversible + auditable; `list`
            -- excludes tombstoned rows.
            merged_into      TEXT
        );
        CREATE TABLE IF NOT EXISTS idx_human_identity_aliases (
            uuid       TEXT NOT NULL,
            channel    TEXT NOT NULL,
            sender_id  TEXT NOT NULL,
            chat_id    TEXT NOT NULL,
            UNIQUE(channel, sender_id, chat_id)
        );
        CREATE INDEX IF NOT EXISTS idx_human_identity_aliases_uuid
            ON idx_human_identity_aliases (uuid);

        -- EM-01b P1c — inbound-email dedup / seen-state. `neoth email fetch`
        -- uses IMAP `SEARCH UNSEEN` + `BODY.PEEK[]` (non-destructive — it never
        -- sets \Seen), so an email the operator hasn't read on their own client
        -- stays UNSEEN and would be re-pulled + re-triaged on every fetch. This
        -- table records each message NEOTH already triaged (keyed by the stable
        -- RFC822 Message-ID, with the IMAP UID as fallback) so a re-fetch skips
        -- it. CREATE-IF-NOT-EXISTS → backward-safe.
        CREATE TABLE IF NOT EXISTS idx_email_seen (
            dedup_key        TEXT NOT NULL PRIMARY KEY,
            imap_uid         TEXT,
            first_seen_unix  INTEGER NOT NULL
        );

        -- GOLD-ADAPT-MEM-06 — knowledge-graph layer (NEOTH's only structural
        -- memory gap). Typed entities + weighted directed relations. The LLM
        -- entity/relation extraction at ingest lands in a later slice; the
        -- schema + persistence + BFS-neighbour query ship now. `forget`
        -- cascades into both. CREATE-IF-NOT-EXISTS → backward-safe.
        CREATE TABLE IF NOT EXISTS idx_entities (
            id           INTEGER PRIMARY KEY,
            name         TEXT NOT NULL,
            entity_type  TEXT NOT NULL DEFAULT 'unknown',
            attributes   TEXT NOT NULL DEFAULT '{}',
            source_count INTEGER NOT NULL DEFAULT 1,
            first_seen   INTEGER NOT NULL DEFAULT 0,
            last_seen    INTEGER NOT NULL DEFAULT 0,
            UNIQUE(name)
        );
        CREATE TABLE IF NOT EXISTS idx_relations (
            id        INTEGER PRIMARY KEY,
            src_id    INTEGER NOT NULL,
            dst_id    INTEGER NOT NULL,
            relation  TEXT NOT NULL,
            weight    REAL NOT NULL DEFAULT 1.0,
            UNIQUE(src_id, dst_id, relation)
        );
        CREATE INDEX IF NOT EXISTS idx_relations_src ON idx_relations (src_id);
        CREATE INDEX IF NOT EXISTS idx_relations_dst ON idx_relations (dst_id);

        -- GOLD-ADAPT-MEM-07 — Hebbian co-access association graph between memory
        -- ROWS (episodes), distinct from the scalar per-row importance. When
        -- several memories are recalled together their pairwise link is
        -- reinforced; `decay_task` decays + prunes link weights; recall can
        -- 1-hop-expand to associated memories. SYMMETRIC: stored canonically
        -- (lo_id < hi_id, one row/pair) — the CHECK enforces that every caller
        -- normalises the pair, so a single UNIQUE covers both directions.
        -- `forget` cascades. CREATE-IF-NOT-EXISTS → backward-safe.
        CREATE TABLE IF NOT EXISTS idx_memory_links (
            lo_id          INTEGER NOT NULL,
            hi_id          INTEGER NOT NULL,
            weight         REAL NOT NULL DEFAULT 1.0,
            last_co_access INTEGER NOT NULL DEFAULT 0,
            -- v20: GOLD-ADAPT-JV-MEM-08 Hebbian feedback counters per edge.
            feedback_success INTEGER NOT NULL DEFAULT 0,
            feedback_failure INTEGER NOT NULL DEFAULT 0,
            UNIQUE(lo_id, hi_id),
            CHECK(lo_id < hi_id)
        );
        CREATE INDEX IF NOT EXISTS idx_memory_links_lo ON idx_memory_links (lo_id);
        CREATE INDEX IF NOT EXISTS idx_memory_links_hi ON idx_memory_links (hi_id);
        CREATE INDEX IF NOT EXISTS idx_memory_links_weight ON idx_memory_links (weight DESC);

        -- ── Schema v9: idx_profile_outbox (Pick #12, Session 14) ────────────
        --
        -- Codex-flagged consistency hole: profile/apply.rs commits idx_profile
        -- rows BEFORE emitting WAL audit frames. A crash between the two
        -- leaves orphan SQLite rows with no audit trail. This outbox closes
        -- the gap via the classic Outbox pattern: WAL payloads are written
        -- INSIDE the same SQLite transaction as the idx_profile rows, then
        -- drained after commit. A drain failure leaves rows in the outbox
        -- — next `apply_delta` call (or daemon startup) replays them. ADR-002
        -- ratified by the Session 14 6-agent council consultation.
        --
        -- Schema rationale:
        --   - `event_type INTEGER` — the WAL event byte (0xB0/B1/B2)
        --   - `payload BLOB` — the serialised JSON payload, ready for
        --      `writer.append(header_built_from_type, payload)`
        --   - `extraction_id TEXT` — drain can target a specific
        --      extraction OR sweep all stale rows
        --   - `enqueued_at INTEGER` — Unix seconds, used for stale-row
        --      detection during startup-replay
        CREATE TABLE IF NOT EXISTS idx_profile_outbox (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            extraction_id TEXT NOT NULL,
            event_type    INTEGER NOT NULL,
            payload       BLOB NOT NULL,
            enqueued_at   INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_profile_outbox_extraction
            ON idx_profile_outbox (extraction_id);
        CREATE INDEX IF NOT EXISTS idx_profile_outbox_enqueued
            ON idx_profile_outbox (enqueued_at);

        -- ── Schema v10: idx_profile_pending (Session 24 ADV-03 item 4) ────
        --   - operator-confirmation queue for extracted profile deltas
        --   - `delta_json` is the full ProfileDelta serialised so
        --     `apply_delta` can replay it verbatim when approved
        --   - `extraction_id` is the dedup key; conflict aborts the insert
        --   - `created_at_unix` lets the CLI sort pending rows oldest-first
        CREATE TABLE IF NOT EXISTS idx_profile_pending (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            extraction_id   TEXT NOT NULL UNIQUE,
            delta_json      TEXT NOT NULL,
            claim_count     INTEGER NOT NULL,
            created_at_unix INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_profile_pending_created
            ON idx_profile_pending (created_at_unix ASC);
        "#,
    )
    .context("apply views schema")?;

    // SPEC-11 merge tombstone — idempotent column add for an `idx_human_identity`
    // created before the `merged_into` column existed. `CREATE TABLE IF NOT
    // EXISTS` never alters an existing table, so back-fill the column here;
    // `.ok()` swallows the "duplicate column" error on tables that already have it.
    let _ = conn.execute(
        "ALTER TABLE idx_human_identity ADD COLUMN merged_into TEXT",
        [],
    );

    // Stamp schema version (idempotent).
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?1)",
        [SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

// ── GOLD-ADAPT-TRAIL-04 — Multi-reader SQLite executor ───────────────────────

/// GOLD-ADAPT-TRAIL-04 — Multi-reader executor for `views.db`.
///
/// Holds **1 write connection** (serialises all DB-mutating operations) and
/// **N read connections** (round-robin, allowing truly concurrent reads under
/// SQLite WAL mode). SQLite WAL guarantees N concurrent readers with no
/// reader-writer lock contention, so `with_reader` calls return immediately
/// even while a write is in flight.
///
/// `rusqlite::Connection` is `Send` but `!Sync`; each connection is wrapped in
/// its own `tokio::sync::Mutex` so the struct is `Sync` and can be shared via
/// `Arc<ViewsExecutor>` across async tasks.
///
/// Construction: call [`ViewsExecutor::open`] once at daemon boot (in
/// `cli/serve.rs`) and distribute the `Arc` to all channel handlers via
/// `PipelineHandlerDeps::views_executor`. The writer mutex is also exposed as
/// a `&tokio::sync::Mutex<Connection>` (via [`write_conn_arc`]) so call sites
/// that use `PipelineConn::Shared` during the incremental migration can point
/// at the same serialised connection.
///
/// [`write_conn_arc`]: ViewsExecutor::write_conn_arc
pub struct ViewsExecutor {
    writer: tokio::sync::Mutex<rusqlite::Connection>,
    readers: Vec<tokio::sync::Mutex<rusqlite::Connection>>,
    next_reader: std::sync::atomic::AtomicUsize,
}

impl ViewsExecutor {
    /// Open 1 write connection + `reader_count` read connections (minimum 1)
    /// to `path`. All connections receive the full pragma set via [`open`].
    pub fn open(path: &std::path::Path, reader_count: usize) -> anyhow::Result<std::sync::Arc<Self>> {
        let writer = open(path)?;
        let count = reader_count.max(1);
        let readers: anyhow::Result<Vec<rusqlite::Connection>> =
            (0..count).map(|_| open(path)).collect();
        Ok(std::sync::Arc::new(Self {
            writer: tokio::sync::Mutex::new(writer),
            readers: readers?.into_iter().map(tokio::sync::Mutex::new).collect(),
            next_reader: std::sync::atomic::AtomicUsize::new(0),
        }))
    }

    /// Acquire the write connection for a DB-mutating closure. Serialises all
    /// writes through a single `Mutex<Connection>` — only one writer is ever
    /// active at a time, which is required by SQLite even in WAL mode.
    pub async fn with_writer<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&rusqlite::Connection) -> T,
    {
        let g = self.writer.lock().await;
        f(&g)
    }

    /// Acquire a read connection from the pool (round-robin index). Under WAL
    /// mode this never blocks waiting for the writer — each read connection
    /// sees a consistent snapshot of committed data.
    pub async fn with_reader<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&rusqlite::Connection) -> T,
    {
        let idx = self
            .next_reader
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.readers.len();
        let g = self.readers[idx].lock().await;
        f(&g)
    }

    /// Compatibility shim: exposes the write-connection mutex so call sites
    /// that need `Arc<tokio::sync::Mutex<Connection>>` (e.g. `PipelineConn::
    /// Shared`) can point at the executor's single writer during the incremental
    /// migration. Returns a reference to the inner `Mutex` — callers wrap it in
    /// `Arc::new(tokio::sync::Mutex<Connection>)` indirection via a clone of
    /// the executor `Arc` rather than extracting the mutex itself.
    ///
    /// **Internal use only.** Remove once all write-path call sites use
    /// `with_writer` directly.
    pub fn write_conn_arc(&self) -> &tokio::sync::Mutex<rusqlite::Connection> {
        &self.writer
    }
}

// SAFETY: `rusqlite::Connection` is `Send`; each is behind a `Mutex`, so
// `ViewsExecutor` is both `Send` and `Sync`.
unsafe impl Send for ViewsExecutor {}
unsafe impl Sync for ViewsExecutor {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn opens_and_creates_schema() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let conn = open(&path).expect("open");

        // Verify schema_version row exists.
        let v: i64 = conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .expect("schema_version row");
        assert_eq!(v, SCHEMA_VERSION);

        // Verify each table is queryable.
        for table in &["idx_episode", "idx_provider", "wal_cursor", "meta"] {
            let _: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap_or_else(|e| panic!("count from {table}: {e}"));
        }
    }

    #[test]
    fn open_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let _c1 = open(&path).expect("first open");
        let c2 = open(&path).expect("second open");
        let v: i64 = c2
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .expect("schema_version row");
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[cfg(unix)]
    #[test]
    fn views_db_is_mode_0600_on_create() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let _ = open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // ── GOLD-ADAPT-MEM-15 recall-quality scorecard ──

    fn ev(result_count: u32, reinforced_count: u32, tier: &str) -> RecallEvent {
        RecallEvent {
            ts_unix: 1,
            result_count,
            reinforced_count,
            tier: tier.to_string(),
        }
    }

    #[test]
    fn record_recall_event_round_trips_and_prunes() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("views.db")).unwrap();
        for _ in 0..3 {
            record_recall_event(&conn, 100, 5, 2, "single").unwrap();
        }
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_recall_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 3, "three events recorded");
        let rows = recent_recall_events(&conn, 10).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].tier, "single");
        assert_eq!(rows[0].result_count, 5);
        assert_eq!(rows[0].reinforced_count, 2);
    }

    #[test]
    fn compute_scorecard_hit_rate_excludes_skip_and_gates_on_sufficiency() {
        // 5 skip + 8 non-skip-with-results + 2 non-skip-empty = 15 total, 10 non-skip.
        let mut events = Vec::new();
        for _ in 0..5 {
            events.push(ev(0, 0, "skip"));
        }
        for _ in 0..8 {
            events.push(ev(5, 0, "single"));
        }
        for _ in 0..2 {
            events.push(ev(0, 0, "multi"));
        }
        let sc = compute_scorecard(&events, &[]);
        assert_eq!(sc.total_recalls, 15);
        assert!(sc.data_sufficient, "10 non-skip recalls ≥ the 10 floor");
        assert!(
            (sc.hit_rate - 0.8).abs() < 1e-9,
            "8/10 non-skip returned rows"
        );
        assert!((sc.empty_rate - 0.2).abs() < 1e-9);
        assert!((sc.tier_skip_pct - (5.0 / 15.0 * 100.0)).abs() < 1e-6);
        assert!((sc.tier_single_pct - (8.0 / 15.0 * 100.0)).abs() < 1e-6);
    }

    #[test]
    fn compute_scorecard_reinforcement_rate_is_mean_over_non_empty() {
        // (4 results, 2 reinforced)→0.5 and (2 results, 2 reinforced)→1.0 ⇒ mean 0.75.
        let events = vec![ev(4, 2, "single"), ev(2, 2, "multi")];
        let sc = compute_scorecard(&events, &[]);
        assert!((sc.reinforcement_rate - 0.75).abs() < 1e-9);
        assert!((sc.mean_result_count - 3.0).abs() < 1e-9);
        assert!(!sc.data_sufficient, "2 non-skip < 10");
    }

    #[test]
    fn compute_scorecard_latency_percentiles_are_nearest_rank() {
        let lat: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let sc = compute_scorecard(&[], &lat);
        // nearest-rank: p95 idx round(99*0.95)=94 ⇒ 95; p50 idx round(99*0.5)=50 ⇒ 51.
        assert_eq!(sc.latency_p95_ms, 95.0);
        assert_eq!(sc.latency_p50_ms, 51.0);
        assert!((sc.latency_mean_ms - 50.5).abs() < 1e-9);
    }

    #[test]
    fn compute_scorecard_empty_window_is_all_zero() {
        let sc = compute_scorecard(&[], &[]);
        assert_eq!(sc.total_recalls, 0);
        assert!(!sc.data_sufficient);
        assert_eq!(sc.hit_rate, 0.0);
        assert_eq!(sc.empty_rate, 0.0);
        assert_eq!(sc.window_start_ts, None);
        assert_eq!(sc.window_end_ts, None);
    }

    #[test]
    fn recall_scorecard_reads_both_windows_from_db() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("views.db")).unwrap();
        for i in 0..12i64 {
            let tier = if i < 2 { "skip" } else { "single" };
            let rc = if i < 2 { 0 } else { 3 };
            record_recall_event(&conn, i, rc, 1, tier).unwrap();
        }
        record_recall_latency(&conn, 1, 42.0).unwrap();
        let sc = recall_scorecard(&conn, 500).unwrap();
        assert_eq!(sc.total_recalls, 12);
        assert_eq!(sc.window, 12);
        assert!(
            (sc.hit_rate - 1.0).abs() < 1e-9,
            "all 10 non-skip returned rows"
        );
        assert!(sc.data_sufficient);
        assert_eq!(sc.latency_p50_ms, 42.0);
    }

    /// TRAIL-01 + TRAIL-05: verify hardening pragmas are actually applied.
    /// Reads each pragma back from SQLite and asserts the expected value,
    /// proving `open()` isn't silently swallowing the `pragma_update` errors.
    #[test]
    fn hardening_pragmas_are_set() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hardening_test.db");
        let conn = open(&path).expect("open");

        let busy: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .expect("busy_timeout");
        assert_eq!(busy, 5_000, "busy_timeout must be 5000 ms");

        let autockpt: i64 = conn
            .query_row("PRAGMA wal_autocheckpoint", [], |r| r.get(0))
            .expect("wal_autocheckpoint");
        assert_eq!(autockpt, 1_000, "wal_autocheckpoint must be 1000 frames");

        let mmap: i64 = conn
            .query_row("PRAGMA mmap_size", [], |r| r.get(0))
            .expect("mmap_size");
        assert_eq!(mmap, 67_108_864, "mmap_size must be 64 MiB");

        let cache: i64 = conn
            .query_row("PRAGMA cache_size", [], |r| r.get(0))
            .expect("cache_size");
        assert_eq!(cache, -8_000, "cache_size must be -8000 KiB");

        let temp: i64 = conn
            .query_row("PRAGMA temp_store", [], |r| r.get(0))
            .expect("temp_store");
        assert_eq!(temp, 2, "temp_store must be 2 (MEMORY)");

        let jsl: i64 = conn
            .query_row("PRAGMA journal_size_limit", [], |r| r.get(0))
            .expect("journal_size_limit");
        assert_eq!(jsl, 209_715_200, "journal_size_limit must be 200 MiB");
    }

    // ── GOLD-ADAPT-TRAIL-04 — ViewsExecutor unit tests ───────────────────────

    #[tokio::test]
    async fn trail04_views_executor_writer_and_reader_share_data() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let exec = ViewsExecutor::open(&path, 2).expect("open executor");

        // Write via the write connection.
        exec.with_writer(|conn| {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('trail04_key', 'trail04_val')",
                [],
            )
            .expect("insert via writer");
        })
        .await;

        // Read via a pool reader — must see the committed row.
        let v = exec
            .with_reader(|conn| {
                conn.query_row(
                    "SELECT value FROM meta WHERE key = 'trail04_key'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap()
            })
            .await;
        assert_eq!(v, "trail04_val");
    }

    #[tokio::test]
    async fn trail04_views_executor_concurrent_readers_do_not_block() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let exec = ViewsExecutor::open(&path, 3).expect("open executor");

        // Seed one row via the writer.
        exec.with_writer(|conn| {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('multi_key', '99')",
                [],
            )
            .unwrap();
        })
        .await;

        // Three concurrent readers — none should wait on the write lock.
        let exec2 = exec.clone();
        let exec3 = exec.clone();
        let (a, b, c) = tokio::join!(
            exec.with_reader(|conn| {
                conn.query_row(
                    "SELECT value FROM meta WHERE key='multi_key'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap()
            }),
            exec2.with_reader(|conn| {
                conn.query_row(
                    "SELECT value FROM meta WHERE key='multi_key'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap()
            }),
            exec3.with_reader(|conn| {
                conn.query_row(
                    "SELECT value FROM meta WHERE key='multi_key'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap()
            }),
        );
        assert_eq!(a, "99");
        assert_eq!(b, "99");
        assert_eq!(c, "99");
    }

    #[tokio::test]
    async fn trail04_views_executor_round_robin_wraps() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        // 2 readers: next_reader goes 0→1→2 (wraps to 0)→1→0 …
        let exec = ViewsExecutor::open(&path, 2).expect("open executor");
        // Drive the counter past usize::MAX boundary is impractical, but we
        // can verify that index selection doesn't panic on repeated reads.
        for _ in 0..10 {
            exec.with_reader(|conn| {
                let _v: i64 = conn
                    .query_row("SELECT COUNT(*) FROM meta", [], |r| r.get(0))
                    .unwrap();
            })
            .await;
        }
    }
}
