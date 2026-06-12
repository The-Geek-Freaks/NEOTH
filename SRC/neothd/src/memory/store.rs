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
pub const SCHEMA_VERSION: i64 = 12;

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
pub fn recent_recall_latencies_ms(
    conn: &Connection,
    limit: usize,
) -> rusqlite::Result<Vec<f64>> {
    let mut stmt =
        conn.prepare("SELECT latency_ms FROM idx_recall_latency ORDER BY id DESC LIMIT ?1")?;
    let rows = stmt.query_map(rusqlite::params![limit as i64], |r| r.get::<_, f64>(0))?;
    rows.collect()
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
            pinned         INTEGER NOT NULL DEFAULT 0
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
            last_access_ts  INTEGER NOT NULL
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
            archive_path    TEXT                        -- pointer back to MD file
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
            revoked_at      INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_groundtruth_scope    ON idx_groundtruth (scope);
        CREATE INDEX IF NOT EXISTS idx_groundtruth_source   ON idx_groundtruth (source);
        CREATE INDEX IF NOT EXISTS idx_groundtruth_revoked  ON idx_groundtruth (revoked_at);

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
    let _ = conn.execute("ALTER TABLE idx_human_identity ADD COLUMN merged_into TEXT", []);

    // Stamp schema version (idempotent).
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?1)",
        [SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

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
}
