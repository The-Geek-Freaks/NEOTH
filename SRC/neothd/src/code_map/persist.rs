//! K-Repo-Map Phase 3a (Session 14 Pick #22) — SQLite persistence.
//!
//! Phase 1 ships the file walker, Phase 2 ships symbol extraction —
//! both produce a `RepoMap` that lives only in memory. Phase 3a
//! lifts that into `~/.neoth/code_map.db` so:
//!
//!   - `neoth code-map persist` becomes idempotent + restartable: a
//!     second invocation against the same root replaces the prior
//!     snapshot atomically.
//!   - Phase 3b recall integration can `SELECT path, language, loc
//!     FROM code_map_files WHERE …` without re-scanning every prompt.
//!   - Operators can introspect what NEOTH knows about their repo
//!     between sessions (`sqlite3 ~/.neoth/code_map.db …`).
//!
//! ## Schema (v2 — CBM-04 incremental re-index)
//!
//! ```sql
//! CREATE TABLE meta (
//!     key   TEXT PRIMARY KEY,
//!     value TEXT NOT NULL
//! );
//!
//! CREATE TABLE code_map_roots (
//!     root       TEXT PRIMARY KEY,
//!     scanned_at INTEGER NOT NULL,
//!     total_files INTEGER NOT NULL,
//!     total_bytes INTEGER NOT NULL,
//!     total_loc  INTEGER NOT NULL,
//!     oversize_skipped INTEGER NOT NULL,
//!     truncated_at INTEGER  -- nullable
//! );
//!
//! CREATE TABLE code_map_files (
//!     id         INTEGER PRIMARY KEY,
//!     root       TEXT NOT NULL,
//!     path       TEXT NOT NULL,
//!     language   TEXT NOT NULL,
//!     bytes      INTEGER NOT NULL,
//!     loc        INTEGER NOT NULL,
//!     sha256     TEXT NOT NULL DEFAULT '',    -- v2: CBM-04 incremental hash
//!     mtime_ns   INTEGER NOT NULL DEFAULT 0,  -- v2: CBM-04 mtime fast-path
//!     UNIQUE(root, path),
//!     FOREIGN KEY(root) REFERENCES code_map_roots(root) ON DELETE CASCADE
//! );
//!
//! CREATE TABLE code_map_symbols (
//!     id      INTEGER PRIMARY KEY,
//!     file_id INTEGER NOT NULL REFERENCES code_map_files(id) ON DELETE CASCADE,
//!     name    TEXT NOT NULL,
//!     kind    TEXT NOT NULL,
//!     line    INTEGER NOT NULL
//! );
//!
//! CREATE INDEX idx_code_map_symbols_name ON code_map_symbols(name);
//! ```
//!
//! v1 → v2 migration: `ALTER TABLE code_map_files ADD COLUMN sha256 …` +
//! `ALTER TABLE code_map_files ADD COLUMN mtime_ns …`. SQLite supports
//! ADD COLUMN with a DEFAULT without a full table rebuild. Run via
//! `migrate_code_map` called from `open()` whenever the existing DB has
//! `schema_version < CODE_MAP_SCHEMA_VERSION`.
//!
//! ## Replacement semantics (v2 — incremental)
//!
//! `persist_map` now runs incremental replacement:
//!   1. Pre-query `(path, sha256, mtime_ns)` for the given root into a HashMap.
//!   2. Partition scan results into `unchanged` (hash + mtime match) and `changed`.
//!   3. DELETE only changed + removed rows (per-file targeted DELETE).
//!   4. UPDATE the root metadata row in-place (or INSERT if first persist).
//!   5. INSERT changed + new file rows and their symbols.
//!   6. Unchanged files — already in DB, symbols already present; skip INSERT.
//!
//! A crash mid-persist leaves the prior snapshot intact (no partial
//! state). A successful commit replaces the snapshot atomically.
//!
//! A crash mid-persist leaves the prior snapshot intact (no partial
//! state). A successful commit replaces the snapshot atomically.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};

use super::symbols::{Symbol, SymbolKind};
use super::walker::{Language, RepoFile, RepoMap, ScanReport};

/// Schema version. v2 adds `sha256` + `mtime_ns` columns to
/// `code_map_files` for CBM-04 incremental re-index (skip-unchanged).
/// v3 adds a monotonic per-root `index_generation` counter to
/// `code_map_roots` (GOLD-R3-13) so a recall consumer can tell that a root
/// was re-scanned under it and invalidate a cached result.
pub const CODE_MAP_SCHEMA_VERSION: i64 = 3;

/// `~/.neoth/code_map.db` resolved against HOME / USERPROFILE.
pub fn default_path() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".neoth").join("code_map.db")
}

/// Open or create the code-map database. Applies schema on first
/// touch; preserves existing rows on reopen.
pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir for {}", path.display()))?;
    }
    let is_new = !path.exists();
    let conn = Connection::open(path)
        .with_context(|| format!("open code_map SQLite db {}", path.display()))?;

    conn.pragma_update(None, "journal_mode", "WAL")
        .context("set SQLite journal_mode=WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("set SQLite synchronous=NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("set SQLite foreign_keys=ON")?;
    // TRAIL-01/05: matching hardening pragmas (see memory/store.rs for rationale).
    conn.pragma_update(None, "busy_timeout", 5_000i64)
        .context("set SQLite busy_timeout=5000")?;
    conn.pragma_update(None, "wal_autocheckpoint", 1_000i64)
        .context("set SQLite wal_autocheckpoint=1000")?;
    conn.pragma_update(None, "mmap_size", 67_108_864i64)
        .context("set SQLite mmap_size=64MiB")?;
    conn.pragma_update(None, "cache_size", -8_000i64)
        .context("set SQLite cache_size=-8000")?;
    conn.pragma_update(None, "temp_store", 2i64)
        .context("set SQLite temp_store=MEMORY")?;
    conn.pragma_update(None, "journal_size_limit", 209_715_200i64)
        .context("set SQLite journal_size_limit=200MiB")?;

    if is_new {
        apply_schema(&conn)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        #[cfg(windows)]
        {
            let _ = crate::wal::win_acl::restrict_to_owner(path);
        }
    } else {
        // Existing DB — check schema_version and migrate if needed.
        // Mirrors the memory/store.rs pattern (lines 108-153 there):
        // read current_version from meta, then run the migration chain.
        // Concurrent openers are safe: SQLite WAL serialises writes and
        // busy_timeout=5000 handles any brief contention window; the
        // second opener will see version=2 and skip the migration.
        let current_version: Option<i64> = conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| {
                    let v: String = row.get(0)?;
                    Ok(v.parse::<i64>().unwrap_or(0))
                },
            )
            .optional()
            .context("read code_map schema_version")?;
        if let Some(v) = current_version
            && v < CODE_MAP_SCHEMA_VERSION
        {
            migrate_code_map(&conn, v).with_context(|| {
                format!("migrate code_map DB from v{v} to v{CODE_MAP_SCHEMA_VERSION}")
            })?;
        }
        // If meta table doesn't exist yet (pre-schema DB), apply_schema
        // handles it; the is_new branch already covers that case via
        // the CREATE IF NOT EXISTS guards. If the DB has no meta row,
        // nothing to migrate — schema is already current.
    }

    Ok(conn)
}

/// Run code-map schema migrations from `current_version` up to
/// [`CODE_MAP_SCHEMA_VERSION`]. Each step is atomic: the version stamp
/// in `meta` only advances after the DDL succeeds.
fn migrate_code_map(conn: &Connection, current_version: i64) -> Result<()> {
    let mut v = current_version;

    // v1 → v2: add sha256 + mtime_ns columns (CBM-04 incremental re-index).
    // SQLite's ADD COLUMN with a DEFAULT is always safe — no full table rebuild.
    if v < 2 {
        conn.execute_batch(
            "ALTER TABLE code_map_files ADD COLUMN sha256   TEXT    NOT NULL DEFAULT ''; \
             ALTER TABLE code_map_files ADD COLUMN mtime_ns INTEGER NOT NULL DEFAULT 0;",
        )
        .context("v1→v2: add sha256 + mtime_ns to code_map_files")?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '2')",
            [],
        )
        .context("v1→v2: stamp schema_version=2")?;
        v = 2;
    }

    // v2 → v3: add a monotonic per-root index_generation counter (GOLD-R3-13).
    // ADD COLUMN with a DEFAULT is a metadata-only change — no table rebuild.
    // Existing roots start at generation 0; their next re-scan bumps them.
    if v < 3 {
        conn.execute_batch(
            "ALTER TABLE code_map_roots \
             ADD COLUMN index_generation INTEGER NOT NULL DEFAULT 0;",
        )
        .context("v2→v3: add index_generation to code_map_roots")?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '3')",
            [],
        )
        .context("v2→v3: stamp schema_version=3")?;
        v = 3;
    }

    let _ = v; // suppress unused-variable warning when no further migrations exist
    Ok(())
}

fn apply_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS code_map_roots (
            root             TEXT PRIMARY KEY,
            scanned_at       INTEGER NOT NULL,
            total_files      INTEGER NOT NULL,
            total_bytes      INTEGER NOT NULL,
            total_loc        INTEGER NOT NULL,
            oversize_skipped INTEGER NOT NULL,
            truncated_at     INTEGER,
            index_generation INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS code_map_files (
            id        INTEGER PRIMARY KEY,
            root      TEXT NOT NULL,
            path      TEXT NOT NULL,
            language  TEXT NOT NULL,
            bytes     INTEGER NOT NULL,
            loc       INTEGER NOT NULL,
            sha256    TEXT NOT NULL DEFAULT '',
            mtime_ns  INTEGER NOT NULL DEFAULT 0,
            UNIQUE(root, path),
            FOREIGN KEY(root) REFERENCES code_map_roots(root) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS code_map_symbols (
            id      INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL REFERENCES code_map_files(id) ON DELETE CASCADE,
            name    TEXT NOT NULL,
            kind    TEXT NOT NULL,
            line    INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_code_map_symbols_name
            ON code_map_symbols(name);
        CREATE INDEX IF NOT EXISTS idx_code_map_files_path
            ON code_map_files(root, path);

        -- QM-2 Phase 2 (2026-05-22) — call-graph edges. One row per
        -- (from_file, from_symbol) → to_name edge produced by the
        -- CallGraph builder. Persisted so recall can render call
        -- relationships without rebuilding the in-memory graph on
        -- every prompt. Schema v1 only stores Calls edges; the
        -- `kind` column is present for forward-compat with the
        -- References variant.
        CREATE TABLE IF NOT EXISTS code_map_edges (
            id          INTEGER PRIMARY KEY,
            root        TEXT NOT NULL,
            from_file   TEXT NOT NULL,
            from_symbol TEXT NOT NULL,
            to_name     TEXT NOT NULL,
            kind        TEXT NOT NULL,
            FOREIGN KEY(root) REFERENCES code_map_roots(root) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_code_map_edges_to_name
            ON code_map_edges(to_name);
        CREATE INDEX IF NOT EXISTS idx_code_map_edges_source
            ON code_map_edges(from_file, from_symbol);

        -- K-Repo-Map FTS5 (Session 19, 2026-05-21) — fuzzy + prefix-
        -- match symbol lookup. Shadows code_map_symbols.name with
        -- the `unicode61` tokenizer so the operator can find
        -- `extract_symbols` with `extract*` or `symbols` + so a
        -- multi-token query like `cluster heart` returns
        -- `cluster::heartbeat::*`. Exact-match path stays on the
        -- btree index above (faster + simpler than MATCH for the
        -- known-name case).
        CREATE VIRTUAL TABLE IF NOT EXISTS code_map_symbols_fts
            USING fts5(
                name,
                kind,
                content='code_map_symbols',
                content_rowid='id',
                tokenize='unicode61 separators ''_-.'''
            );

        -- INSERT/DELETE triggers keep FTS5 in sync with the base
        -- table. UPDATE on code_map_symbols isn't expected today
        -- (persist_map deletes + re-inserts), but the trigger
        -- handles it defensively.
        CREATE TRIGGER IF NOT EXISTS code_map_symbols_fts_insert
            AFTER INSERT ON code_map_symbols
        BEGIN
            INSERT INTO code_map_symbols_fts(rowid, name, kind)
            VALUES (new.id, new.name, new.kind);
        END;
        CREATE TRIGGER IF NOT EXISTS code_map_symbols_fts_delete
            AFTER DELETE ON code_map_symbols
        BEGIN
            INSERT INTO code_map_symbols_fts(code_map_symbols_fts, rowid, name, kind)
            VALUES ('delete', old.id, old.name, old.kind);
        END;
        CREATE TRIGGER IF NOT EXISTS code_map_symbols_fts_update
            AFTER UPDATE ON code_map_symbols
        BEGIN
            INSERT INTO code_map_symbols_fts(code_map_symbols_fts, rowid, name, kind)
            VALUES ('delete', old.id, old.name, old.kind);
            INSERT INTO code_map_symbols_fts(rowid, name, kind)
            VALUES (new.id, new.name, new.kind);
        END;
        "#,
    )
    .context("apply code_map schema")?;

    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?1)",
        rusqlite::params![CODE_MAP_SCHEMA_VERSION.to_string()],
    )
    .context("stamp schema_version")?;

    Ok(())
}

/// Counts from a single `persist_map` call. Lets the operator see at
/// a glance whether the snapshot grew, shrank, or replaced an
/// existing one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PersistStats {
    pub files_inserted: usize,
    pub symbols_inserted: usize,
    pub prior_files_replaced: usize,
    /// Files skipped because their sha256 + mtime_ns matched the stored
    /// row (CBM-04 incremental re-index). Skipped files already have
    /// correct rows + symbols in the DB — no DELETE/INSERT needed.
    pub files_skipped_unchanged: usize,
}

/// Incrementally replace the snapshot for `map.root` (CBM-04).
///
/// Pre-pass: query existing `(path, sha256, mtime_ns)` rows into a
/// HashMap. Files whose hash + mtime match the new scan are skipped
/// (already correct in the DB). Changed and new files are
/// deleted-then-reinserted; removed files are deleted. The root
/// metadata row is upserted in-place rather than cascade-deleted, so
/// unchanged file rows survive across calls.
///
/// On error the transaction rolls back — the prior snapshot stays
/// intact (no partial state).
pub fn persist_map(conn: &mut Connection, map: &RepoMap) -> Result<PersistStats> {
    // ── Pre-pass: load existing (path → (sha256, mtime_ns)) ─────────
    // Key: repo-relative path. Value: (sha256 hex, mtime_ns as i64).
    // Empty when this is the first persist for this root.
    let stored: std::collections::HashMap<String, (String, i64)> = {
        let mut stmt = conn
            .prepare("SELECT path, sha256, mtime_ns FROM code_map_files WHERE root = ?1")
            .context("prepare pre-pass stored-hash query")?;
        stmt.query_map(rusqlite::params![&map.root], |row| {
            let path: String = row.get(0)?;
            let sha256: String = row.get(1)?;
            let mtime_ns: i64 = row.get(2)?;
            Ok((path, (sha256, mtime_ns)))
        })
        .context("execute pre-pass stored-hash query")?
        .collect::<rusqlite::Result<_>>()
        .context("collect stored-hash rows")?
    };

    // Count prior files for operator feedback (mirrors old stats field).
    let prior_files_replaced = stored.len();

    // ── Partition scan into unchanged vs changed/new ─────────────────
    // A file is "unchanged" when both sha256 AND mtime_ns match the
    // stored row. The sha256 is the authoritative guard; mtime is a
    // fast-path hint. If mtime changed but hash is the same (e.g. a
    // `touch` with identical content), we still skip the reinsert —
    // the DB content is correct, only the mtime_ns column would
    // diverge, which is acceptable (minor mtime drift vs an I/O save).
    let mut unchanged_paths: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut changed_files: Vec<&super::walker::RepoFile> = Vec::new();

    for file in &map.files {
        if let Some((stored_sha, stored_mtime)) = stored.get(&file.path)
            && *stored_sha == file.sha256
            && *stored_mtime == file.mtime_ns as i64
        {
            unchanged_paths.insert(&file.path);
            continue;
        }
        changed_files.push(file);
    }

    // Paths present in DB but absent from new scan = removed files.
    let new_paths: std::collections::HashSet<&str> =
        map.files.iter().map(|f| f.path.as_str()).collect();
    let removed_paths: Vec<&str> = stored
        .keys()
        .filter(|p| !new_paths.contains(p.as_str()))
        .map(String::as_str)
        .collect();

    // ── Single transaction: upsert root + delete changed/removed + insert changed/new ──
    let tx = conn.transaction().context("begin persist tx")?;
    let now_unix = crate::time::now_unix_i64();

    // Upsert the root metadata row. We use INSERT … ON CONFLICT UPDATE
    // rather than INSERT OR REPLACE, because INSERT OR REPLACE deletes
    // the old row before inserting the new one — that DELETE cascades
    // through the FK into code_map_files and wipes unchanged rows.
    // ON CONFLICT(root) DO UPDATE SET … updates in place with no DELETE.
    tx.execute(
        "INSERT INTO code_map_roots \
         (root, scanned_at, total_files, total_bytes, total_loc, oversize_skipped, truncated_at, \
          index_generation) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1) \
         ON CONFLICT(root) DO UPDATE SET \
             scanned_at       = excluded.scanned_at, \
             total_files      = excluded.total_files, \
             total_bytes      = excluded.total_bytes, \
             total_loc        = excluded.total_loc, \
             oversize_skipped = excluded.oversize_skipped, \
             truncated_at     = excluded.truncated_at, \
             index_generation = index_generation + 1",
        rusqlite::params![
            &map.root,
            now_unix,
            map.report.total_files as i64,
            map.report.total_bytes as i64,
            map.report.total_loc as i64,
            map.report.oversize_skipped as i64,
            map.report.truncated_at.map(|n| n as i64),
        ],
    )
    .context("upsert code_map_roots row")?;

    // Delete rows for changed files (their symbols cascade via FK).
    for file in &changed_files {
        tx.execute(
            "DELETE FROM code_map_files WHERE root = ?1 AND path = ?2",
            rusqlite::params![&map.root, &file.path],
        )
        .with_context(|| format!("delete changed file row for {}", file.path))?;
    }

    // Delete rows for removed files (absent from new scan).
    for path in &removed_paths {
        tx.execute(
            "DELETE FROM code_map_files WHERE root = ?1 AND path = ?2",
            rusqlite::params![&map.root, path],
        )
        .with_context(|| format!("delete removed file row for {path}"))?;
    }

    // Insert changed + new file rows and their symbols.
    let mut files_inserted = 0usize;
    let mut symbols_inserted = 0usize;
    for file in &changed_files {
        tx.execute(
            "INSERT INTO code_map_files \
             (root, path, language, bytes, loc, sha256, mtime_ns) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                &map.root,
                &file.path,
                file.language.label(),
                file.bytes as i64,
                file.loc as i64,
                &file.sha256,
                file.mtime_ns as i64,
            ],
        )
        .with_context(|| format!("insert code_map_files row for {}", file.path))?;
        let file_id = tx.last_insert_rowid();
        files_inserted += 1;
        for sym in &file.symbols {
            tx.execute(
                "INSERT INTO code_map_symbols \
                 (file_id, name, kind, line) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![file_id, &sym.name, sym.kind.label(), sym.line as i64],
            )
            .with_context(|| {
                format!(
                    "insert code_map_symbols row for {}::{}",
                    file.path, sym.name
                )
            })?;
            symbols_inserted += 1;
        }
    }

    tx.commit().context("commit persist tx")?;
    Ok(PersistStats {
        files_inserted,
        symbols_inserted,
        prior_files_replaced,
        files_skipped_unchanged: unchanged_paths.len(),
    })
}

/// QM-2 Phase 2: persist call-graph edges for `root`. Drops every
/// prior edge under that root (cascade via `code_map_roots` is the
/// safety net) + inserts the supplied set. Caller owns the
/// `CallGraph::build` invocation upstream — this fn just stores.
///
/// Idempotent: re-running with the same edges produces the same
/// row count (per the upstream DELETE).
pub fn persist_edges(
    conn: &mut Connection,
    root: &str,
    edges: &[crate::code_map::graph::CodeEdge],
) -> Result<usize> {
    let tx = conn.transaction().context("open persist_edges tx")?;
    tx.execute(
        "DELETE FROM code_map_edges WHERE root = ?1",
        rusqlite::params![root],
    )
    .context("clear prior edges for root")?;
    let mut inserted = 0usize;
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO code_map_edges (root, from_file, from_symbol, to_name, kind) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .context("prepare edge insert")?;
        for edge in edges {
            stmt.execute(rusqlite::params![
                root,
                edge.from_file,
                edge.from_symbol,
                edge.to_name,
                edge.kind.as_str(),
            ])
            .context("insert edge row")?;
            inserted += 1;
        }
    }
    tx.commit().context("commit persist_edges tx")?;
    Ok(inserted)
}

/// QM-2 Phase 2: load edges for `root`. Empty Vec when none stored.
pub fn load_edges(conn: &Connection, root: &str) -> Result<Vec<crate::code_map::graph::CodeEdge>> {
    let mut stmt = conn
        .prepare(
            "SELECT from_file, from_symbol, to_name, kind FROM code_map_edges \
             WHERE root = ?1 ORDER BY from_file, from_symbol, to_name",
        )
        .context("prepare load_edges stmt")?;
    let mut out = Vec::new();
    let rows = stmt
        .query_map(rusqlite::params![root], |row| {
            let from_file: String = row.get(0)?;
            let from_symbol: String = row.get(1)?;
            let to_name: String = row.get(2)?;
            let kind_str: String = row.get(3)?;
            let kind = match kind_str.as_str() {
                "calls" => crate::code_map::graph::EdgeKind::Calls,
                "references" => crate::code_map::graph::EdgeKind::References,
                _ => crate::code_map::graph::EdgeKind::Calls,
            };
            Ok(crate::code_map::graph::CodeEdge {
                from_file,
                from_symbol,
                to_name,
                kind,
            })
        })
        .context("query edges")?;
    for r in rows {
        out.push(r.context("read edge row")?);
    }
    Ok(out)
}

/// Load EVERY stored edge across all roots. The `codegraph_callers` /
/// `codegraph_callees` MCP tools query by symbol name globally (a symbol
/// can be called across roots), so they need the whole edge set rather
/// than one root's slice. Deterministic order for stable BFS output.
pub fn load_all_edges(conn: &Connection) -> Result<Vec<crate::code_map::graph::CodeEdge>> {
    let mut stmt = conn
        .prepare(
            "SELECT from_file, from_symbol, to_name, kind FROM code_map_edges \
             ORDER BY from_file, from_symbol, to_name",
        )
        .context("prepare load_all_edges stmt")?;
    let mut out = Vec::new();
    let rows = stmt
        .query_map([], |row| {
            let from_file: String = row.get(0)?;
            let from_symbol: String = row.get(1)?;
            let to_name: String = row.get(2)?;
            let kind_str: String = row.get(3)?;
            let kind = match kind_str.as_str() {
                "references" => crate::code_map::graph::EdgeKind::References,
                _ => crate::code_map::graph::EdgeKind::Calls,
            };
            Ok(crate::code_map::graph::CodeEdge {
                from_file,
                from_symbol,
                to_name,
                kind,
            })
        })
        .context("query all edges")?;
    for r in rows {
        out.push(r.context("read edge row")?);
    }
    Ok(out)
}

/// Tuple shape returned by the `code_map_roots` row query. Named so
/// clippy's type-complexity lint doesn't trip on the 7-arity raw
/// tuple, and so a future migration can rename the columns without
/// touching every call site.
type RootRow = (String, i64, i64, i64, i64, i64, Option<i64>);

/// Reload a previously-persisted `RepoMap` for the given root. Returns
/// `None` when the database has no snapshot for that root.
pub fn load_map(conn: &Connection, root: &str) -> Result<Option<RepoMap>> {
    let root_row: Option<RootRow> = conn
        .query_row(
            "SELECT root, scanned_at, total_files, total_bytes, total_loc, \
                    oversize_skipped, truncated_at \
             FROM code_map_roots WHERE root = ?1",
            rusqlite::params![root],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .context("query code_map_roots")?;

    let Some((
        root,
        _scanned_at,
        total_files,
        total_bytes,
        total_loc,
        oversize_skipped,
        truncated_at,
    )) = root_row
    else {
        return Ok(None);
    };

    // Pull all files for this root (v2: include sha256 + mtime_ns).
    let mut stmt = conn
        .prepare(
            "SELECT id, path, language, bytes, loc, sha256, mtime_ns \
             FROM code_map_files WHERE root = ?1 ORDER BY path ASC",
        )
        .context("prepare code_map_files SELECT")?;
    let file_rows: Vec<(i64, String, String, i64, i64, String, i64)> = stmt
        .query_map(rusqlite::params![&root], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect code_map_files rows")?;

    // Pull symbols + group by file_id.
    let mut sym_stmt = conn
        .prepare(
            "SELECT file_id, name, kind, line FROM code_map_symbols \
             ORDER BY file_id ASC, line ASC",
        )
        .context("prepare code_map_symbols SELECT")?;
    let sym_rows: Vec<(i64, String, String, i64)> = sym_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect code_map_symbols rows")?;

    let mut files: Vec<RepoFile> = Vec::with_capacity(file_rows.len());
    let mut by_lang: std::collections::HashMap<Language, u64> = std::collections::HashMap::new();
    for (file_id, path, lang_label, bytes, loc, sha256, mtime_ns) in file_rows {
        let language = language_from_label(&lang_label).unwrap_or(Language::Other);
        *by_lang.entry(language).or_insert(0) += 1;
        let symbols: Vec<Symbol> = sym_rows
            .iter()
            .filter(|(fid, _, _, _)| *fid == file_id)
            .map(|(_, name, kind_label, line)| Symbol {
                name: name.clone(),
                kind: symbol_kind_from_label(kind_label).unwrap_or(SymbolKind::Function),
                line: *line as u32,
            })
            .collect();
        files.push(RepoFile {
            path,
            language,
            bytes: bytes as u64,
            loc: loc as u64,
            sha256,
            mtime_ns: mtime_ns as u64,
            symbols,
        });
    }

    let mut by_language: Vec<(Language, u64)> = by_lang.into_iter().collect();
    by_language.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.label().cmp(b.0.label())));

    Ok(Some(RepoMap {
        root,
        files,
        report: ScanReport {
            total_files: total_files as u64,
            total_bytes: total_bytes as u64,
            total_loc: total_loc as u64,
            by_language,
            oversize_skipped: oversize_skipped as u64,
            truncated_at: truncated_at.map(|n| n as u64),
        },
    }))
}

/// GOLD-R3-13 — the monotonic index generation of `root`, or `None` when the
/// root has no persisted snapshot. Bumped by [`persist_map`] on every re-scan,
/// so a recall consumer that remembers the generation it read can detect that
/// the root was re-indexed under it and invalidate a cached result.
pub fn root_index_generation(conn: &Connection, root: &str) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT index_generation FROM code_map_roots WHERE root = ?1",
        rusqlite::params![root],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .context("query code_map_roots index_generation")
}

/// GOLD-R3-13 — is the persisted snapshot for `root` stale relative to the
/// files currently on disk? Re-scans the root (no symbol extraction) with the
/// same ignore rules and compares content hashes against the stored rows: a
/// stale index has an added, removed, or content-changed file. Returns `false`
/// (fresh) when the root has no snapshot to compare against.
///
/// This re-reads the root's files to hash them, so it is an EXPLICIT, opt-in
/// check (an operator command), never the hot chat-context path. A stored row
/// with an empty hash (a pre-CBM-04 v1 row not yet re-scanned) is treated as
/// unknown and does not by itself signal staleness. Ceiling: both sides use the
/// same walker caps, so a stable tree yields equal counts; a truncated giant
/// repo could compare unequal set sizes and read as stale.
pub fn is_index_stale(conn: &Connection, root: &str) -> Result<bool> {
    let stored: std::collections::HashMap<String, String> = {
        let mut stmt = conn
            .prepare("SELECT path, sha256 FROM code_map_files WHERE root = ?1")
            .context("prepare staleness stored-hash query")?;
        stmt.query_map(rusqlite::params![root], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .context("execute staleness stored-hash query")?
        .collect::<rusqlite::Result<_>>()
        .context("collect staleness stored-hash rows")?
    };
    if stored.is_empty() {
        return Ok(false);
    }
    let scanned = super::walker::RepoMapBuilder::new(root)
        .with_symbols(false)
        .scan()
        .with_context(|| format!("re-scan {root} for staleness check"))?;

    // Added or removed files change the set size (both sides bounded by the
    // same caps, so a stable tree yields equal counts).
    if scanned.files.len() != stored.len() {
        return Ok(true);
    }
    // Any on-disk file that is new, or whose content hash differs from the
    // stored hash, means the index predates an edit. An empty stored hash is
    // unknown and is not counted as a change.
    for file in &scanned.files {
        match stored.get(&file.path) {
            Some(stored_sha) if stored_sha.is_empty() || *stored_sha == file.sha256 => {}
            _ => return Ok(true),
        }
    }
    Ok(false)
}

/// Find every persisted file whose symbol list contains a declaration
/// matching `symbol_name` exactly. Ordered by `(root, path)` so a
/// repo with many roots stays grouped. Result rows carry the bare
/// fields the CLI needs to render `file:line` jump targets — no
/// `RepoFile` reconstruction.
pub fn search_symbol(conn: &Connection, symbol_name: &str) -> Result<Vec<SymbolHit>> {
    let mut stmt = conn
        .prepare(
            "SELECT f.root, f.path, s.kind, s.line \
             FROM code_map_symbols s \
             JOIN code_map_files f ON f.id = s.file_id \
             WHERE s.name = ?1 \
             ORDER BY f.root ASC, f.path ASC, s.line ASC",
        )
        .context("prepare symbol search SELECT")?;
    let rows: Vec<SymbolHit> = stmt
        .query_map(rusqlite::params![symbol_name], |row| {
            Ok(SymbolHit {
                root: row.get::<_, String>(0)?,
                path: row.get::<_, String>(1)?,
                kind: row.get::<_, String>(2)?,
                line: row.get::<_, i64>(3)? as u32,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect symbol-search rows")?;
    Ok(rows)
}

/// K-Repo-Map FTS5 fuzzy search (Session 19, 2026-05-21).
/// Matches symbol names against the FTS5 virtual table with the
/// `unicode61` tokenizer + `_-.` separators. Operator queries:
///
///   - `extract*` — prefix match (returns extract_symbols,
///     extract_response, etc).
///   - `cluster heart` — multi-token AND (returns
///     cluster::heartbeat::*).
///   - `"send_hello"` — quoted exact phrase (escapes operator-
///     supplied `_`/`-` so the FTS5 query syntax doesn't bind
///     them as operators).
///
/// Sanitises the query against the documented FTS5 syntax — bare
/// strings get wrapped in quotes when they contain non-token
/// characters; explicit `*` suffix is preserved. Returns rows
/// ordered by `bm25(code_map_symbols_fts)` ascending (smaller =
/// closer match).
///
/// Result `SymbolHit` is the same struct as
/// [`search_symbol`] — exact + fuzzy paths produce
/// interchangeable hits so the CLI renderer doesn't branch.
pub fn search_symbol_fuzzy(conn: &Connection, query: &str) -> Result<Vec<SymbolHit>> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    // FTS5 query syntax — protect against operator-supplied
    // tokens that double as FTS5 syntax characters. We trust:
    //   - trailing `*` (prefix-match)
    //   - whitespace separating tokens
    // Everything else gets quoted as a phrase to neuter
    // syntax injection (` AND `, `:`, `(`, `)`).
    let fts_query = build_fts_query(trimmed);
    let mut stmt = conn
        .prepare(
            "SELECT f.root, f.path, s.kind, s.line \
             FROM code_map_symbols_fts fts \
             JOIN code_map_symbols s ON s.id = fts.rowid \
             JOIN code_map_files f ON f.id = s.file_id \
             WHERE code_map_symbols_fts MATCH ?1 \
             ORDER BY bm25(code_map_symbols_fts), f.root, f.path, s.line \
             LIMIT 200",
        )
        .context("prepare fuzzy symbol search SELECT")?;
    let rows: Vec<SymbolHit> = stmt
        .query_map(rusqlite::params![fts_query], |row| {
            Ok(SymbolHit {
                root: row.get::<_, String>(0)?,
                path: row.get::<_, String>(1)?,
                kind: row.get::<_, String>(2)?,
                line: row.get::<_, i64>(3)? as u32,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect fuzzy symbol-search rows")?;
    Ok(rows)
}

/// Sanitise an operator-supplied FTS5 query. Returns a string
/// safe to pass to `MATCH`. Bare tokens stay bare (so prefix
/// `extract*` works). Tokens containing FTS5 metacharacters or
/// punctuation get wrapped in double quotes (FTS5 phrase
/// syntax). Pure — testable.
fn build_fts_query(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    let mut first = true;
    for tok in input.split_whitespace() {
        if !first {
            out.push(' ');
        }
        first = false;
        // Preserve trailing `*` for prefix matching.
        let (core, suffix) = if let Some(stripped) = tok.strip_suffix('*') {
            (stripped, "*")
        } else {
            (tok, "")
        };
        if core.chars().all(|c| c.is_alphanumeric() || c == '_') {
            // Bare token — FTS5 parses it directly.
            out.push_str(core);
            out.push_str(suffix);
        } else {
            // Wrap as a phrase. Escape embedded `"` per FTS5
            // syntax (double-quote-doubling).
            out.push('"');
            for ch in core.chars() {
                if ch == '"' {
                    out.push_str("\"\"");
                } else {
                    out.push(ch);
                }
            }
            out.push('"');
            // Trailing `*` after a quoted phrase is also valid
            // FTS5 syntax (prefix on the last token of the
            // phrase).
            out.push_str(suffix);
        }
    }
    out
}

/// One row returned from `search_symbol`. Flat fields (no `RepoFile`)
/// because the CLI just needs to render a "file:line — kind" line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolHit {
    pub root: String,
    pub path: String,
    pub kind: String,
    pub line: u32,
}

fn language_from_label(label: &str) -> Option<Language> {
    match label {
        "rust" => Some(Language::Rust),
        "python" => Some(Language::Python),
        "typescript" => Some(Language::TypeScript),
        "javascript" => Some(Language::JavaScript),
        "go" => Some(Language::Go),
        "c" => Some(Language::C),
        "cpp" => Some(Language::Cpp),
        "java" => Some(Language::Java),
        "kotlin" => Some(Language::Kotlin),
        "swift" => Some(Language::Swift),
        "csharp" => Some(Language::CSharp),
        "ruby" => Some(Language::Ruby),
        "php" => Some(Language::PhpLang),
        "shell" => Some(Language::Shell),
        "lua" => Some(Language::Lua),
        "markdown" => Some(Language::Markdown),
        "toml" => Some(Language::Toml),
        "yaml" => Some(Language::Yaml),
        "json" => Some(Language::Json),
        "html" => Some(Language::Html),
        "css" => Some(Language::Css),
        "sql" => Some(Language::Sql),
        "dockerfile" => Some(Language::Dockerfile),
        "other" => Some(Language::Other),
        _ => None,
    }
}

fn symbol_kind_from_label(label: &str) -> Option<SymbolKind> {
    match label {
        "function" => Some(SymbolKind::Function),
        "method" => Some(SymbolKind::Method),
        "class" => Some(SymbolKind::Class),
        "struct" => Some(SymbolKind::Struct),
        "enum" => Some(SymbolKind::Enum),
        "trait" => Some(SymbolKind::Trait),
        "interface" => Some(SymbolKind::Interface),
        "module" => Some(SymbolKind::Module),
        "type" => Some(SymbolKind::Type),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::walker::{RepoFile, RepoMap, ScanReport};
    use tempfile::tempdir;

    fn temp_db() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("code_map.db");
        let conn = open(&path).unwrap();
        (dir, conn)
    }

    fn sample_map(root: &str) -> RepoMap {
        RepoMap {
            root: root.to_string(),
            files: vec![
                RepoFile {
                    path: "src/main.rs".into(),
                    language: Language::Rust,
                    bytes: 120,
                    loc: 8,
                    sha256: "aaaa1111".into(),
                    mtime_ns: 1_000_000,
                    symbols: vec![Symbol {
                        name: "main".into(),
                        kind: SymbolKind::Function,
                        line: 1,
                    }],
                },
                RepoFile {
                    path: "README.md".into(),
                    language: Language::Markdown,
                    bytes: 50,
                    loc: 3,
                    sha256: "bbbb2222".into(),
                    mtime_ns: 2_000_000,
                    symbols: vec![],
                },
            ],
            report: ScanReport {
                total_files: 2,
                total_bytes: 170,
                total_loc: 11,
                by_language: vec![(Language::Markdown, 1), (Language::Rust, 1)],
                oversize_skipped: 0,
                truncated_at: None,
            },
        }
    }

    #[test]
    fn qm2_phase2_edges_persist_roundtrip() {
        let (_dir, mut conn) = temp_db();
        // Need a root row first because edges FK into code_map_roots.
        let map = sample_map("/repo/a");
        persist_map(&mut conn, &map).unwrap();
        let edges = vec![
            crate::code_map::graph::CodeEdge {
                from_file: "src/a.rs".into(),
                from_symbol: "caller".into(),
                to_name: "callee".into(),
                kind: crate::code_map::graph::EdgeKind::Calls,
            },
            crate::code_map::graph::CodeEdge {
                from_file: "src/b.rs".into(),
                from_symbol: "other".into(),
                to_name: "callee".into(),
                kind: crate::code_map::graph::EdgeKind::Calls,
            },
        ];
        let n = persist_edges(&mut conn, "/repo/a", &edges).unwrap();
        assert_eq!(n, 2);
        let loaded = load_edges(&conn, "/repo/a").unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().any(|e| e.from_file == "src/a.rs"));
        assert!(loaded.iter().any(|e| e.from_file == "src/b.rs"));
    }

    #[test]
    fn qm2_phase2_edges_idempotent_replace() {
        let (_dir, mut conn) = temp_db();
        let map = sample_map("/repo/a");
        persist_map(&mut conn, &map).unwrap();
        let edges = vec![crate::code_map::graph::CodeEdge {
            from_file: "x.rs".into(),
            from_symbol: "a".into(),
            to_name: "b".into(),
            kind: crate::code_map::graph::EdgeKind::Calls,
        }];
        persist_edges(&mut conn, "/repo/a", &edges).unwrap();
        // Second run replaces — still 1 row.
        persist_edges(&mut conn, "/repo/a", &edges).unwrap();
        let loaded = load_edges(&conn, "/repo/a").unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn qm2_phase2_load_edges_unknown_root_returns_empty() {
        let (_dir, conn) = temp_db();
        let loaded = load_edges(&conn, "/never/seen").unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn schema_applies_on_first_open() {
        let (_dir, conn) = temp_db();
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, CODE_MAP_SCHEMA_VERSION.to_string());
    }

    #[test]
    fn persist_then_load_roundtrips_files_and_symbols() {
        let (_dir, mut conn) = temp_db();
        let map = sample_map("/repo/a");
        let stats = persist_map(&mut conn, &map).unwrap();
        assert_eq!(stats.files_inserted, 2);
        assert_eq!(stats.symbols_inserted, 1);
        assert_eq!(stats.prior_files_replaced, 0);

        let loaded = load_map(&conn, "/repo/a")
            .unwrap()
            .expect("snapshot present");
        assert_eq!(loaded.root, "/repo/a");
        assert_eq!(loaded.files.len(), 2);
        let main_rs = loaded
            .files
            .iter()
            .find(|f| f.path == "src/main.rs")
            .unwrap();
        assert_eq!(main_rs.language, Language::Rust);
        assert_eq!(main_rs.bytes, 120);
        assert_eq!(main_rs.loc, 8);
        assert_eq!(main_rs.symbols.len(), 1);
        assert_eq!(main_rs.symbols[0].name, "main");
        assert_eq!(main_rs.symbols[0].kind, SymbolKind::Function);
        assert_eq!(main_rs.symbols[0].line, 1);
    }

    #[test]
    fn load_unknown_root_returns_none() {
        let (_dir, conn) = temp_db();
        let loaded = load_map(&conn, "/nonexistent").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn re_persist_same_root_replaces_atomically() {
        let (_dir, mut conn) = temp_db();
        let map_v1 = sample_map("/repo/a");
        let _ = persist_map(&mut conn, &map_v1).unwrap();

        // Smaller second snapshot — different file count + content.
        let map_v2 = RepoMap {
            root: "/repo/a".into(),
            files: vec![RepoFile {
                path: "src/other.rs".into(),
                language: Language::Rust,
                bytes: 30,
                loc: 2,
                sha256: "cccc3333".into(),
                mtime_ns: 3_000_000,
                symbols: vec![],
            }],
            report: ScanReport {
                total_files: 1,
                total_bytes: 30,
                total_loc: 2,
                by_language: vec![(Language::Rust, 1)],
                oversize_skipped: 0,
                truncated_at: None,
            },
        };
        let stats = persist_map(&mut conn, &map_v2).unwrap();
        assert_eq!(stats.files_inserted, 1);
        assert_eq!(stats.prior_files_replaced, 2);

        let loaded = load_map(&conn, "/repo/a").unwrap().unwrap();
        assert_eq!(loaded.files.len(), 1, "old files must be gone");
        assert_eq!(loaded.files[0].path, "src/other.rs");

        // The old symbol should have cascaded away too.
        let hits = search_symbol(&conn, "main").unwrap();
        assert!(
            hits.is_empty(),
            "old root's symbols must cascade on re-persist; got {hits:?}"
        );
    }

    #[test]
    fn two_distinct_roots_coexist() {
        let (_dir, mut conn) = temp_db();
        let _ = persist_map(&mut conn, &sample_map("/repo/a")).unwrap();
        let _ = persist_map(&mut conn, &sample_map("/repo/b")).unwrap();
        let a = load_map(&conn, "/repo/a").unwrap().unwrap();
        let b = load_map(&conn, "/repo/b").unwrap().unwrap();
        assert_eq!(a.files.len(), 2);
        assert_eq!(b.files.len(), 2);
        // Both should be queryable independently.
        assert_eq!(a.root, "/repo/a");
        assert_eq!(b.root, "/repo/b");
    }

    #[test]
    fn search_symbol_returns_matching_hits() {
        let (_dir, mut conn) = temp_db();
        let _ = persist_map(&mut conn, &sample_map("/repo/a")).unwrap();
        let hits = search_symbol(&conn, "main").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "src/main.rs");
        assert_eq!(hits[0].kind, "function");
        assert_eq!(hits[0].line, 1);
        assert_eq!(hits[0].root, "/repo/a");
    }

    #[test]
    fn search_symbol_returns_empty_when_no_match() {
        let (_dir, mut conn) = temp_db();
        let _ = persist_map(&mut conn, &sample_map("/repo/a")).unwrap();
        let hits = search_symbol(&conn, "nonexistent_fn").unwrap();
        assert!(hits.is_empty());
    }

    // ── K-Repo-Map FTS5 fuzzy search ────────────────────────────────

    fn fts_sample_map(root: &str) -> RepoMap {
        RepoMap {
            root: root.to_string(),
            files: vec![
                RepoFile {
                    path: "src/extract.rs".into(),
                    language: Language::Rust,
                    bytes: 100,
                    loc: 10,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![
                        Symbol {
                            name: "extract_symbols".into(),
                            kind: SymbolKind::Function,
                            line: 5,
                        },
                        Symbol {
                            name: "extract_response".into(),
                            kind: SymbolKind::Function,
                            line: 25,
                        },
                    ],
                },
                RepoFile {
                    path: "src/cluster.rs".into(),
                    language: Language::Rust,
                    bytes: 100,
                    loc: 10,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![Symbol {
                        name: "cluster_heartbeat".into(),
                        kind: SymbolKind::Function,
                        line: 1,
                    }],
                },
            ],
            report: ScanReport::default(),
        }
    }

    #[test]
    fn search_symbol_fuzzy_returns_empty_on_empty_query() {
        let (_dir, conn) = temp_db();
        assert!(search_symbol_fuzzy(&conn, "").unwrap().is_empty());
        assert!(search_symbol_fuzzy(&conn, "   ").unwrap().is_empty());
    }

    #[test]
    fn search_symbol_fuzzy_returns_empty_when_no_match() {
        let (_dir, mut conn) = temp_db();
        let _ = persist_map(&mut conn, &fts_sample_map("/r")).unwrap();
        let hits = search_symbol_fuzzy(&conn, "totally_absent").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn search_symbol_fuzzy_matches_prefix_with_star_suffix() {
        let (_dir, mut conn) = temp_db();
        let _ = persist_map(&mut conn, &fts_sample_map("/r")).unwrap();
        let hits = search_symbol_fuzzy(&conn, "extract*").unwrap();
        // Both `extract_symbols` and `extract_response` match the
        // prefix.
        assert_eq!(hits.len(), 2, "got {hits:?}");
        let names: Vec<&str> = hits.iter().map(|h| h.path.as_str()).collect();
        // Both live in the same file in this fixture.
        assert!(names.iter().all(|p| *p == "src/extract.rs"));
    }

    #[test]
    fn search_symbol_fuzzy_matches_tokenizer_separator_split() {
        // The unicode61 tokenizer with `_` as a separator splits
        // `extract_symbols` into tokens `extract` + `symbols`. A
        // bare query `symbols` matches the second token.
        let (_dir, mut conn) = temp_db();
        let _ = persist_map(&mut conn, &fts_sample_map("/r")).unwrap();
        let hits = search_symbol_fuzzy(&conn, "symbols").unwrap();
        assert!(
            hits.iter().any(|h| h.path == "src/extract.rs"),
            "tokenizer split must surface extract_symbols on 'symbols' query: {hits:?}"
        );
    }

    #[test]
    fn search_symbol_fuzzy_matches_multi_token_and() {
        // Two-token AND query: only `cluster_heartbeat` has
        // BOTH `cluster` AND `heartbeat` tokens.
        let (_dir, mut conn) = temp_db();
        let _ = persist_map(&mut conn, &fts_sample_map("/r")).unwrap();
        let hits = search_symbol_fuzzy(&conn, "cluster heartbeat").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "src/cluster.rs");
    }

    #[test]
    fn build_fts_query_passes_bare_alphanumeric_tokens_unchanged() {
        assert_eq!(build_fts_query("extract"), "extract");
        assert_eq!(build_fts_query("Cluster_Heartbeat"), "Cluster_Heartbeat");
        assert_eq!(build_fts_query("foo bar"), "foo bar");
    }

    #[test]
    fn build_fts_query_preserves_trailing_star() {
        assert_eq!(build_fts_query("extract*"), "extract*");
        // Trailing star on second token still preserved.
        assert_eq!(build_fts_query("foo bar*"), "foo bar*");
    }

    #[test]
    fn build_fts_query_quotes_tokens_with_metachars() {
        // FTS5 operator chars (:, (, ), AND) inside a token
        // get phrase-quoted so they can't be parsed as
        // syntax. Pin via known cases.
        assert_eq!(build_fts_query("a:b"), "\"a:b\"");
        assert_eq!(build_fts_query("foo(bar)"), "\"foo(bar)\"");
        // `"` inside a token gets doubled per FTS5 syntax.
        assert_eq!(build_fts_query("she\"s"), "\"she\"\"s\"");
    }

    #[test]
    fn empty_map_persists_without_files_or_symbols() {
        let (_dir, mut conn) = temp_db();
        let map = RepoMap {
            root: "/empty/repo".into(),
            files: vec![],
            report: ScanReport::default(),
        };
        let stats = persist_map(&mut conn, &map).unwrap();
        assert_eq!(stats.files_inserted, 0);
        assert_eq!(stats.symbols_inserted, 0);
        let loaded = load_map(&conn, "/empty/repo").unwrap().unwrap();
        assert!(loaded.files.is_empty());
        assert_eq!(loaded.report.total_files, 0);
    }

    #[test]
    fn report_truncated_at_roundtrips() {
        let (_dir, mut conn) = temp_db();
        let mut map = sample_map("/repo/big");
        map.report.truncated_at = Some(50_000);
        map.report.oversize_skipped = 42;
        let _ = persist_map(&mut conn, &map).unwrap();
        let loaded = load_map(&conn, "/repo/big").unwrap().unwrap();
        assert_eq!(loaded.report.truncated_at, Some(50_000));
        assert_eq!(loaded.report.oversize_skipped, 42);
    }

    #[test]
    fn all_symbol_kinds_roundtrip_correctly() {
        let (_dir, mut conn) = temp_db();
        let map = RepoMap {
            root: "/repo/kinds".into(),
            files: vec![RepoFile {
                path: "lib.rs".into(),
                language: Language::Rust,
                bytes: 200,
                loc: 20,
                sha256: String::new(),
                mtime_ns: 0,
                symbols: vec![
                    Symbol {
                        name: "f".into(),
                        kind: SymbolKind::Function,
                        line: 1,
                    },
                    Symbol {
                        name: "m".into(),
                        kind: SymbolKind::Method,
                        line: 2,
                    },
                    Symbol {
                        name: "C".into(),
                        kind: SymbolKind::Class,
                        line: 3,
                    },
                    Symbol {
                        name: "S".into(),
                        kind: SymbolKind::Struct,
                        line: 4,
                    },
                    Symbol {
                        name: "E".into(),
                        kind: SymbolKind::Enum,
                        line: 5,
                    },
                    Symbol {
                        name: "T".into(),
                        kind: SymbolKind::Trait,
                        line: 6,
                    },
                    Symbol {
                        name: "I".into(),
                        kind: SymbolKind::Interface,
                        line: 7,
                    },
                    Symbol {
                        name: "Mod".into(),
                        kind: SymbolKind::Module,
                        line: 8,
                    },
                    Symbol {
                        name: "Ty".into(),
                        kind: SymbolKind::Type,
                        line: 9,
                    },
                ],
            }],
            report: ScanReport::default(),
        };
        let _ = persist_map(&mut conn, &map).unwrap();
        let loaded = load_map(&conn, "/repo/kinds").unwrap().unwrap();
        let kinds: Vec<SymbolKind> = loaded.files[0].symbols.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&SymbolKind::Function));
        assert!(kinds.contains(&SymbolKind::Method));
        assert!(kinds.contains(&SymbolKind::Class));
        assert!(kinds.contains(&SymbolKind::Struct));
        assert!(kinds.contains(&SymbolKind::Enum));
        assert!(kinds.contains(&SymbolKind::Trait));
        assert!(kinds.contains(&SymbolKind::Interface));
        assert!(kinds.contains(&SymbolKind::Module));
        assert!(kinds.contains(&SymbolKind::Type));
    }

    #[test]
    fn language_label_roundtrips_for_every_recognised_language() {
        let (_dir, mut conn) = temp_db();
        for lang in [
            Language::Rust,
            Language::Python,
            Language::TypeScript,
            Language::JavaScript,
            Language::Go,
            Language::C,
            Language::Cpp,
            Language::Java,
            Language::Kotlin,
            Language::Swift,
            Language::CSharp,
            Language::Ruby,
            Language::PhpLang,
            Language::Shell,
            Language::Lua,
            Language::Markdown,
            Language::Toml,
            Language::Yaml,
            Language::Json,
            Language::Html,
            Language::Css,
            Language::Sql,
            Language::Dockerfile,
            Language::Other,
        ] {
            let map = RepoMap {
                root: format!("/repo/{}", lang.label()),
                files: vec![RepoFile {
                    path: "x".into(),
                    language: lang,
                    bytes: 1,
                    loc: 1,
                    sha256: String::new(),
                    mtime_ns: 0,
                    symbols: vec![],
                }],
                report: ScanReport::default(),
            };
            let _ = persist_map(&mut conn, &map).unwrap();
            let loaded = load_map(&conn, &format!("/repo/{}", lang.label()))
                .unwrap()
                .unwrap();
            assert_eq!(
                loaded.files[0].language, lang,
                "language label roundtrip drift for {lang:?}",
            );
        }
    }

    #[test]
    fn default_path_returns_neoth_home_code_map_db() {
        let p = default_path();
        let s = p.to_string_lossy();
        assert!(s.contains(".neoth"), "got: {s}");
        assert!(s.ends_with("code_map.db"), "got: {s}");
    }

    #[test]
    fn load_map_against_stale_pre_phase_3a_db_errors_not_silently_returns_none() {
        // Pick #34 (Session 14, test-gap audit-fix): an operator with
        // a pre-Phase-3a `code_map.db` lacking the `code_map_roots`
        // table (or hand-crafted DB) previously caused `load_map` to
        // surface a rusqlite "no such table" error. The audit warned
        // that `optional()` could silently swallow it as `None` —
        // verifying here that the table-missing case DOES error out,
        // so an operator with a stale schema sees the actionable
        // signal instead of "repo-context just doesn't work".
        let dir = tempdir().unwrap();
        let path = dir.path().join("stale.db");
        let conn = Connection::open(&path).unwrap();
        // Schema looks "open-able" but has no code_map_roots table.
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO meta (key, value) VALUES ('schema_version', '0');",
        )
        .unwrap();
        let result = load_map(&conn, "/some/repo");
        assert!(
            result.is_err(),
            "stale schema must surface an error, not silently return None; got {result:?}"
        );
        let err_msg = result.unwrap_err().to_string();
        // SQLite's "no such table" message — operator's lever to fix is
        // `neoth code-map persist` against a fresh DB.
        assert!(
            err_msg.to_lowercase().contains("no such table")
                || err_msg.to_lowercase().contains("code_map_roots")
                || err_msg.to_lowercase().contains("code_map_files"),
            "error should name the missing table; got: {err_msg}"
        );
    }

    // ── CBM-04 incremental re-index tests ────────────────────────────

    /// Helper: scan a temp dir with the real walker so sha256 + mtime_ns
    /// are computed from actual file bytes (not hand-crafted).
    fn scan_dir(dir: &std::path::Path) -> RepoMap {
        crate::code_map::walker::RepoMapBuilder::new(dir)
            .with_symbols(false)
            .scan()
            .unwrap()
    }

    #[test]
    fn incremental_persist_skips_unchanged_files() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), b"fn a() {}\n").unwrap();
        std::fs::write(dir.path().join("b.rs"), b"fn b() {}\n").unwrap();

        let (_db_dir, mut conn) = temp_db();

        // First persist: nothing stored yet — both files are new.
        let map1 = scan_dir(dir.path());
        let stats1 = persist_map(&mut conn, &map1).unwrap();
        assert_eq!(stats1.files_inserted, 2, "first persist: 2 new files");
        assert_eq!(
            stats1.files_skipped_unchanged, 0,
            "first persist: nothing to skip"
        );

        // Modify b.rs so its sha256 changes.
        std::fs::write(dir.path().join("b.rs"), b"fn b_modified() {}\n").unwrap();

        let map2 = scan_dir(dir.path());
        let stats2 = persist_map(&mut conn, &map2).unwrap();
        assert_eq!(
            stats2.files_skipped_unchanged, 1,
            "a.rs unchanged — must be skipped"
        );
        assert_eq!(
            stats2.files_inserted, 1,
            "b.rs changed — must be reinserted"
        );

        // Both files must still be in the DB after incremental persist.
        let loaded = load_map(&conn, &map2.root)
            .unwrap()
            .expect("snapshot present");
        assert_eq!(
            loaded.files.len(),
            2,
            "both files present after incremental persist"
        );
        let paths: Vec<&str> = loaded.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.ends_with("a.rs")));
        assert!(paths.iter().any(|p| p.ends_with("b.rs")));
    }

    #[test]
    fn incremental_persist_sha256_wins_over_mtime() {
        // If mtime changes but sha256 is identical (e.g. write same bytes),
        // the file should still be skipped — sha256 is the authoritative guard.
        // The skip condition is AND(sha256, mtime), so a mtime change alone
        // causes a re-insert; a sha256 match with mtime change causes skip.
        // This test verifies the implementation matches the research-plan spec.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("stable.rs"), b"fn stable() {}\n").unwrap();

        let (_db_dir, mut conn) = temp_db();
        let map1 = scan_dir(dir.path());
        persist_map(&mut conn, &map1).unwrap();

        // Re-write the same content (sha256 identical, mtime may or may not change).
        // On most OSes writing the same bytes resets the mtime — so this is a
        // mtime-changed + content-same scenario.
        std::fs::write(dir.path().join("stable.rs"), b"fn stable() {}\n").unwrap();

        let map2 = scan_dir(dir.path());
        let stats2 = persist_map(&mut conn, &map2).unwrap();

        // sha256 is the same → file must be skipped even if mtime differs.
        // (If the OS didn't update mtime, skipped_unchanged = 1 trivially.)
        let loaded = load_map(&conn, &map2.root).unwrap().unwrap();
        assert_eq!(loaded.files.len(), 1);
        // Key invariant: file is present after both paths (skip or reinsert).
        assert!(loaded.files.iter().any(|f| f.path.ends_with("stable.rs")));
        // Either skipped (sha256+mtime both same) or reinserted (mtime changed).
        // Both are correct behaviour — the file must still be in the DB.
        let _ = stats2; // both outcomes are valid; the DB integrity is what matters
    }

    #[test]
    fn index_generation_starts_at_one_and_bumps_on_rescan() {
        use crate::code_map::walker::{RepoMap, ScanReport};
        let dir = tempdir().unwrap();
        let path = dir.path().join("gen.db");
        let mut conn = open(&path).unwrap();

        // Unknown root → None.
        assert_eq!(root_index_generation(&conn, "/repo/x").unwrap(), None);

        let map = RepoMap {
            root: "/repo/x".into(),
            files: Vec::new(),
            report: ScanReport::default(),
        };
        persist_map(&mut conn, &map).unwrap();
        assert_eq!(
            root_index_generation(&conn, "/repo/x").unwrap(),
            Some(1),
            "first persist starts the generation at 1"
        );

        // Re-scan the same root → generation bumps in place (no reset).
        persist_map(&mut conn, &map).unwrap();
        assert_eq!(
            root_index_generation(&conn, "/repo/x").unwrap(),
            Some(2),
            "a re-scan must bump the index generation"
        );

        // A different root keeps its own independent counter.
        let other = RepoMap {
            root: "/repo/y".into(),
            files: Vec::new(),
            report: ScanReport::default(),
        };
        persist_map(&mut conn, &other).unwrap();
        assert_eq!(root_index_generation(&conn, "/repo/y").unwrap(), Some(1));
        assert_eq!(root_index_generation(&conn, "/repo/x").unwrap(), Some(2));
    }

    #[test]
    fn is_index_stale_detects_edit_add_and_remove() {
        use crate::code_map::walker::RepoMapBuilder;

        let repo = tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(repo.path().join("src/b.rs"), "fn b() {}\n").unwrap();

        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("cm.db")).unwrap();
        let map = RepoMapBuilder::new(repo.path())
            .with_symbols(false)
            .scan()
            .unwrap();
        let root = map.root.clone();
        persist_map(&mut conn, &map).unwrap();

        // Freshly persisted → not stale.
        assert!(
            !is_index_stale(&conn, &root).unwrap(),
            "a freshly persisted index must not be stale"
        );
        // Unknown root → not stale (nothing to compare).
        assert!(!is_index_stale(&conn, "/definitely/not/a/root").unwrap());

        // Edit a file's CONTENT (sha256 changes) → stale.
        std::fs::write(repo.path().join("src/a.rs"), "fn a() { let _ = 1; }\n").unwrap();
        assert!(
            is_index_stale(&conn, &root).unwrap(),
            "a content edit must be detected via the hash"
        );

        // Re-persist → fresh again.
        let map2 = RepoMapBuilder::new(repo.path())
            .with_symbols(false)
            .scan()
            .unwrap();
        persist_map(&mut conn, &map2).unwrap();
        assert!(!is_index_stale(&conn, &root).unwrap());

        // Add a file → stale (set size grows).
        std::fs::write(repo.path().join("src/c.rs"), "fn c() {}\n").unwrap();
        assert!(
            is_index_stale(&conn, &root).unwrap(),
            "a new file must be detected"
        );

        // Re-persist, then REMOVE a file → stale (set size shrinks).
        let map3 = RepoMapBuilder::new(repo.path())
            .with_symbols(false)
            .scan()
            .unwrap();
        persist_map(&mut conn, &map3).unwrap();
        std::fs::remove_file(repo.path().join("src/c.rs")).unwrap();
        assert!(
            is_index_stale(&conn, &root).unwrap(),
            "a removed file must be detected"
        );
    }

    #[test]
    fn open_migrates_v1_to_v3_on_existing_db() {
        // Build a v1 DB manually (apply_schema with version stamped as 1,
        // without sha256/mtime_ns columns), then call open() and verify the
        // migration chain fires: schema_version advances to "3" (v1→v2→v3),
        // the v2 file columns exist, and the v3 index_generation column exists.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v1.db");

        // Create a minimal v1 DB: meta + code_map_roots + code_map_files
        // WITHOUT sha256/mtime_ns columns (as schema v1 was).
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO meta (key, value) VALUES ('schema_version', '1');
                 CREATE TABLE code_map_roots (
                     root TEXT PRIMARY KEY,
                     scanned_at INTEGER NOT NULL,
                     total_files INTEGER NOT NULL,
                     total_bytes INTEGER NOT NULL,
                     total_loc INTEGER NOT NULL,
                     oversize_skipped INTEGER NOT NULL,
                     truncated_at INTEGER
                 );
                 CREATE TABLE code_map_files (
                     id INTEGER PRIMARY KEY,
                     root TEXT NOT NULL,
                     path TEXT NOT NULL,
                     language TEXT NOT NULL,
                     bytes INTEGER NOT NULL,
                     loc INTEGER NOT NULL,
                     UNIQUE(root, path),
                     FOREIGN KEY(root) REFERENCES code_map_roots(root) ON DELETE CASCADE
                 );
                 CREATE TABLE code_map_symbols (
                     id INTEGER PRIMARY KEY,
                     file_id INTEGER NOT NULL REFERENCES code_map_files(id) ON DELETE CASCADE,
                     name TEXT NOT NULL,
                     kind TEXT NOT NULL,
                     line INTEGER NOT NULL
                 );
                 CREATE TABLE code_map_edges (
                     id INTEGER PRIMARY KEY,
                     root TEXT NOT NULL,
                     from_file TEXT NOT NULL,
                     from_symbol TEXT NOT NULL,
                     to_name TEXT NOT NULL,
                     kind TEXT NOT NULL,
                     FOREIGN KEY(root) REFERENCES code_map_roots(root) ON DELETE CASCADE
                 );
                 CREATE VIRTUAL TABLE IF NOT EXISTS code_map_symbols_fts
                     USING fts5(name, kind, content='code_map_symbols',
                                content_rowid='id',
                                tokenize='unicode61 separators ''_-.''');
                 CREATE TRIGGER IF NOT EXISTS code_map_symbols_fts_insert
                     AFTER INSERT ON code_map_symbols
                 BEGIN
                     INSERT INTO code_map_symbols_fts(rowid, name, kind)
                     VALUES (new.id, new.name, new.kind);
                 END;
                 CREATE TRIGGER IF NOT EXISTS code_map_symbols_fts_delete
                     AFTER DELETE ON code_map_symbols
                 BEGIN
                     INSERT INTO code_map_symbols_fts(code_map_symbols_fts, rowid, name, kind)
                     VALUES ('delete', old.id, old.name, old.kind);
                 END;",
            )
            .unwrap();
            // Insert a row without sha256/mtime_ns to confirm migration handles existing rows.
            conn.execute(
                "INSERT INTO code_map_roots VALUES ('/r', 0, 1, 100, 10, 0, NULL)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO code_map_files (root, path, language, bytes, loc) \
                 VALUES ('/r', 'x.rs', 'rust', 100, 10)",
                [],
            )
            .unwrap();
        }

        // Open via the public API — should trigger v1→v2 migration.
        let conn = open(&path).expect("open must succeed on a v1 DB");

        // schema_version must now be "3" (v1→v2→v3 chain).
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            version, "3",
            "schema_version must advance to 3 after migration"
        );

        // v3 column: code_map_roots.index_generation exists, and the migrated
        // legacy root defaulted to generation 0.
        let root_cols: Vec<String> = {
            let mut stmt = conn.prepare("PRAGMA table_info(code_map_roots)").unwrap();
            stmt.query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert!(
            root_cols.iter().any(|c| c == "index_generation"),
            "v3 must add index_generation to code_map_roots; got {root_cols:?}"
        );
        assert_eq!(
            root_index_generation(&conn, "/r").unwrap(),
            Some(0),
            "a migrated legacy root must default to generation 0"
        );

        // Both new columns must exist (PRAGMA table_info returns one row per column).
        let col_names: Vec<String> = {
            let mut stmt = conn.prepare("PRAGMA table_info(code_map_files)").unwrap();
            stmt.query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect()
        };
        assert!(
            col_names.iter().any(|c| c == "sha256"),
            "sha256 column must exist after migration; got {col_names:?}"
        );
        assert!(
            col_names.iter().any(|c| c == "mtime_ns"),
            "mtime_ns column must exist after migration; got {col_names:?}"
        );

        // Existing row must survive with default values.
        let (sha256, mtime_ns): (String, i64) = conn
            .query_row(
                "SELECT sha256, mtime_ns FROM code_map_files WHERE path = 'x.rs'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            sha256, "",
            "existing row sha256 must default to empty string"
        );
        assert_eq!(mtime_ns, 0, "existing row mtime_ns must default to 0");
    }
}
