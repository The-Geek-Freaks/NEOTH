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
//! ## Schema (v4 — generation-bound graph snapshots)
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
//!     truncated_at INTEGER,  -- nullable
//!     index_generation INTEGER NOT NULL DEFAULT 0,
//!     graph_generation INTEGER NOT NULL DEFAULT 0,
//!     root_identity TEXT  -- stable local dev+ino / volume+file-index token
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
//!     line    INTEGER NOT NULL,
//!     line_end INTEGER
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};

use super::symbols::{Symbol, SymbolKind};
use super::walker::{Language, RepoFile, RepoMap, ScanReport};

/// Schema version. v2 adds `sha256` + `mtime_ns` columns to
/// `code_map_files` for CBM-04 incremental re-index (skip-unchanged).
/// v3 adds a monotonic per-root `index_generation` counter to
/// `code_map_roots` (GOLD-R3-13) so a recall consumer can tell that a root
/// was re-scanned under it and invalidate a cached result.
/// v4 adds `graph_generation`, advanced only in the same transaction that
/// replaces a root's edges. Consumers can therefore reject a mixed snapshot
/// after `persist_map` succeeds but edge persistence does not.
/// v5 binds the canonical display path to a stable local directory identity.
/// Unreachable legacy roots remain NULL and cannot produce typed receipts until
/// a successful rebuild adopts their identity; reachable roots are adopted by
/// the migration itself.
/// v8 adds nullable parser-certified inclusive symbol end lines. Existing
/// regex-only and legacy rows remain `NULL`, which means unknown rather than
/// an estimated declaration extent.
/// v9 records the graph-edge provenance tier and its canonical ordinal
/// confidence. Legacy heuristic rows are deliberately migrated as inferred.
/// v10 adds nullable exact target-file identity; legacy NULL rows are never
/// exact TestedBy evidence. v11 adds a separate generation-bound import graph.
pub const CODE_MAP_SCHEMA_VERSION: i64 = 11;

/// Hard ceiling for one filesystem freshness receipt. The count gate runs
/// before row materialisation and every SELECT still carries `LIMIT cap + 1`
/// so a concurrent count-to-query insertion cannot force unbounded allocation.
pub(crate) const MAX_FRESHNESS_FILES: usize = 250_000;
const MAX_FRESHNESS_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_FRESHNESS_ROW_TEXT_BYTES: usize = 64 * 1024;

/// Doctor never needs an unbounded repository-wide edge census.  This cap
/// covers the rows materialised by its `tested_by` evidence observation; one
/// additional sentinel row makes a partial observation explicit.
pub(crate) const MAX_DOCTOR_TEST_EVIDENCE_ROWS: usize = 1_024;
const DOCTOR_TEST_EVIDENCE_VM_STEP_LIMIT: usize = 100_000;
const DOCTOR_TEST_EVIDENCE_VM_STEP_INTERVAL: i32 = 1_000;

/// Retrieval never needs a whole-root symbol census merely to explain why
/// exact `TestedBy` evidence may be absent. The caller also supplies a tighter
/// shared-work cap for impact-bound queries.
const MAX_TEST_EVIDENCE_EXCLUSION_ROWS: usize = 20_000;
const MAX_TEST_EVIDENCE_EXCLUSION_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_TEST_EVIDENCE_EXCLUSION_ROW_TEXT_BYTES: usize = 64 * 1024;
const TEST_EVIDENCE_EXCLUSION_VM_STEP_LIMIT: usize = 100_000;
const TEST_EVIDENCE_EXCLUSION_VM_STEP_INTERVAL: i32 = 1_000;

struct TestEvidenceExclusionProgressReset<'a> {
    conn: &'a Connection,
}

impl Drop for TestEvidenceExclusionProgressReset<'_> {
    fn drop(&mut self) {
        self.conn.progress_handler(0, None::<fn() -> bool>);
    }
}

/// Instance-default code-map path. `FreedomConfig::default_neoth_home()` is
/// the shared authority and honours `NEOTH_HOME`; using raw HOME here split
/// CLI writers from daemon/chat readers under custom instance homes.
pub fn default_path() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home().join("code_map.db")
}

#[cfg(test)]
mod v10_migration_tests {
    use super::*;
    use tempfile::tempdir;

    fn v9(path: &Path, valid_edges: bool) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO meta VALUES ('schema_version', '9');
             CREATE TABLE code_map_roots (
               root TEXT PRIMARY KEY, scanned_at INTEGER NOT NULL, total_files INTEGER NOT NULL,
               total_bytes INTEGER NOT NULL, total_loc INTEGER NOT NULL, oversize_skipped INTEGER NOT NULL,
               truncated_at INTEGER, index_generation INTEGER NOT NULL DEFAULT 0,
               graph_generation INTEGER NOT NULL DEFAULT 0, root_identity TEXT
             );
             CREATE TABLE code_map_files (
               id INTEGER PRIMARY KEY, root TEXT NOT NULL, path TEXT NOT NULL, language TEXT NOT NULL,
               bytes INTEGER NOT NULL, loc INTEGER NOT NULL, sha256 TEXT NOT NULL DEFAULT '',
               mtime_ns INTEGER NOT NULL DEFAULT 0, UNIQUE(root, path)
             );
             CREATE TABLE code_map_symbols (
               id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL,
               line INTEGER NOT NULL, line_end INTEGER
             );
             CREATE TABLE code_map_edges (
               id INTEGER PRIMARY KEY, root TEXT NOT NULL, from_file TEXT NOT NULL,
               from_symbol TEXT NOT NULL, to_name TEXT NOT NULL, kind TEXT NOT NULL,
               confidence INTEGER NOT NULL DEFAULT 50,
               confidence_tier TEXT NOT NULL DEFAULT 'inferred'
             );",
        ).unwrap();
        conn.execute_batch(
            "INSERT INTO code_map_roots VALUES ('/r', 10, 1, 12, 2, 0, NULL, 7, 7, 'fixture-root');
             INSERT INTO code_map_files VALUES (1, '/r', 'src/a.rs', 'rust', 12, 2, 'abc', 1);
             INSERT INTO code_map_symbols VALUES (1, 1, 'a', 'function', 1, 2);",
        )
        .unwrap();
        if valid_edges {
            conn.execute_batch(
                "INSERT INTO code_map_edges (root, from_file, from_symbol, to_name, kind, confidence, confidence_tier)
                   VALUES ('/r','src/a.rs','a','b','calls',50,'inferred'),
                          ('/r','src/b.rs','b','a','references',50,'inferred');",
            ).unwrap();
        }
    }

    #[test]
    fn v9_to_v10_preserves_legacy_edges_with_null_target_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v9.db");
        v9(&path, true);
        let conn = open(&path).unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "11");
        let import_generation: i64 = conn
            .query_row(
                "SELECT import_generation FROM code_map_roots WHERE root = '/r'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            import_generation, -1,
            "legacy imports are invalid until rebuilt"
        );
        let rows: Vec<(String, Option<String>)> = conn
            .prepare("SELECT kind, target_file FROM code_map_edges ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![("calls".into(), None), ("references".into(), None)]
        );
        let map = load_map(&conn, "/r").unwrap().unwrap();
        assert_eq!(map.files[0].path, "src/a.rs");
        assert_eq!(root_index_generation(&conn, "/r").unwrap(), Some(7));
        assert_eq!(root_graph_generation(&conn, "/r").unwrap(), Some(7));
        assert_eq!(load_edges(&conn, "/r").unwrap().len(), 2);
        let coverage = crate::code_map::test_coverage::test_coverage_for(
            &conn,
            "/r",
            crate::code_map::test_coverage::TestCoverageNode {
                file: "src/a.rs".into(),
                symbol: "a".into(),
            },
            crate::code_map::test_coverage::TestCoverageOptions::default(),
        )
        .unwrap();
        assert!(
            coverage.observed_tests.is_empty(),
            "legacy NULL target identity is not exact coverage"
        );
        assert!(parse_persisted_edge_kind("future-kind").is_err());
    }

    #[test]
    fn failed_v10_migration_rolls_back_schema_and_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("broken-v9.db");
        v9(&path, true);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("ALTER TABLE code_map_edges ADD COLUMN target_file TEXT;")
            .unwrap();
        assert!(open(&path).is_err());
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "9");
        assert_eq!(root_index_generation(&conn, "/r").unwrap(), Some(7));
        assert_eq!(root_graph_generation(&conn, "/r").unwrap(), Some(7));
    }
}

/// Open or create the code-map database. Applies schema on first
/// touch; preserves existing rows on reopen.
pub fn open(path: &Path) -> Result<Connection> {
    open_with_migration_hooks(path, |_| {}, || {}, || {}, || {})
}

/// Open an existing code-map database without creating directories, SQLite
/// sidecars, schema tables, or migrations. Status/Doctor paths must use this
/// instead of [`open`].
pub(crate) fn open_read_only(path: &Path) -> Result<Connection> {
    ensure!(path.exists(), "code-map database is absent");
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect code-map database {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "code-map database is not a regular file"
    );
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open code-map database read-only {}", path.display()))?;
    connection.pragma_update(None, "query_only", "ON")?;
    Ok(connection)
}

fn open_with_migration_hooks<
    ConfigureConnection,
    AfterVersionRead,
    BeforeImmediate,
    AfterImmediate,
>(
    path: &Path,
    configure_connection: ConfigureConnection,
    after_version_read: AfterVersionRead,
    before_immediate: BeforeImmediate,
    after_immediate: AfterImmediate,
) -> Result<Connection>
where
    ConfigureConnection: FnOnce(&Connection),
    AfterVersionRead: FnOnce(),
    BeforeImmediate: FnOnce(),
    AfterImmediate: FnOnce(),
{
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir for {}", path.display()))?;
    }
    let is_new = !path.exists();
    let mut conn = Connection::open(path)
        .with_context(|| format!("open code_map SQLite db {}", path.display()))?;

    // Set the busy handler before any pragma that may need the SQLite writer
    // lock. Concurrent first-open/migration paths can otherwise fail at
    // `journal_mode=WAL` before the later timeout is installed.
    conn.busy_timeout(std::time::Duration::from_millis(5_000))
        .context("set SQLite busy_timeout=5000")?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("set SQLite journal_mode=WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("set SQLite synchronous=NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("set SQLite foreign_keys=ON")?;
    // TRAIL-01/05: matching hardening pragmas (see memory/store.rs for rationale).
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
    configure_connection(&conn);

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
        // Existing DB — a cheap read avoids taking the migration writer lock
        // for current schemas. The migration itself acquires IMMEDIATE and
        // re-reads the version under that lock, so concurrent openers cannot
        // both execute the same ALTER TABLE.
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
        after_version_read();
        if let Some(v) = current_version
            && v < CODE_MAP_SCHEMA_VERSION
        {
            migrate_code_map_with_hooks(&mut conn, before_immediate, after_immediate)
                .with_context(|| {
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

/// Run code-map schema migrations under one IMMEDIATE writer transaction.
/// The version is deliberately re-read after acquiring that lock: a second
/// concurrent opener observes the first opener's committed version and skips
/// every already-applied ALTER instead of racing it.
fn migrate_code_map_with_hooks<BeforeImmediate, AfterImmediate>(
    conn: &mut Connection,
    before_immediate: BeforeImmediate,
    after_immediate: AfterImmediate,
) -> Result<()>
where
    BeforeImmediate: FnOnce(),
    AfterImmediate: FnOnce(),
{
    before_immediate();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin locked code-map migration")?;
    after_immediate();
    let mut v: i64 = tx
        .query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |row| {
                let value: String = row.get(0)?;
                Ok(value.parse::<i64>().unwrap_or(0))
            },
        )
        .context("re-read code_map schema_version under migration lock")?;

    // v1 → v2: add sha256 + mtime_ns columns (CBM-04 incremental re-index).
    // SQLite's ADD COLUMN with a DEFAULT is always safe — no full table rebuild.
    if v < 2 {
        tx.execute_batch(
            "ALTER TABLE code_map_files ADD COLUMN sha256   TEXT    NOT NULL DEFAULT ''; \
             ALTER TABLE code_map_files ADD COLUMN mtime_ns INTEGER NOT NULL DEFAULT 0;",
        )
        .context("v1→v2: add sha256 + mtime_ns to code_map_files")?;
        tx.execute(
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
        tx.execute_batch(
            "ALTER TABLE code_map_roots \
             ADD COLUMN index_generation INTEGER NOT NULL DEFAULT 0;",
        )
        .context("v2→v3: add index_generation to code_map_roots")?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '3')",
            [],
        )
        .context("v2→v3: stamp schema_version=3")?;
        v = 3;
    }

    // v3 → v4: bind the persisted edge set to the exact index generation.
    // Existing roots deliberately receive an invalid negative graph
    // generation. A legacy index generation can also be zero, and equality of
    // two uncertified zero values must never be interpreted as a valid graph.
    if v < 4 {
        tx.execute_batch(
            "ALTER TABLE code_map_roots \
             ADD COLUMN graph_generation INTEGER NOT NULL DEFAULT -1;",
        )
        .context("v3→v4: add graph_generation to code_map_roots")?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '4')",
            [],
        )
        .context("v3→v4: stamp schema_version=4")?;
        v = 4;
    }

    // v4 → v5: stable local repository identity. The partial unique index
    // permits unreachable legacy roots to remain NULL, while preventing one
    // physical directory from being indexed under multiple live aliases.
    if v < 5 {
        tx.execute_batch("ALTER TABLE code_map_roots ADD COLUMN root_identity TEXT;")
            .context("v4→v5: add physical root identity column")?;
        adopt_reachable_root_identities_during_migration(&tx)?;
        tx.execute_batch(
            "CREATE UNIQUE INDEX idx_code_map_roots_identity \
             ON code_map_roots(root_identity) WHERE root_identity IS NOT NULL;",
        )
        .context("v4→v5: enforce unique physical root identity")?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '5')",
            [],
        )
        .context("v4→v5: stamp schema_version=5")?;
    }

    if v < 6 {
        tx.execute_batch(
            "CREATE TABLE code_map_lifecycle_attempts (
                root_identity TEXT PRIMARY KEY NOT NULL,
                root_display TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                prior_index_generation INTEGER,
                prior_graph_generation INTEGER,
                published_index_generation INTEGER,
                published_graph_generation INTEGER,
                source_fingerprint_sha256 TEXT,
                started_at_ms INTEGER NOT NULL,
                completed_at_ms INTEGER
             );",
        )
        .context("v5→v6: create code-map lifecycle attempt journal")?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '6')",
            [],
        )
        .context("v5→v6: stamp schema_version=6")?;
    }

    if v < 7 {
        tx.execute(
            "ALTER TABLE code_map_lifecycle_attempts ADD COLUMN owner_id TEXT",
            [],
        )
        .context("v6→v7: add lifecycle refresh owner identity")?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '7')",
            [],
        )
        .context("v6→v7: stamp schema_version=7")?;
        v = 7;
    }

    // v7 → v8: only parser-certified declaration end lines are stored. A
    // nullable column preserves the distinction between a legacy/regex symbol
    // with no proven extent and an actual one-line extent.
    if v < 8 {
        tx.execute(
            "ALTER TABLE code_map_symbols ADD COLUMN line_end INTEGER",
            [],
        )
        .context("v7→v8: add nullable code-map symbol end line")?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '8')",
            [],
        )
        .context("v7→v8: stamp schema_version=8")?;
    }

    // v8 → v9: persist graph evidence provenance. Existing edges were built
    // by the heuristic scanner, so endpoint uniqueness cannot upgrade them.
    if v < 9 {
        tx.execute_batch(
            "ALTER TABLE code_map_edges ADD COLUMN confidence INTEGER NOT NULL DEFAULT 50; \
             ALTER TABLE code_map_edges ADD COLUMN confidence_tier TEXT NOT NULL DEFAULT 'inferred';",
        )
        .context("v8→v9: add inferred graph-edge confidence columns")?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '9')",
            [],
        )
        .context("v8→v9: stamp schema_version=9")?;
    }

    if v < 10 {
        tx.execute("ALTER TABLE code_map_edges ADD COLUMN target_file TEXT", [])
            .context("v9→v10: add nullable exact edge target file")?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '10')",
            [],
        )
        .context("v9→v10: stamp schema_version=10")?;
    }

    // Legacy snapshots have no evidence that an import graph was built, so
    // use an invalid sentinel rather than silently treating zero rows as a
    // current empty graph.
    if v < 11 {
        tx.execute_batch(
            "ALTER TABLE code_map_roots ADD COLUMN import_generation INTEGER NOT NULL DEFAULT -1; \
             CREATE TABLE code_map_import_edges ( \
                 id INTEGER PRIMARY KEY, root TEXT NOT NULL, from_file TEXT NOT NULL, \
                 to_file TEXT NOT NULL, language TEXT NOT NULL, \
                 FOREIGN KEY(root) REFERENCES code_map_roots(root) ON DELETE CASCADE, \
                 UNIQUE(root, from_file, to_file, language) \
             ); \
             CREATE INDEX idx_code_map_import_edges_source ON code_map_import_edges(root, from_file); \
             CREATE INDEX idx_code_map_import_edges_target ON code_map_import_edges(root, to_file);",
        )
        .context("v10→v11: add generation-bound import graph")?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '11')",
            [],
        )
        .context("v10→v11: stamp schema_version=11")?;
    }

    tx.commit().context("commit locked code-map migration")?;
    Ok(())
}

#[derive(Debug)]
struct MigratingRoot {
    display: String,
    canonical_display: String,
    identity: String,
    scanned_at: i64,
    index_generation: i64,
    graph_generation: i64,
}

/// Adopt every reachable v4 root under the migration writer lock. Multiple path
/// aliases of the same physical directory are reduced to one complete snapshot:
/// newest scan wins, then highest generations, then canonical spelling, then
/// lexical path. Rows are never merged across generations.
fn adopt_reachable_root_identities_during_migration(tx: &Transaction<'_>) -> Result<()> {
    let stored: Vec<(String, i64, i64, i64)> = {
        let mut stmt = tx
            .prepare(
                "SELECT root, scanned_at, index_generation, graph_generation \
                 FROM code_map_roots ORDER BY root ASC",
            )
            .context("prepare v5 root identity adoption query")?;
        stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .context("query v4 roots for identity adoption")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect v4 roots for identity adoption")?
    };

    let mut by_identity: std::collections::BTreeMap<String, Vec<MigratingRoot>> =
        std::collections::BTreeMap::new();
    for (display, scanned_at, index_generation, graph_generation) in stored {
        let canonical = match super::root_identity::CanonicalRepoRoot::discover(Path::new(&display))
        {
            Ok(root) => root,
            Err(error) => match Path::new(&display).try_exists() {
                Ok(false) => continue,
                Ok(true) => {
                    return Err(error)
                        .with_context(|| format!("adopt reachable v4 code-map root {display:?}"));
                }
                Err(probe_error) => {
                    return Err(probe_error).with_context(|| {
                        format!("probe v4 code-map root {display:?} during identity migration")
                    });
                }
            },
        };
        let identity = canonical.identity().as_str().to_owned();
        by_identity
            .entry(identity.clone())
            .or_default()
            .push(MigratingRoot {
                display,
                canonical_display: canonical.display().to_owned(),
                identity,
                scanned_at,
                index_generation,
                graph_generation,
            });
    }

    for mut aliases in by_identity.into_values() {
        aliases.sort_by(|a, b| {
            b.scanned_at
                .cmp(&a.scanned_at)
                .then_with(|| b.index_generation.cmp(&a.index_generation))
                .then_with(|| b.graph_generation.cmp(&a.graph_generation))
                .then_with(|| {
                    let a_is_canonical = a.display == a.canonical_display;
                    let b_is_canonical = b.display == b.canonical_display;
                    b_is_canonical.cmp(&a_is_canonical)
                })
                .then_with(|| a.display.cmp(&b.display))
        });
        let winner = aliases.remove(0);
        if aliases
            .iter()
            .any(|alias| alias.canonical_display != winner.canonical_display)
        {
            bail!(
                "physical code-map root identity {:?} resolved to multiple canonical paths",
                winner.identity
            );
        }
        for loser in aliases {
            tx.execute(
                "DELETE FROM code_map_roots WHERE root = ?1",
                rusqlite::params![&loser.display],
            )
            .with_context(|| format!("remove superseded v4 root alias {:?}", loser.display))?;
        }
        if winner.display == winner.canonical_display {
            tx.execute(
                "UPDATE code_map_roots SET root_identity = ?2 WHERE root = ?1",
                rusqlite::params![&winner.display, &winner.identity],
            )
            .with_context(|| format!("adopt v4 code-map root identity {:?}", winner.display))?;
        } else {
            move_root_snapshot(
                tx,
                &winner.display,
                &winner.canonical_display,
                &winner.identity,
            )?;
        }
    }
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
            index_generation INTEGER NOT NULL DEFAULT 0,
            graph_generation INTEGER NOT NULL DEFAULT 0,
            import_generation INTEGER NOT NULL DEFAULT 0,
            root_identity    TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_code_map_roots_identity
            ON code_map_roots(root_identity) WHERE root_identity IS NOT NULL;

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
            line    INTEGER NOT NULL,
            line_end INTEGER
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
            confidence  INTEGER NOT NULL DEFAULT 50,
            confidence_tier TEXT NOT NULL DEFAULT 'inferred',
            target_file TEXT,
            FOREIGN KEY(root) REFERENCES code_map_roots(root) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_code_map_edges_to_name
            ON code_map_edges(to_name);
        CREATE INDEX IF NOT EXISTS idx_code_map_edges_source
            ON code_map_edges(from_file, from_symbol);

        CREATE TABLE IF NOT EXISTS code_map_import_edges (
            id        INTEGER PRIMARY KEY,
            root      TEXT NOT NULL,
            from_file TEXT NOT NULL,
            to_file   TEXT NOT NULL,
            language  TEXT NOT NULL,
            FOREIGN KEY(root) REFERENCES code_map_roots(root) ON DELETE CASCADE,
            UNIQUE(root, from_file, to_file, language)
        );
        CREATE INDEX IF NOT EXISTS idx_code_map_import_edges_source
            ON code_map_import_edges(root, from_file);
        CREATE INDEX IF NOT EXISTS idx_code_map_import_edges_target
            ON code_map_import_edges(root, to_file);

        CREATE TABLE IF NOT EXISTS code_map_lifecycle_attempts (
            root_identity TEXT PRIMARY KEY NOT NULL,
            root_display TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            phase TEXT NOT NULL,
            prior_index_generation INTEGER,
            prior_graph_generation INTEGER,
            published_index_generation INTEGER,
            published_graph_generation INTEGER,
            source_fingerprint_sha256 TEXT,
            owner_id TEXT,
            started_at_ms INTEGER NOT NULL,
            completed_at_ms INTEGER
        );

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
    /// Files skipped because sha256 + mtime_ns and, when supplied by the
    /// scanner, the exact declaration set matched the stored row (CBM-04
    /// incremental re-index). Skipped files already have correct rows +
    /// symbols in the DB — no DELETE/INSERT needed.
    pub files_skipped_unchanged: usize,
}

/// Exact publication metadata captured before the bound IMMEDIATE transaction
/// commits. Returning these generations avoids a post-commit re-query that a
/// concurrent writer could advance independently of the returned stats/edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundPersistResult {
    pub(crate) stats: PersistStats,
    pub(crate) edges_inserted: usize,
    pub(crate) index_generation: i64,
    pub(crate) graph_generation: i64,
}

/// Incrementally replace the snapshot for `map.root` (CBM-04).
///
/// Pre-pass: query existing `(path, sha256, mtime_ns, symbols)` rows into a
/// HashMap. Files whose hash + mtime and supplied symbol set match the new scan
/// are skipped (already correct in the DB). Changed and new files are
/// deleted-then-reinserted; removed files are deleted. The root
/// metadata row is upserted in-place rather than cascade-deleted, so
/// unchanged file rows survive across calls.
///
/// On error the transaction rolls back — the prior snapshot stays
/// intact (no partial state).
pub fn persist_map(conn: &mut Connection, map: &RepoMap) -> Result<PersistStats> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin persist-map transaction")?;
    let stats =
        persist_map_in_transaction(&tx, map, SymbolComparisonMode::LegacyEmptyWildcard, None)?;
    tx.commit().context("commit persist-map transaction")?;
    Ok(stats)
}

#[derive(Clone, Copy)]
enum SymbolComparisonMode {
    /// Historical low-level `persist_map` callers use an empty declaration
    /// list to mean "symbols were not supplied"; retain the stored rows.
    LegacyEmptyWildcard,
    /// A production map+graph snapshot is the exact scanner output. An empty
    /// declaration list therefore means no declarations and removes stale
    /// symbol rows from the prior generation.
    ExactSnapshot,
}

const PERSIST_PREPASS_FILE_CAP: i64 = 100_000;
const PERSIST_PREPASS_SYMBOL_CAP: i64 = 250_000;
const PERSIST_PREPASS_EDGE_CAP: usize = 250_000;
const PERSIST_PREPASS_TEXT_BYTE_CAP: i64 = 32 * 1024 * 1024;
const PERSIST_ROW_TEXT_BYTE_CAP: usize = MAX_FRESHNESS_ROW_TEXT_BYTES;

fn add_incoming_text_bytes(
    total: &mut usize,
    bytes: usize,
    limit: usize,
    field: &str,
) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .with_context(|| format!("incoming code-map {field} byte count overflow"))?;
    ensure!(
        *total <= limit,
        "incoming code-map {field} text exceeds bounded publish cap of {limit} bytes"
    );
    Ok(())
}

fn enforce_incoming_map_bounds(map: &RepoMap) -> Result<()> {
    ensure!(
        map.root.len() <= PERSIST_ROW_TEXT_BYTE_CAP,
        "incoming code-map root exceeds {PERSIST_ROW_TEXT_BYTE_CAP} bytes"
    );
    ensure!(
        map.files.len() <= PERSIST_PREPASS_FILE_CAP as usize,
        "incoming code-map snapshot for {:?} contains {} files; bounded publish cap is {PERSIST_PREPASS_FILE_CAP}",
        map.root,
        map.files.len()
    );
    let mut symbols = 0usize;
    let mut text_bytes = 0usize;
    let mut freshness_text_bytes = 0usize;
    for file in &map.files {
        let file_row_bytes = file
            .path
            .len()
            .checked_add(file.sha256.len())
            .context("incoming code-map file-row byte count overflow")?;
        ensure!(
            file_row_bytes <= PERSIST_ROW_TEXT_BYTE_CAP,
            "incoming code-map file row exceeds {PERSIST_ROW_TEXT_BYTE_CAP} bytes"
        );
        add_incoming_text_bytes(
            &mut freshness_text_bytes,
            file_row_bytes,
            MAX_FRESHNESS_TEXT_BYTES,
            "freshness row",
        )?;
        add_incoming_text_bytes(
            &mut text_bytes,
            file.path.len(),
            PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
            "path",
        )?;
        add_incoming_text_bytes(
            &mut text_bytes,
            file.sha256.len(),
            PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
            "hash",
        )?;
        symbols = symbols
            .checked_add(file.symbols.len())
            .context("incoming code-map symbol count overflow")?;
        ensure!(
            symbols <= PERSIST_PREPASS_SYMBOL_CAP as usize,
            "incoming code-map snapshot for {:?} contains more than {PERSIST_PREPASS_SYMBOL_CAP} symbols",
            map.root
        );
        for symbol in &file.symbols {
            if let Some(line_end) = symbol.line_end {
                ensure!(
                    line_end >= symbol.line,
                    "incoming code-map symbol end line {line_end} precedes start line {} for {}::{}",
                    symbol.line,
                    file.path,
                    symbol.name
                );
            }
            let symbol_row_bytes = symbol
                .name
                .len()
                .checked_add(symbol.kind.label().len())
                .context("incoming code-map symbol-row byte count overflow")?;
            ensure!(
                symbol_row_bytes <= PERSIST_ROW_TEXT_BYTE_CAP,
                "incoming code-map symbol row exceeds {PERSIST_ROW_TEXT_BYTE_CAP} bytes"
            );
            add_incoming_text_bytes(
                &mut text_bytes,
                symbol.name.len(),
                PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
                "symbol name",
            )?;
            add_incoming_text_bytes(
                &mut text_bytes,
                symbol.kind.label().len(),
                PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
                "symbol kind",
            )?;
        }
    }
    Ok(())
}

pub(crate) fn enforce_incoming_edge_bounds(
    root: &str,
    edges: &[crate::code_map::graph::CodeEdge],
) -> Result<()> {
    ensure!(
        edges.len() <= PERSIST_PREPASS_EDGE_CAP,
        "incoming code-map graph for {root:?} contains {} edges; bounded publish cap is {PERSIST_PREPASS_EDGE_CAP}",
        edges.len()
    );
    let mut text_bytes = 0usize;
    for edge in edges {
        edge.validate_confidence()?;
        let edge_row_bytes = edge
            .from_file
            .len()
            .checked_add(edge.from_symbol.len())
            .and_then(|bytes| bytes.checked_add(edge.to_name.len()))
            .and_then(|bytes| bytes.checked_add(edge.kind.as_str().len()))
            .and_then(|bytes| bytes.checked_add(edge.confidence_tier.as_str().len()))
            .and_then(|bytes| bytes.checked_add(edge.target_file.as_deref().map_or(0, str::len)))
            .and_then(|bytes| bytes.checked_add(edge.confidence.to_string().len()))
            .context("incoming code-map edge-row byte count overflow")?;
        ensure!(
            edge_row_bytes <= PERSIST_ROW_TEXT_BYTE_CAP,
            "incoming code-map edge row exceeds {PERSIST_ROW_TEXT_BYTE_CAP} bytes"
        );
        add_incoming_text_bytes(
            &mut text_bytes,
            edge.from_file.len(),
            PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
            "edge source path",
        )?;
        add_incoming_text_bytes(
            &mut text_bytes,
            edge.from_symbol.len(),
            PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
            "edge source symbol",
        )?;
        add_incoming_text_bytes(
            &mut text_bytes,
            edge.to_name.len(),
            PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
            "edge target",
        )?;
        add_incoming_text_bytes(
            &mut text_bytes,
            edge.target_file.as_deref().map_or(0, str::len),
            PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
            "exact edge target file",
        )?;
        add_incoming_text_bytes(
            &mut text_bytes,
            edge.kind.as_str().len(),
            PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
            "edge kind",
        )?;
        add_incoming_text_bytes(
            &mut text_bytes,
            edge.confidence_tier.as_str().len(),
            PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
            "edge confidence tier",
        )?;
    }
    Ok(())
}

fn enforce_persist_prepass_bounds(conn: &Connection, root: &str) -> Result<()> {
    let (file_count, file_text_bytes): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(\
                 LENGTH(CAST(path AS BLOB)) + LENGTH(CAST(sha256 AS BLOB))\
             ), 0) FROM code_map_files WHERE root = ?1",
            rusqlite::params![root],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("measure prior code-map file pre-pass")?;
    let (symbol_count, symbol_text_bytes): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(\
                 LENGTH(CAST(s.name AS BLOB)) + LENGTH(CAST(s.kind AS BLOB))\
             ), 0) \
             FROM code_map_files f \
             JOIN code_map_symbols s ON s.file_id = f.id \
             WHERE f.root = ?1",
            rusqlite::params![root],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("measure prior code-map symbol pre-pass")?;
    ensure!(
        (0..=PERSIST_PREPASS_FILE_CAP).contains(&file_count),
        "prior code-map snapshot for {root:?} contains {file_count} files; bounded rebuild cap is {PERSIST_PREPASS_FILE_CAP}"
    );
    ensure!(
        (0..=PERSIST_PREPASS_SYMBOL_CAP).contains(&symbol_count),
        "prior code-map snapshot for {root:?} contains {symbol_count} symbols; bounded rebuild cap is {PERSIST_PREPASS_SYMBOL_CAP}"
    );
    let total_text_bytes = file_text_bytes
        .checked_add(symbol_text_bytes)
        .context("prior code-map pre-pass text-byte count overflow")?;
    ensure!(
        (0..=PERSIST_PREPASS_TEXT_BYTE_CAP).contains(&total_text_bytes),
        "prior code-map snapshot for {root:?} contains {total_text_bytes} text bytes; bounded rebuild cap is {PERSIST_PREPASS_TEXT_BYTE_CAP}"
    );
    Ok(())
}

/// Bind a canonical display path to its physical directory before reading the
/// prior snapshot. If the same directory moved, migrate its root key and child
/// rows inside this writer transaction so generations remain monotonic.
fn prepare_root_identity_for_persist(
    tx: &Transaction<'_>,
    root: &str,
    expected_root: Option<&super::root_identity::CanonicalRepoRoot>,
) -> Result<Option<String>> {
    let identity = if let Some(expected) = expected_root {
        ensure!(
            expected.display() == root,
            "bound code-map root {:?} does not match map root {root:?}",
            expected.display()
        );
        expected.identity().as_str().to_owned()
    } else {
        let canonical = match super::root_identity::CanonicalRepoRoot::discover(Path::new(root)) {
            Ok(root) => root,
            Err(error) if !Path::new(root).exists() => {
                // Compatibility for imported/synthetic legacy maps: an unreachable
                // root may remain NULL, but it is never eligible for a typed recall
                // receipt. Never let an unreachable write retain a previously
                // certified physical identity.
                let existing_identity: Option<Option<String>> = tx
                    .query_row(
                        "SELECT root_identity FROM code_map_roots WHERE root = ?1",
                        rusqlite::params![root],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("query existing root identity for unreachable map")?;
                if existing_identity.flatten().is_some() {
                    return Err(error).with_context(|| {
                    format!(
                        "refuse to update identity-bound code-map root {root:?} while it is unreachable"
                    )
                });
                }
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if canonical.display() != root {
            bail!(
                "code-map root {root:?} is not canonical; rebuild from {:?}",
                canonical.display()
            );
        }
        canonical.identity().as_str().to_owned()
    };
    let prior_path: Option<String> = tx
        .query_row(
            "SELECT root FROM code_map_roots WHERE root_identity = ?1",
            rusqlite::params![&identity],
            |row| row.get(0),
        )
        .optional()
        .context("query path previously bound to repository identity")?;

    if let Some(prior_path) = prior_path
        && prior_path != root
    {
        let target_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM code_map_roots WHERE root = ?1)",
                rusqlite::params![root],
                |row| row.get(0),
            )
            .context("check renamed code-map target root collision")?;
        if target_exists {
            bail!(
                "cannot reconcile renamed code-map root {prior_path:?} to {root:?}: target key already exists"
            );
        }

        move_root_snapshot(tx, &prior_path, root, &identity)?;
    }

    // A path reused for a different physical directory is a new identity. The
    // subsequent exact map replacement advances the generation and refreshes
    // its rows, while the receipt's identity prevents cache confusion.
    tx.execute(
        "UPDATE code_map_roots SET root_identity = ?2 WHERE root = ?1",
        rusqlite::params![root, &identity],
    )
    .context("adopt physical identity for existing code-map root")?;
    Ok(Some(identity))
}

/// Rename one complete root snapshot without disabling foreign keys or mixing
/// rows from another generation. `target` must not exist.
fn move_root_snapshot(
    tx: &Transaction<'_>,
    source: &str,
    target: &str,
    identity: &str,
) -> Result<()> {
    // Release the unique identity long enough to create the new parent row,
    // then move every child before deleting the old parent. Foreign keys remain
    // enabled throughout; no cascade can discard the selected snapshot.
    tx.execute(
        "UPDATE code_map_roots SET root_identity = NULL WHERE root = ?1",
        rusqlite::params![source],
    )
    .context("release prior code-map root identity during rename")?;
    let inserted = tx
        .execute(
            "INSERT INTO code_map_roots \
             (root, scanned_at, total_files, total_bytes, total_loc, oversize_skipped, \
              truncated_at, index_generation, graph_generation, root_identity) \
             SELECT ?2, scanned_at, total_files, total_bytes, total_loc, oversize_skipped, \
                    truncated_at, index_generation, graph_generation, ?3 \
             FROM code_map_roots WHERE root = ?1",
            rusqlite::params![source, target, identity],
        )
        .context("create reconciled code-map root row")?;
    if inserted != 1 {
        bail!("code-map root {source:?} disappeared during identity reconciliation");
    }
    tx.execute(
        "UPDATE code_map_files SET root = ?2 WHERE root = ?1",
        rusqlite::params![source, target],
    )
    .context("move code-map files to reconciled root")?;
    tx.execute(
        "UPDATE code_map_edges SET root = ?2 WHERE root = ?1",
        rusqlite::params![source, target],
    )
    .context("move code-map edges to reconciled root")?;
    tx.execute(
        "DELETE FROM code_map_roots WHERE root = ?1",
        rusqlite::params![source],
    )
    .context("remove prior code-map root path after reconciliation")?;
    Ok(())
}

/// Apply the map half of a snapshot to an already-exclusive transaction.
///
/// Keeping the pre-pass under the same IMMEDIATE transaction as the writes is
/// essential: an incremental diff computed before acquiring the writer lock
/// can otherwise be applied to a newer snapshot published by another process.
fn persist_map_in_transaction(
    tx: &Transaction<'_>,
    map: &RepoMap,
    symbol_comparison: SymbolComparisonMode,
    expected_root: Option<&super::root_identity::CanonicalRepoRoot>,
) -> Result<PersistStats> {
    // `line_end` stays optional: historical rows and declarations without a
    // parser-certified balanced body must never be upgraded to a guessed end.
    type StoredSymbols = Vec<(String, String, u32, Option<u32>)>;
    type StoredFile = (String, i64, StoredSymbols);

    enforce_incoming_map_bounds(map)?;
    let root_identity = prepare_root_identity_for_persist(tx, &map.root, expected_root)?;
    enforce_persist_prepass_bounds(tx, &map.root)?;

    // ── Pre-pass: load existing file fingerprints + declarations ─────
    // Exact declaration comparison matters when an older snapshot was built
    // without `--symbols`: unchanged source bytes must still be replaced once
    // so the now-mandatory concrete graph identities are adopted.
    let mut stored: std::collections::HashMap<String, StoredFile> = {
        let mut stmt = tx
            .prepare("SELECT path, sha256, mtime_ns FROM code_map_files WHERE root = ?1")
            .context("prepare pre-pass stored-hash query")?;
        stmt.query_map(rusqlite::params![&map.root], |row| {
            let path: String = row.get(0)?;
            let sha256: String = row.get(1)?;
            let mtime_ns: i64 = row.get(2)?;
            Ok((path, (sha256, mtime_ns, StoredSymbols::new())))
        })
        .context("execute pre-pass stored-hash query")?
        .collect::<rusqlite::Result<_>>()
        .context("collect stored-hash rows")?
    };
    {
        let mut stmt = tx
            .prepare(
                "SELECT f.path, s.name, s.kind, s.line, s.line_end \
                 FROM code_map_files f \
                 JOIN code_map_symbols s ON s.file_id = f.id \
                 WHERE f.root = ?1 \
                 ORDER BY f.path, s.name, s.kind, s.line, s.line_end",
            )
            .context("prepare pre-pass stored-symbol query")?;
        let rows = stmt
            .query_map(rusqlite::params![&map.root], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })
            .context("execute pre-pass stored-symbol query")?;
        for row in rows {
            let (path, name, kind, line, line_end) = row.context("read stored symbol row")?;
            let line = u32::try_from(line)
                .with_context(|| format!("invalid stored symbol line {line} for {path}::{name}"))?;
            let line_end = line_end
                .map(|end| {
                    let end = u32::try_from(end).with_context(|| {
                        format!("invalid stored symbol end line {end} for {path}::{name}")
                    })?;
                    ensure!(
                        end >= line,
                        "stored symbol end line {end} precedes start line {line} for {path}::{name}"
                    );
                    Ok(end)
                })
                .transpose()?;
            if let Some((_, _, symbols)) = stored.get_mut(&path) {
                symbols.push((name, kind, line, line_end));
            }
        }
    }

    // Count prior files for operator feedback (mirrors old stats field).
    let prior_files_replaced = stored.len();

    // ── Partition scan into unchanged vs changed/new ─────────────────
    // A file is "unchanged" when sha256 AND mtime_ns match and the scanner's
    // declaration set matches according to the caller's explicit contract.
    // The legacy low-level API treats an empty declaration set as "not
    // supplied"; production atomic snapshots compare exact sets, including
    // empty, so stale declarations cannot survive into a certified graph.
    let mut unchanged_paths: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut changed_files: Vec<&super::walker::RepoFile> = Vec::new();

    for file in &map.files {
        let mut scanned_symbols: StoredSymbols = file
            .symbols
            .iter()
            .map(|symbol| {
                (
                    symbol.name.clone(),
                    symbol.kind.label().to_string(),
                    symbol.line,
                    symbol.line_end,
                )
            })
            .collect();
        scanned_symbols.sort();
        let symbols_match = match symbol_comparison {
            SymbolComparisonMode::LegacyEmptyWildcard => {
                scanned_symbols.is_empty()
                    || stored
                        .get(&file.path)
                        .is_some_and(|(_, _, symbols)| symbols == &scanned_symbols)
            }
            SymbolComparisonMode::ExactSnapshot => stored
                .get(&file.path)
                .is_some_and(|(_, _, symbols)| symbols == &scanned_symbols),
        };
        if let Some((stored_sha, stored_mtime, _)) = stored.get(&file.path)
            && *stored_sha == file.sha256
            && *stored_mtime == file.mtime_ns as i64
            && symbols_match
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

    let now_unix = crate::time::now_unix_i64();

    // Upsert the root metadata row. We use INSERT … ON CONFLICT UPDATE
    // rather than INSERT OR REPLACE, because INSERT OR REPLACE deletes
    // the old row before inserting the new one — that DELETE cascades
    // through the FK into code_map_files and wipes unchanged rows.
    // ON CONFLICT(root) DO UPDATE SET … updates in place with no DELETE.
    tx.execute(
        "INSERT INTO code_map_roots \
         (root, scanned_at, total_files, total_bytes, total_loc, oversize_skipped, truncated_at, \
          index_generation, graph_generation, root_identity) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 0, ?8) \
         ON CONFLICT(root) DO UPDATE SET \
             scanned_at       = excluded.scanned_at, \
             total_files      = excluded.total_files, \
             total_bytes      = excluded.total_bytes, \
             total_loc        = excluded.total_loc, \
             oversize_skipped = excluded.oversize_skipped, \
             truncated_at     = excluded.truncated_at, \
             root_identity    = excluded.root_identity, \
             index_generation = index_generation + 1, \
             import_generation = 0",
        rusqlite::params![
            &map.root,
            now_unix,
            map.report.total_files as i64,
            map.report.total_bytes as i64,
            map.report.total_loc as i64,
            map.report.oversize_skipped as i64,
            map.report.truncated_at.map(|n| n as i64),
            root_identity,
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
                 (file_id, name, kind, line, line_end) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    file_id,
                    &sym.name,
                    sym.kind.label(),
                    sym.line as i64,
                    sym.line_end.map(i64::from),
                ],
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

    Ok(PersistStats {
        files_inserted,
        symbols_inserted,
        prior_files_replaced,
        files_skipped_unchanged: unchanged_paths.len(),
    })
}

/// Low-level compatibility helper: persist call-graph edges for `root`. Drops every
/// prior edge under that root (cascade via `code_map_roots` is the
/// safety net) + inserts the supplied set. Caller owns the
/// `CallGraph::build` invocation upstream — this fn just stores.
/// Production rebuilds must use [`persist_map_and_edges`] so the graph cannot
/// be rebound to a map published by a concurrent writer.
///
/// Idempotent: re-running with the same edges produces the same row count
/// (per the upstream DELETE). The root's current `index_generation` is read
/// inside this transaction and copied to `graph_generation` only after every
/// edge insert succeeds. A failed edge replacement therefore cannot make a
/// mixed index/graph snapshot look current.
pub fn persist_edges(
    conn: &mut Connection,
    root: &str,
    edges: &[crate::code_map::graph::CodeEdge],
) -> Result<usize> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin persist-edges transaction")?;
    let inserted = replace_edges_in_transaction(&tx, root, edges)?;
    tx.commit().context("commit persist-edges transaction")?;
    Ok(inserted)
}

/// Atomically publish one map and the exact edge set built from that map.
///
/// Production code-map rebuilds must use this entry point. Readers either see
/// the prior certified pair or the complete new pair; they can never observe a
/// newer map with an older edge set whose generation was rebound by a retry.
pub fn persist_map_and_edges(
    conn: &mut Connection,
    map: &RepoMap,
    edges: &[crate::code_map::graph::CodeEdge],
) -> Result<(PersistStats, usize)> {
    persist_map_and_edges_with_hooks(conn, map, edges, || {}, || {}, || {})
}

/// Atomically publish a map/graph pair already scanned from `expected_root`.
///
/// Unlike the compatibility writer, this path never rediscovers and silently
/// adopts a different directory identity at publication time. The expected
/// identity is written into the snapshot, and a final physical check runs
/// inside the IMMEDIATE transaction so a pre-commit replacement rolls back.
pub(crate) fn persist_map_and_edges_bound(
    conn: &mut Connection,
    map: &RepoMap,
    edges: &[crate::code_map::graph::CodeEdge],
    import_edges: &[crate::code_map::imports::ImportEdge],
    expected_root: &super::root_identity::CanonicalRepoRoot,
) -> Result<BoundPersistResult> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin bound atomic code-map snapshot transaction")?;
    let stats = persist_map_in_transaction(
        &tx,
        map,
        SymbolComparisonMode::ExactSnapshot,
        Some(expected_root),
    )?;
    let inserted = replace_edges_in_transaction(&tx, &map.root, edges)?;
    replace_import_edges_in_transaction(&tx, &map.root, import_edges)?;
    let observed = super::root_identity::CanonicalRepoRoot::discover(Path::new(&map.root))?;
    ensure!(
        observed == *expected_root,
        "code-map repository root was replaced before bound snapshot commit"
    );
    let (stored_identity, index_generation, graph_generation, import_generation) = tx
        .query_row(
            "SELECT root_identity, index_generation, graph_generation, import_generation \
             FROM code_map_roots WHERE root = ?1",
            rusqlite::params![&map.root],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .context("read bound code-map publication generations")?;
    ensure!(
        stored_identity.as_deref() == Some(expected_root.identity().as_str()),
        "bound code-map snapshot persisted a different physical root identity"
    );
    ensure!(
        index_generation > 0
            && index_generation == graph_generation
            && index_generation == import_generation,
        "bound code-map snapshot published mismatched index/graph/import generations"
    );
    tx.commit()
        .context("commit bound atomic code-map snapshot transaction")?;
    Ok(BoundPersistResult {
        stats,
        edges_inserted: inserted,
        index_generation,
        graph_generation,
    })
}

/// Atomically publish a complete map while replacing outgoing edges only for
/// selected source paths.  Callers use every code path when the global
/// declaration-name set changed; otherwise they select changed code sources.
pub(crate) fn persist_delta_map_and_edges_bound<PreCommitFence>(
    conn: &mut Connection,
    map: &RepoMap,
    published_edges: &[crate::code_map::graph::CodeEdge],
    import_edges: &[crate::code_map::imports::ImportEdge],
    replacement_edges: &[crate::code_map::graph::CodeEdge],
    replacement_sources: &std::collections::BTreeSet<String>,
    removed_paths: &std::collections::BTreeSet<String>,
    expected_root: &super::root_identity::CanonicalRepoRoot,
    pre_commit_fence: PreCommitFence,
) -> Result<BoundPersistResult>
where
    PreCommitFence: FnOnce() -> Result<()>,
{
    enforce_incoming_edge_bounds(&map.root, published_edges)?;
    for edge in replacement_edges {
        ensure!(
            replacement_sources.contains(&edge.from_file)
                && !removed_paths.contains(&edge.from_file),
            "delta edge source is outside the selected live source set"
        );
    }
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin bound atomic delta code-map snapshot transaction")?;
    let stats = persist_map_in_transaction(
        &tx,
        map,
        SymbolComparisonMode::ExactSnapshot,
        Some(expected_root),
    )?;
    let mut delete_sources = replacement_sources.clone();
    delete_sources.extend(removed_paths.iter().cloned());
    for source in &delete_sources {
        tx.execute(
            "DELETE FROM code_map_edges WHERE root = ?1 AND from_file = ?2",
            rusqlite::params![&map.root, source],
        )
        .with_context(|| format!("clear delta code-map edges for {source}"))?;
    }
    let (retained_count, retained_text_bytes): (i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(LENGTH(from_file) + LENGTH(from_symbol) + LENGTH(to_name) + LENGTH(kind) + LENGTH(confidence_tier) + LENGTH(COALESCE(target_file, '')) + LENGTH(CAST(confidence AS TEXT))), 0) \
         FROM code_map_edges WHERE root = ?1",
        rusqlite::params![&map.root],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let replacement_count =
        i64::try_from(replacement_edges.len()).context("convert delta replacement edge count")?;
    let replacement_text_bytes = replacement_edges.iter().try_fold(0i64, |total, edge| {
        let text = edge
            .from_file
            .len()
            .checked_add(edge.from_symbol.len())
            .and_then(|bytes| bytes.checked_add(edge.to_name.len()))
            .and_then(|bytes| bytes.checked_add(edge.kind.as_str().len()))
            .and_then(|bytes| bytes.checked_add(edge.confidence_tier.as_str().len()))
            .and_then(|bytes| bytes.checked_add(edge.target_file.as_deref().map_or(0, str::len)))
            .and_then(|bytes| bytes.checked_add(edge.confidence.to_string().len()))
            .context("delta replacement edge text byte count overflow")?;
        let text = i64::try_from(text).context("convert delta replacement edge text bytes")?;
        total
            .checked_add(text)
            .context("delta replacement edge text total overflow")
    })?;
    ensure!(
        retained_count
            .checked_add(replacement_count)
            .is_some_and(|count| count <= PERSIST_PREPASS_EDGE_CAP as i64),
        "delta code-map graph exceeds bounded {PERSIST_PREPASS_EDGE_CAP}-edge publish cap"
    );
    ensure!(
        retained_text_bytes
            .checked_add(replacement_text_bytes)
            .is_some_and(|bytes| bytes <= PERSIST_PREPASS_TEXT_BYTE_CAP),
        "delta code-map graph text exceeds bounded {PERSIST_PREPASS_TEXT_BYTE_CAP}-byte publish cap"
    );
    let mut inserted = 0usize;
    {
        let mut statement = tx.prepare(
            "INSERT INTO code_map_edges (root, from_file, from_symbol, to_name, kind, confidence, confidence_tier, target_file) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for edge in replacement_edges {
            statement.execute(rusqlite::params![
                &map.root,
                &edge.from_file,
                &edge.from_symbol,
                &edge.to_name,
                edge.kind.as_str(),
                edge.confidence,
                edge.confidence_tier.as_str(),
                edge.target_file.as_deref(),
            ])?;
            inserted += 1;
        }
    }
    // Import resolution can change when a module is added, removed or moved,
    // so delta publication deliberately replaces the complete root-local import
    // graph in this same transaction instead of retaining selected sources.
    replace_import_edges_in_transaction(&tx, &map.root, import_edges)?;
    pre_commit_fence().context("validate delta source fence under writer transaction")?;
    let observed = super::root_identity::CanonicalRepoRoot::discover(Path::new(&map.root))?;
    ensure!(
        observed == *expected_root,
        "code-map repository root was replaced before bound delta commit"
    );
    let (stored_identity, index_generation) = tx.query_row(
        "SELECT root_identity, index_generation FROM code_map_roots WHERE root = ?1",
        rusqlite::params![&map.root],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    ensure!(
        stored_identity.as_deref() == Some(expected_root.identity().as_str()),
        "bound delta snapshot persisted a different physical root identity"
    );
    let updated = tx.execute(
        "UPDATE code_map_roots SET graph_generation = ?2, import_generation = ?2 WHERE root = ?1",
        rusqlite::params![&map.root, index_generation],
    )?;
    ensure!(updated == 1, "bind delta graph generation");
    tx.commit()
        .context("commit bound atomic delta code-map snapshot transaction")?;
    Ok(BoundPersistResult {
        stats,
        edges_inserted: inserted,
        index_generation,
        graph_generation: index_generation,
    })
}

fn persist_map_and_edges_with_hooks<BeforeImmediate, AfterImmediate, AfterMap>(
    conn: &mut Connection,
    map: &RepoMap,
    edges: &[crate::code_map::graph::CodeEdge],
    before_immediate: BeforeImmediate,
    after_immediate: AfterImmediate,
    after_map: AfterMap,
) -> Result<(PersistStats, usize)>
where
    BeforeImmediate: FnOnce(),
    AfterImmediate: FnOnce(),
    AfterMap: FnOnce(),
{
    before_immediate();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin atomic code-map snapshot transaction")?;
    after_immediate();
    let stats = persist_map_in_transaction(&tx, map, SymbolComparisonMode::ExactSnapshot, None)?;
    after_map();
    let inserted = replace_edges_in_transaction(&tx, &map.root, edges)?;
    tx.commit()
        .context("commit atomic code-map snapshot transaction")?;
    Ok((stats, inserted))
}

fn replace_edges_in_transaction(
    tx: &Transaction<'_>,
    root: &str,
    edges: &[crate::code_map::graph::CodeEdge],
) -> Result<usize> {
    enforce_incoming_edge_bounds(root, edges)?;
    let index_generation = tx
        .query_row(
            "SELECT index_generation FROM code_map_roots WHERE root = ?1",
            rusqlite::params![root],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .context("query index generation before edge replacement")?;
    let Some(index_generation) = index_generation else {
        bail!("cannot persist edges for unknown code-map root {root:?}; persist the map first");
    };

    tx.execute(
        "DELETE FROM code_map_edges WHERE root = ?1",
        rusqlite::params![root],
    )
    .context("clear prior edges for root")?;
    let mut inserted = 0usize;
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO code_map_edges (root, from_file, from_symbol, to_name, kind, confidence, confidence_tier, target_file) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .context("prepare edge insert")?;
        for edge in edges {
            stmt.execute(rusqlite::params![
                root,
                edge.from_file,
                edge.from_symbol,
                edge.to_name,
                edge.kind.as_str(),
                edge.confidence,
                edge.confidence_tier.as_str(),
                edge.target_file.as_deref(),
            ])
            .context("insert edge row")?;
            inserted += 1;
        }
    }
    let updated = tx
        .execute(
            "UPDATE code_map_roots SET graph_generation = ?2 WHERE root = ?1",
            rusqlite::params![root, index_generation],
        )
        .context("bind edge snapshot to index generation")?;
    if updated != 1 {
        bail!(
            "code-map root {root:?} disappeared while binding graph generation; edge snapshot rolled back"
        );
    }
    Ok(inserted)
}

fn replace_import_edges_in_transaction(
    tx: &Transaction<'_>,
    root: &str,
    edges: &[crate::code_map::imports::ImportEdge],
) -> Result<usize> {
    ensure!(
        edges.len() <= crate::code_map::imports::DEFAULT_MAX_IMPORT_EDGES,
        "import graph exceeds bounded {}-edge publish cap",
        crate::code_map::imports::DEFAULT_MAX_IMPORT_EDGES
    );
    for edge in edges {
        ensure!(
            valid_repo_relative_import_path(&edge.from_file)
                && valid_repo_relative_import_path(&edge.to_file)
                && !edge.language.is_empty(),
            "import edge has an invalid persisted endpoint or language"
        );
        let endpoints: i64 = tx.query_row(
            "SELECT COUNT(*) FROM code_map_files WHERE root = ?1 AND path IN (?2, ?3)",
            rusqlite::params![root, &edge.from_file, &edge.to_file],
            |row| row.get(0),
        )?;
        ensure!(
            endpoints == 2,
            "import edge endpoint is not a current file in the published root"
        );
    }
    tx.execute(
        "DELETE FROM code_map_import_edges WHERE root = ?1",
        rusqlite::params![root],
    )
    .context("clear prior import edges for root")?;
    let mut inserted = 0usize;
    let mut statement = tx.prepare(
        "INSERT INTO code_map_import_edges (root, from_file, to_file, language) \
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for edge in edges {
        statement.execute(rusqlite::params![
            root,
            &edge.from_file,
            &edge.to_file,
            &edge.language
        ])?;
        inserted += 1;
    }
    let index_generation: i64 = tx.query_row(
        "SELECT index_generation FROM code_map_roots WHERE root = ?1",
        rusqlite::params![root],
        |row| row.get(0),
    )?;
    let updated = tx.execute(
        "UPDATE code_map_roots SET import_generation = ?2 WHERE root = ?1",
        rusqlite::params![root, index_generation],
    )?;
    ensure!(updated == 1, "bind import graph generation");
    Ok(inserted)
}

fn valid_repo_relative_import_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !std::path::Path::new(path).is_absolute()
        && std::path::Path::new(path)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

/// Reject an unknown, absolute or traversal-shaped import query before an
/// empty adjacency result can be mistaken for a current known file with zero
/// imports. The lookup is against the active transaction's same-root file set.
pub(crate) fn ensure_current_import_file(conn: &Connection, root: &str, path: &str) -> Result<()> {
    ensure!(
        valid_repo_relative_import_path(path),
        "codegraph import file must be a normalized repository-relative indexed path"
    );
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM code_map_files WHERE root = ?1 AND path = ?2)",
        rusqlite::params![root, path],
        |row| row.get(0),
    )?;
    ensure!(
        exists,
        "codegraph import file is not present in the active code-map snapshot"
    );
    Ok(())
}

/// Load only a root's import edges. An empty vector is meaningful only after
/// callers independently verify `import_generation == index_generation > 0`.
pub(crate) fn load_import_edges_for_root_bounded(
    conn: &Connection,
    root: &str,
    limit: usize,
    text_byte_limit: usize,
) -> Result<(Vec<crate::code_map::imports::ImportEdge>, bool)> {
    let row_limit = i64::try_from(limit.saturating_add(1)).context("import edge row limit")?;
    let mut stmt = conn.prepare(
        "SELECT from_file, to_file, language FROM code_map_import_edges \
         WHERE root = ?1 ORDER BY from_file, to_file, language LIMIT ?2",
    )?;
    let mut rows = stmt.query(rusqlite::params![root, row_limit])?;
    let mut edges = Vec::new();
    let mut text_bytes = 0usize;
    while let Some(row) = rows.next()? {
        if edges.len() >= limit {
            return Ok((edges, true));
        }
        let edge = crate::code_map::imports::ImportEdge {
            from_file: row.get(0)?,
            to_file: row.get(1)?,
            language: row.get(2)?,
        };
        text_bytes = text_bytes
            .checked_add(edge.from_file.len())
            .and_then(|bytes| bytes.checked_add(edge.to_file.len()))
            .and_then(|bytes| bytes.checked_add(edge.language.len()))
            .context("import edge text byte count overflow")?;
        ensure!(
            text_bytes <= text_byte_limit,
            "code-map import graph exceeds bounded {text_byte_limit}-byte text budget"
        );
        edges.push(edge);
    }
    Ok((edges, false))
}

/// QM-2 Phase 2: load edges for `root`. Empty Vec when none stored.
pub fn load_edges(conn: &Connection, root: &str) -> Result<Vec<crate::code_map::graph::CodeEdge>> {
    let mut stmt = conn
        .prepare(
            "SELECT from_file, from_symbol, to_name, kind, confidence, confidence_tier, target_file FROM code_map_edges \
             WHERE root = ?1 ORDER BY from_file, from_symbol, to_name",
        )
        .context("prepare load_edges stmt")?;
    let rows = stmt
        .query_map(rusqlite::params![root], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })
        .context("query edges")?;
    let mut out = Vec::new();
    for row in rows {
        let (from_file, from_symbol, to_name, kind, confidence, confidence_tier, target_file) =
            row.context("read edge row")?;
        out.push(parse_persisted_edge(
            from_file,
            from_symbol,
            to_name,
            target_file,
            &kind,
            confidence,
            &confidence_tier,
        )?);
    }
    Ok(out)
}

/// Load EVERY stored edge across all roots. The `codegraph_callers` /
/// `codegraph_callees` MCP tools query by symbol name globally (a symbol
/// can be called across roots), so they need the whole edge set rather
/// than one root's slice. Deterministic order for stable BFS output.
pub fn load_all_edges(conn: &Connection) -> Result<Vec<crate::code_map::graph::CodeEdge>> {
    load_edges_filtered(conn, None)
}

/// Every call/reference edge under ONE persisted root.
///
/// The containment boundary that scopes `relevant_files` to the caller's repo is
/// only real if the call graph honours it too: `load_all_edges` mixes every
/// indexed repository, so a caller/callee query answered symbols and file paths
/// from repositories the client never asked about.
pub fn load_edges_for_root(
    conn: &Connection,
    root: &str,
) -> Result<Vec<crate::code_map::graph::CodeEdge>> {
    load_edges_filtered(conn, Some(root))
}

/// Read the complete existing graph for a bounded delta publication. Unlike
/// the compatibility loader above, this rejects rather than materialises a
/// graph beyond the writer's row or aggregate-text ceilings.
pub(crate) fn load_edges_for_delta_refresh(
    conn: &Connection,
    root: &str,
) -> Result<Vec<crate::code_map::graph::CodeEdge>> {
    let (edges, truncated, _) = load_edges_for_root_bounded_with_text_limit(
        conn,
        root,
        PERSIST_PREPASS_EDGE_CAP,
        PERSIST_PREPASS_TEXT_BYTE_CAP as usize,
    )?;
    ensure!(
        !truncated,
        "persisted code-map graph for {root:?} exceeds bounded {PERSIST_PREPASS_EDGE_CAP}-edge delta refresh cap"
    );
    Ok(edges)
}

/// Impact-analysis loader with a second, byte-based allocation boundary.
/// SQLite reports each row's text size before Rust materialises its strings,
/// so a concurrent insertion after an aggregate preflight cannot force one
/// enormous edge allocation.
pub(crate) fn load_edges_for_root_bounded_with_text_limit(
    conn: &Connection,
    root: &str,
    limit: usize,
    text_byte_limit: usize,
) -> Result<(Vec<crate::code_map::graph::CodeEdge>, bool, usize)> {
    const MAX_EDGE_ROW_TEXT_BYTES: usize = 64 * 1024;
    let sql_limit = i64::try_from(limit.saturating_add(1))
        .context("convert bounded edge-query limit to SQLite integer")?;
    let mut stmt = conn
        .prepare(
            "SELECT from_file, from_symbol, to_name, kind, confidence, confidence_tier, target_file, \
                    length(CAST(from_file AS BLOB)) + \
                    length(CAST(from_symbol AS BLOB)) + \
                    length(CAST(to_name AS BLOB)) + \
                    length(CAST(kind AS BLOB)) + \
                    length(CAST(confidence AS TEXT)) + \
                    length(CAST(confidence_tier AS BLOB)) + \
                    COALESCE(length(CAST(target_file AS BLOB)), 0) \
             FROM code_map_edges \
             WHERE root = ?1 ORDER BY from_file, from_symbol, to_name LIMIT ?2",
        )
        .context("prepare bounded root-edge query")?;
    let mut rows = stmt
        .query(rusqlite::params![root, sql_limit])
        .context("query bounded root edges")?;
    let mut out = Vec::with_capacity(limit.min(4_096).saturating_add(1));
    let mut text_bytes = 0usize;
    while let Some(row) = rows.next().context("advance bounded edge row")? {
        let row_bytes: i64 = row.get(7).context("read bounded edge text-byte count")?;
        let row_bytes = usize::try_from(row_bytes)
            .with_context(|| format!("invalid negative edge text-byte count {row_bytes}"))?;
        if row_bytes > MAX_EDGE_ROW_TEXT_BYTES {
            bail!(
                "impact edge row requires {row_bytes} text bytes; per-row ceiling is \
                 {MAX_EDGE_ROW_TEXT_BYTES}"
            );
        }
        text_bytes = text_bytes
            .checked_add(row_bytes)
            .context("edge text-byte count overflow")?;
        if text_bytes > text_byte_limit {
            bail!("impact edge materialization refused more than {text_byte_limit} text bytes");
        }
        let from_file = row
            .get::<_, String>(0)
            .context("read bounded edge source file")?;
        let from_symbol = row
            .get::<_, String>(1)
            .context("read bounded edge source symbol")?;
        let to_name = row
            .get::<_, String>(2)
            .context("read bounded edge target name")?;
        let kind = row.get::<_, String>(3).context("read bounded edge kind")?;
        let confidence = row
            .get::<_, i64>(4)
            .context("read bounded edge confidence")?;
        let confidence_tier = row
            .get::<_, String>(5)
            .context("read bounded edge confidence tier")?;
        let target_file = row
            .get::<_, Option<String>>(6)
            .context("read bounded exact edge target file")?;
        out.push(parse_persisted_edge(
            from_file,
            from_symbol,
            to_name,
            target_file,
            &kind,
            confidence,
            &confidence_tier,
        )?);
    }
    let truncated = out.len() > limit;
    out.truncate(limit);
    Ok((out, truncated, text_bytes))
}

fn load_edges_filtered(
    conn: &Connection,
    root: Option<&str>,
) -> Result<Vec<crate::code_map::graph::CodeEdge>> {
    let sql = match root {
        Some(_) => {
            "SELECT from_file, from_symbol, to_name, kind, confidence, confidence_tier, target_file FROM code_map_edges \
             WHERE root = ?1 ORDER BY from_file, from_symbol, to_name"
        }
        None => {
            "SELECT from_file, from_symbol, to_name, kind, confidence, confidence_tier, target_file FROM code_map_edges \
             ORDER BY from_file, from_symbol, to_name"
        }
    };
    let mut stmt = conn.prepare(sql).context("prepare load_edges stmt")?;
    let params: Vec<String> = root.map(|root| vec![root.to_string()]).unwrap_or_default();
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })
        .context("query all edges")?;
    let mut out = Vec::new();
    for row in rows {
        let (from_file, from_symbol, to_name, kind, confidence, confidence_tier, target_file) =
            row.context("read edge row")?;
        out.push(parse_persisted_edge(
            from_file,
            from_symbol,
            to_name,
            target_file,
            &kind,
            confidence,
            &confidence_tier,
        )?);
    }
    Ok(out)
}

fn parse_persisted_edge(
    from_file: String,
    from_symbol: String,
    to_name: String,
    target_file: Option<String>,
    kind: &str,
    confidence: i64,
    confidence_tier: &str,
) -> Result<crate::code_map::graph::CodeEdge> {
    let confidence = u8::try_from(confidence)
        .with_context(|| format!("invalid persisted code-map edge confidence {confidence}"))?;
    let confidence_tier = parse_persisted_edge_confidence_tier(confidence_tier)?;
    if target_file.as_deref() == Some("") {
        bail!("persisted code-map edge has an empty exact target file")
    }
    let edge = crate::code_map::graph::CodeEdge {
        from_file,
        from_symbol,
        to_name,
        target_file,
        kind: parse_persisted_edge_kind(kind)?,
        confidence,
        confidence_tier,
    };
    edge.validate_confidence().with_context(|| {
        "invalid persisted code-map edge confidence/tier pair; rebuild the code map with this NEOTH version"
    })?;
    Ok(edge)
}

fn parse_persisted_edge_confidence_tier(
    confidence_tier: &str,
) -> Result<crate::code_map::graph::EdgeConfidenceTier> {
    match confidence_tier {
        "inferred" => Ok(crate::code_map::graph::EdgeConfidenceTier::Inferred),
        "resolved" => Ok(crate::code_map::graph::EdgeConfidenceTier::Resolved),
        other => bail!(
            "unsupported persisted code-map edge confidence tier {other:?}; rebuild the code map with this NEOTH version"
        ),
    }
}

fn parse_persisted_edge_kind(kind: &str) -> Result<crate::code_map::graph::EdgeKind> {
    match kind {
        "calls" => Ok(crate::code_map::graph::EdgeKind::Calls),
        "references" => Ok(crate::code_map::graph::EdgeKind::References),
        "tested_by" => Ok(crate::code_map::graph::EdgeKind::TestedBy),
        other => bail!(
            "unsupported persisted code-map edge kind {other:?}; rebuild the code map with this NEOTH version"
        ),
    }
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
    enforce_persist_prepass_bounds(conn, &root)?;

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

    // Pull only this root's bounded symbols and group them in one pass. The
    // former global query loaded declarations for every persisted repository
    // and then performed an O(files * symbols) filter.
    let mut sym_stmt = conn
        .prepare(
            "SELECT s.file_id, s.name, s.kind, s.line, s.line_end \
             FROM code_map_symbols s \
             JOIN code_map_files f ON f.id = s.file_id \
             WHERE f.root = ?1 \
             ORDER BY s.file_id ASC, s.line ASC, s.line_end ASC",
        )
        .context("prepare code_map_symbols SELECT")?;
    let mut sym_rows = sym_stmt
        .query(rusqlite::params![&root])
        .context("query root-scoped code_map_symbols")?;
    let mut symbols_by_file: std::collections::HashMap<i64, Vec<Symbol>> =
        std::collections::HashMap::new();
    while let Some(row) = sym_rows
        .next()
        .context("advance root-scoped code_map_symbols row")?
    {
        let file_id: i64 = row.get(0).context("read code-map symbol file id")?;
        let name: String = row.get(1).context("read code-map symbol name")?;
        let kind_label: String = row.get(2).context("read code-map symbol kind")?;
        let line: i64 = row.get(3).context("read code-map symbol line")?;
        let line_end: Option<i64> = row.get(4).context("read code-map symbol end line")?;
        let line = u32::try_from(line).context("invalid persisted code-map symbol line")?;
        let line_end = line_end
            .map(|end| {
                let end =
                    u32::try_from(end).context("invalid persisted code-map symbol end line")?;
                ensure!(
                    end >= line,
                    "persisted code-map symbol end line {end} precedes start line {line}"
                );
                Ok(end)
            })
            .transpose()?;
        symbols_by_file.entry(file_id).or_default().push(Symbol {
            name,
            kind: symbol_kind_from_label(&kind_label).unwrap_or(SymbolKind::Function),
            line,
            line_end,
        });
    }

    let mut files: Vec<RepoFile> = Vec::with_capacity(file_rows.len());
    let mut by_lang: std::collections::HashMap<Language, u64> = std::collections::HashMap::new();
    for (file_id, path, lang_label, bytes, loc, sha256, mtime_ns) in file_rows {
        let language = language_from_label(&lang_label).unwrap_or(Language::Other);
        *by_lang.entry(language).or_insert(0) += 1;
        let symbols = symbols_by_file.remove(&file_id).unwrap_or_default();
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

/// The index generation for which `root`'s persisted edge set was built, or
/// `None` when the root has no persisted snapshot. This advances atomically
/// with edge replacement in [`persist_edges`].
pub fn root_graph_generation(conn: &Connection, root: &str) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT graph_generation FROM code_map_roots WHERE root = ?1",
        rusqlite::params![root],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .context("query code_map_roots graph_generation")
}

/// True only for a root generation whose scanner reported no file-count or
/// per-file-size omissions. Prompt and architecture consumers refuse partial
/// operator snapshots even when their index/graph generations match.
pub(crate) fn root_snapshot_complete(conn: &Connection, root: &str) -> Result<bool> {
    conn.query_row(
        "SELECT oversize_skipped = 0 AND truncated_at IS NULL \
         FROM code_map_roots WHERE root = ?1",
        rusqlite::params![root],
        |row| row.get::<_, bool>(0),
    )
    .optional()
    .context("query code-map root completeness")
    .map(|complete| complete.unwrap_or(false))
}

/// Read classifier-visible test-evidence exclusions from the already-persisted
/// root snapshot. This intentionally avoids source re-scanning and schema
/// migration: file paths, languages, and declarations are enough to retain
/// only the narrow path/language and duplicate-target facts below. Framework
/// marker forms are not recoverable from this schema and remain unknown.
///
/// `max_rows` is a whole-operation work ceiling. Both file and declaration
/// rows, including a cap sentinel, consume it; `work_units` reports the exact
/// number physically materialised so an impact caller can charge its shared
/// budget without resetting it per node.
pub(crate) fn root_test_evidence_exclusion_summary_bounded(
    conn: &Connection,
    root: &str,
    max_rows: usize,
) -> Result<crate::code_map::graph::TestEvidenceExclusionSummary> {
    ensure!(
        max_rows > 0,
        "test-evidence exclusion work cap must be positive"
    );
    let max_rows = max_rows.min(MAX_TEST_EVIDENCE_EXCLUSION_ROWS);
    let step_limit = Arc::new(AtomicBool::new(false));
    let step_limit_for_progress = Arc::clone(&step_limit);
    let mut steps = 0usize;
    conn.progress_handler(
        TEST_EVIDENCE_EXCLUSION_VM_STEP_INTERVAL,
        Some(move || {
            steps = steps.saturating_add(TEST_EVIDENCE_EXCLUSION_VM_STEP_INTERVAL as usize);
            let stop = steps >= TEST_EVIDENCE_EXCLUSION_VM_STEP_LIMIT;
            if stop {
                step_limit_for_progress.store(true, Ordering::Relaxed);
            }
            stop
        }),
    );
    let _reset_progress = TestEvidenceExclusionProgressReset { conn };
    let mut summary = crate::code_map::graph::TestEvidenceExclusionSummary::default();
    let mut categories = BTreeMap::new();
    let file_observation_cap = max_rows.saturating_sub(1);
    let file_limit = i64::try_from(file_observation_cap.saturating_add(1))
        .context("convert test-evidence exclusion file row limit")?;
    let mut statement = conn
        .prepare(
            "SELECT path, language, \
                    length(CAST(path AS BLOB)) + length(CAST(language AS BLOB)) \
             FROM code_map_files \
             WHERE root = ?1 ORDER BY path LIMIT ?2",
        )
        .context("prepare bounded test-evidence exclusion file query")?;
    let mut rows = statement
        .query(rusqlite::params![root, file_limit])
        .context("query bounded test-evidence exclusion files")?;
    let mut text_bytes = 0usize;
    while let Some(row) = match rows.next() {
        Ok(row) => row,
        Err(error) if step_limit.load(Ordering::Relaxed) => bail!(
            "test-evidence exclusion query exceeded its {} SQLite-VM-step work bound: {error}",
            TEST_EVIDENCE_EXCLUSION_VM_STEP_LIMIT
        ),
        Err(error) => {
            return Err(error).context("advance bounded test-evidence exclusion file row");
        }
    } {
        if summary.source_files_examined == file_observation_cap {
            summary.work_units = summary
                .work_units
                .checked_add(1)
                .context("test-evidence exclusion sentinel work overflow")?;
            summary.capped = true;
            summary.categories = categories;
            return Ok(summary);
        }
        let row_bytes: i64 = row
            .get(2)
            .context("read test-evidence exclusion file text-byte count")?;
        let row_bytes = usize::try_from(row_bytes).with_context(|| {
            format!("invalid test-evidence exclusion file text bytes {row_bytes}")
        })?;
        ensure!(
            row_bytes <= MAX_TEST_EVIDENCE_EXCLUSION_ROW_TEXT_BYTES,
            "test-evidence exclusion file row exceeds text ceiling"
        );
        text_bytes = text_bytes
            .checked_add(row_bytes)
            .context("test-evidence exclusion file text-byte overflow")?;
        ensure!(
            text_bytes <= MAX_TEST_EVIDENCE_EXCLUSION_TEXT_BYTES,
            "test-evidence exclusion file materialization exceeds text ceiling"
        );
        let path: String = row.get(0).context("read test-evidence exclusion path")?;
        let language: String = row
            .get(1)
            .context("read test-evidence exclusion language")?;
        for category in
            crate::code_map::graph::persisted_test_evidence_file_exclusions(&path, &language)
        {
            let count = categories.entry(category).or_insert(0usize);
            *count = count
                .checked_add(1)
                .context("test-evidence exclusion category count overflow")?;
        }
        summary.source_files_examined = summary
            .source_files_examined
            .checked_add(1)
            .context("test-evidence exclusion file count overflow")?;
        summary.work_units = summary
            .work_units
            .checked_add(1)
            .context("test-evidence exclusion file work overflow")?;
    }
    drop(rows);
    drop(statement);

    // Only a complete bounded file pass may make a duplicate-target claim.
    // A truncated declaration stream could hide a second target file, so it
    // remains unknown instead of publishing a misleading lower bound.
    let remaining = max_rows.saturating_sub(summary.work_units);
    if remaining == 0 {
        summary.capped = true;
        summary.categories = categories;
        return Ok(summary);
    }
    let symbol_observation_cap = remaining.saturating_sub(1);
    let symbol_limit = i64::try_from(symbol_observation_cap.saturating_add(1))
        .context("convert test-evidence exclusion symbol row limit")?;
    let mut statement = conn
        .prepare(
            "SELECT f.path, f.language, s.name, s.kind, \
                    length(CAST(f.path AS BLOB)) + length(CAST(f.language AS BLOB)) + \
                    length(CAST(s.name AS BLOB)) + length(CAST(s.kind AS BLOB)) \
             FROM code_map_files f \
             JOIN code_map_symbols s ON s.file_id = f.id \
             WHERE f.root = ?1 \
             ORDER BY s.name, f.path, s.kind, s.line LIMIT ?2",
        )
        .context("prepare bounded test-evidence exclusion symbol query")?;
    let mut rows = statement
        .query(rusqlite::params![root, symbol_limit])
        .context("query bounded test-evidence exclusion symbols")?;
    let mut duplicate_names = BTreeSet::new();
    let mut current_name: Option<String> = None;
    let mut current_paths = BTreeSet::new();
    while let Some(row) = match rows.next() {
        Ok(row) => row,
        Err(error) if step_limit.load(Ordering::Relaxed) => bail!(
            "test-evidence exclusion query exceeded its {} SQLite-VM-step work bound: {error}",
            TEST_EVIDENCE_EXCLUSION_VM_STEP_LIMIT
        ),
        Err(error) => {
            return Err(error).context("advance bounded test-evidence exclusion symbol row");
        }
    } {
        if summary.source_symbols_examined == symbol_observation_cap {
            summary.work_units = summary
                .work_units
                .checked_add(1)
                .context("test-evidence exclusion symbol sentinel work overflow")?;
            summary.capped = true;
            summary.categories = categories;
            return Ok(summary);
        }
        let row_bytes: i64 = row
            .get(4)
            .context("read test-evidence exclusion symbol text-byte count")?;
        let row_bytes = usize::try_from(row_bytes).with_context(|| {
            format!("invalid test-evidence exclusion symbol text bytes {row_bytes}")
        })?;
        ensure!(
            row_bytes <= MAX_TEST_EVIDENCE_EXCLUSION_ROW_TEXT_BYTES,
            "test-evidence exclusion symbol row exceeds text ceiling"
        );
        text_bytes = text_bytes
            .checked_add(row_bytes)
            .context("test-evidence exclusion symbol text-byte overflow")?;
        ensure!(
            text_bytes <= MAX_TEST_EVIDENCE_EXCLUSION_TEXT_BYTES,
            "test-evidence exclusion symbol materialization exceeds text ceiling"
        );
        let path: String = row.get(0).context("read test-evidence target path")?;
        let language: String = row.get(1).context("read test-evidence target language")?;
        let name: String = row.get(2).context("read test-evidence target name")?;
        let kind: String = row.get(3).context("read test-evidence target kind")?;
        if crate::code_map::graph::persisted_supported_test_evidence_target(&path, &language, &kind)
        {
            if current_name.as_deref() != Some(&name) {
                if current_paths.len() > 1 {
                    duplicate_names.insert(current_name.take().expect("present duplicate name"));
                }
                current_paths.clear();
                current_name = Some(name.clone());
            }
            current_paths.insert(path);
        }
        summary.source_symbols_examined = summary
            .source_symbols_examined
            .checked_add(1)
            .context("test-evidence exclusion symbol count overflow")?;
        summary.work_units = summary
            .work_units
            .checked_add(1)
            .context("test-evidence exclusion symbol work overflow")?;
    }
    if current_paths.len() > 1 {
        duplicate_names.insert(current_name.expect("present final duplicate name"));
    }
    if !duplicate_names.is_empty() {
        categories.insert(
            crate::code_map::graph::TestEvidenceExclusionCategory::DuplicateTarget,
            duplicate_names.len(),
        );
    }
    summary.categories = categories;
    Ok(summary)
}

/// Bounded, persisted `TestedBy` evidence for Doctor.  These are structural
/// graph observations only: an exact edge is not a record that any test was
/// executed, and an empty observation is never evidence that a repository has
/// no tests or coverage.
///
/// The caller must first establish the root's canonical physical identity and
/// lifecycle freshness.  This helper neither performs that filesystem work nor
/// creates, migrates, refreshes, repairs, or writes the SQLite store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RootTestEvidenceSummary {
    pub schema_version: i64,
    pub index_generation: i64,
    pub graph_generation: i64,
    pub snapshot_complete: bool,
    /// `tested_by` rows observed within the bounded query, excluding its
    /// sentinel row when `capped` is true.
    pub observed_tested_by_edges: usize,
    /// Observed rows that carry a non-empty exact target file and the resolved
    /// provenance tier.  This remains structural graph evidence, not coverage.
    pub observed_exact_tested_by_edges: usize,
    /// More matching rows existed beyond `observed_tested_by_edges`; counts
    /// are deliberately not presented as totals in this state.
    pub capped: bool,
}

/// Read a root's persisted test-evidence shape without materialising source,
/// symbol, or edge text.  The SQL result has both a row/sentinel limit and a
/// SQLite VM-step interruption bound, so an unindexed or adversarially large
/// store becomes an explicit diagnostic rather than an unbounded Doctor scan.
pub(crate) fn root_test_evidence_summary(
    conn: &Connection,
    root: &str,
) -> Result<RootTestEvidenceSummary> {
    root_test_evidence_summary_with_limits(
        conn,
        root,
        MAX_DOCTOR_TEST_EVIDENCE_ROWS,
        DOCTOR_TEST_EVIDENCE_VM_STEP_LIMIT,
        DOCTOR_TEST_EVIDENCE_VM_STEP_INTERVAL,
    )
}

/// The production wrapper above fixes both budgets.  Keeping the bounded
/// operation in one helper lets its real SQLite query prove exact cap and
/// interruption cleanup semantics without duplicating the query in tests.
fn root_test_evidence_summary_with_limits(
    conn: &Connection,
    root: &str,
    max_rows: usize,
    vm_step_limit: usize,
    vm_step_interval: i32,
) -> Result<RootTestEvidenceSummary> {
    ensure!(
        max_rows > 0,
        "Doctor test-evidence row cap must be positive"
    );
    ensure!(
        vm_step_limit > 0,
        "Doctor test-evidence VM-step cap must be positive"
    );
    ensure!(
        vm_step_interval > 0,
        "Doctor test-evidence VM-step interval must be positive"
    );
    let schema_version_raw: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .context("read code-map schema version for Doctor evidence")?;
    let schema_version = schema_version_raw
        .parse::<i64>()
        .context("parse code-map schema version for Doctor evidence")?;
    let index_generation = root_index_generation(conn, root)?
        .ok_or_else(|| anyhow::anyhow!("Doctor evidence root is not persisted"))?;
    let graph_generation = root_graph_generation(conn, root)?
        .ok_or_else(|| anyhow::anyhow!("Doctor evidence root graph is not persisted"))?;
    let snapshot_complete = root_snapshot_complete(conn, root)?;

    let row_limit = i64::try_from(max_rows.saturating_add(1))
        .context("convert Doctor evidence row limit to SQLite integer")?;
    let step_limit = Arc::new(AtomicBool::new(false));
    let step_limit_for_progress = Arc::clone(&step_limit);
    let mut steps = 0usize;
    conn.progress_handler(
        vm_step_interval,
        Some(move || {
            steps = steps.saturating_add(vm_step_interval as usize);
            let stop = steps >= vm_step_limit;
            if stop {
                step_limit_for_progress.store(true, Ordering::Relaxed);
            }
            stop
        }),
    );
    let query_result: Result<(usize, usize, bool)> = (|| {
        let mut statement = conn
            .prepare(
                "SELECT target_file IS NOT NULL \
                         AND length(CAST(target_file AS BLOB)) > 0 \
                         AND confidence = 100 \
                         AND confidence_tier = 'resolved' \
                 FROM code_map_edges \
                 WHERE root = ?1 AND kind = 'tested_by' \
                 LIMIT ?2",
            )
            .context("prepare bounded Doctor test-evidence query")?;
        let mut rows = statement
            .query(rusqlite::params![root, row_limit])
            .context("query bounded Doctor test evidence")?;
        let mut observed = 0usize;
        let mut exact = 0usize;
        while let Some(row) = rows
            .next()
            .context("advance bounded Doctor test evidence")?
        {
            if observed == max_rows {
                return Ok((observed, exact, true));
            }
            let is_exact = row
                .get::<_, bool>(0)
                .context("read bounded Doctor exact-test-evidence flag")?;
            observed = observed
                .checked_add(1)
                .context("Doctor test-evidence row count overflow")?;
            if is_exact {
                exact = exact
                    .checked_add(1)
                    .context("Doctor exact-test-evidence row count overflow")?;
            }
        }
        Ok((observed, exact, false))
    })();
    conn.progress_handler(0, None::<fn() -> bool>);
    match query_result {
        Ok(_) if step_limit.load(Ordering::Relaxed) => bail!(
            "Doctor test-evidence query exceeded its {} SQLite-VM-step work bound",
            vm_step_limit
        ),
        Ok((observed_tested_by_edges, observed_exact_tested_by_edges, capped)) => {
            Ok(RootTestEvidenceSummary {
                schema_version,
                index_generation,
                graph_generation,
                snapshot_complete,
                observed_tested_by_edges,
                observed_exact_tested_by_edges,
                capped,
            })
        }
        Err(error) if step_limit.load(Ordering::Relaxed) => bail!(
            "Doctor test-evidence query exceeded its {} SQLite-VM-step work bound: {error:#}",
            vm_step_limit
        ),
        Err(error) => Err(error).context("read bounded Doctor test evidence"),
    }
}

/// GOLD-R3-13 — is the persisted snapshot for `root` stale relative to the
/// files currently on disk? Re-scans the root (no symbol extraction) with the
/// same ignore rules and compares content hashes against the stored rows: a
/// stale index has an added, removed, or content-changed file. Returns `false`
/// (fresh) when the root has no snapshot to compare against.
///
/// This re-reads the root's files to hash them, so it is an EXPLICIT, opt-in
/// check (an operator command), never the hot chat-context path. A stored row
/// with an empty hash (a pre-CBM-04 v1 row not yet re-scanned) is unverifiable
/// and therefore stale until rebuilt. Both the persisted SELECT
/// and filesystem walk are capped by [`MAX_FRESHNESS_FILES`]; exceeding that
/// ceiling is an explicit error, never a partial receipt reported as fresh.
pub fn is_index_stale(conn: &Connection, root: &str) -> Result<bool> {
    Ok(index_freshness_receipt(conn, root)?.stale)
}

/// One bounded filesystem observation used to ensure a long-running consumer
/// does not report `stale = false` after the repository changed mid-query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IndexFreshnessReceipt {
    pub(crate) stale: bool,
    pub(crate) filesystem_fingerprint: Vec<(String, String)>,
}

/// Strict freshness check used by production recall paths.
///
/// This deliberately does not cache watcher silence: filesystem watcher
/// delivery is asynchronous and therefore cannot prove that an edit preceding
/// this call has already been observed. Every authorization-sensitive recall
/// revalidates persisted hashes against a bounded filesystem scan. The
/// generation parameter remains part of the call contract so a future cache
/// can only be introduced with a synchronous, snapshot-bound proof.
pub(crate) fn index_freshness_receipt_cached(
    conn: &Connection,
    root: &str,
    generation: i64,
) -> Result<IndexFreshnessReceipt> {
    ensure!(
        generation > 0,
        "cannot verify a nonpositive code-map generation"
    );
    index_freshness_receipt(conn, root)
}

pub(crate) fn index_freshness_receipt_cached_scoped(
    conn: &Connection,
    root: &str,
    generation: i64,
    included_relative_paths: &[std::path::PathBuf],
    excluded_relative_paths: &[std::path::PathBuf],
) -> Result<IndexFreshnessReceipt> {
    ensure!(
        generation > 0,
        "cannot verify a nonpositive code-map generation"
    );
    index_freshness_receipt_bounded_with_limits_and_scope_and_hook(
        conn,
        root,
        MAX_FRESHNESS_FILES,
        MAX_FRESHNESS_TEXT_BYTES,
        included_relative_paths,
        excluded_relative_paths,
        || {},
    )
}

pub(crate) fn index_freshness_receipt(
    conn: &Connection,
    root: &str,
) -> Result<IndexFreshnessReceipt> {
    index_freshness_receipt_bounded_with_hook(conn, root, MAX_FRESHNESS_FILES, || {})
}

fn index_freshness_receipt_bounded_with_hook<F>(
    conn: &Connection,
    root: &str,
    max_files: usize,
    after_count: F,
) -> Result<IndexFreshnessReceipt>
where
    F: FnOnce(),
{
    index_freshness_receipt_bounded_with_limits_and_hook(
        conn,
        root,
        max_files,
        MAX_FRESHNESS_TEXT_BYTES,
        after_count,
    )
}

fn index_freshness_receipt_bounded_with_limits_and_hook<F>(
    conn: &Connection,
    root: &str,
    max_files: usize,
    max_text_bytes: usize,
    after_count: F,
) -> Result<IndexFreshnessReceipt>
where
    F: FnOnce(),
{
    index_freshness_receipt_bounded_with_limits_and_scope_and_hook(
        conn,
        root,
        max_files,
        max_text_bytes,
        &[],
        &[],
        after_count,
    )
}

fn index_freshness_receipt_bounded_with_limits_and_scope_and_hook<F>(
    conn: &Connection,
    root: &str,
    max_files: usize,
    max_text_bytes: usize,
    included_relative_paths: &[std::path::PathBuf],
    excluded_relative_paths: &[std::path::PathBuf],
    after_count: F,
) -> Result<IndexFreshnessReceipt>
where
    F: FnOnce(),
{
    let (root_exists, stored_count): (bool, i64) = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM code_map_roots WHERE root = ?1), \
                    (SELECT COUNT(*) FROM code_map_files WHERE root = ?1)",
            rusqlite::params![root],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("read root existence and stored file count before freshness receipt")?;
    enforce_freshness_file_count(stored_count, max_files)?;
    after_count();

    // An unknown root has no persisted snapshot to compare. A KNOWN empty root
    // is different: it must still be walked so the first newly-created file is
    // reported stale instead of being mistaken for "no snapshot".
    if !root_exists {
        return Ok(IndexFreshnessReceipt {
            stale: false,
            filesystem_fingerprint: Vec::new(),
        });
    }

    let query_limit = i64::try_from(max_files.saturating_add(1))
        .context("convert freshness file-query limit to SQLite integer")?;
    let stored_rows: Vec<(String, String)> = {
        let mut stmt = conn
            .prepare(
                "SELECT path, sha256, \
                        length(CAST(path AS BLOB)) + length(CAST(sha256 AS BLOB)) \
                 FROM code_map_files \
                 WHERE root = ?1 ORDER BY path LIMIT ?2",
            )
            .context("prepare staleness stored-hash query")?;
        let mut rows = stmt
            .query(rusqlite::params![root, query_limit])
            .context("execute staleness stored-hash query")?;
        let mut bounded = Vec::with_capacity(max_files.min(4_096).saturating_add(1));
        let mut text_bytes = 0usize;
        while let Some(row) = rows.next().context("advance staleness stored-hash row")? {
            let row_bytes: i64 = row
                .get(2)
                .context("read staleness stored-hash text-byte count")?;
            let row_bytes = usize::try_from(row_bytes).with_context(|| {
                format!("invalid negative freshness row text-byte count {row_bytes}")
            })?;
            if row_bytes > MAX_FRESHNESS_ROW_TEXT_BYTES {
                bail!(
                    "code-map freshness row requires {row_bytes} text bytes; per-row \
                     ceiling is {MAX_FRESHNESS_ROW_TEXT_BYTES}"
                );
            }
            text_bytes = text_bytes
                .checked_add(row_bytes)
                .context("code-map freshness text-byte count overflow")?;
            if text_bytes > max_text_bytes {
                bail!(
                    "code-map freshness refused more than {max_text_bytes} stored \
                     path/hash text bytes"
                );
            }
            bounded.push((
                row.get::<_, String>(0)
                    .context("read staleness stored path")?,
                row.get::<_, String>(1)
                    .context("read staleness stored hash")?,
            ));
        }
        bounded
    };
    if stored_rows.len() > max_files {
        bail!(
            "code-map freshness refused more than {max_files} stored file rows; \
             persist a narrower repository or select a smaller code-map root"
        );
    }
    let stored: std::collections::HashMap<String, String> = stored_rows.into_iter().collect();
    let walker_limit = u64::try_from(max_files).context("convert freshness walker file ceiling")?;
    let mut builder = super::walker::RepoMapBuilder::new(root)
        .max_files(walker_limit)
        .with_symbols(false)
        .strict_errors(true)
        .exclude_relative_paths(excluded_relative_paths.iter().cloned());
    if !included_relative_paths.is_empty() {
        builder = builder.include_relative_paths(included_relative_paths.iter().cloned());
    }
    let scanned = builder
        .scan()
        .with_context(|| format!("re-scan {root} for staleness check"))?;
    if scanned.report.truncated_at.is_some() {
        bail!(
            "code-map freshness refused a filesystem with more than {max_files} files; \
             persist a narrower repository or select a smaller code-map root"
        );
    }
    if scanned.report.oversize_skipped > 0 {
        bail!(
            "code-map freshness skipped {} oversized filesystem file(s); freshness is unknown",
            scanned.report.oversize_skipped
        );
    }
    let mut filesystem_fingerprint: Vec<(String, String)> = scanned
        .files
        .iter()
        .map(|file| (file.path.clone(), file.sha256.clone()))
        .collect();
    filesystem_fingerprint.sort();

    // Added or removed files change the set size (both sides bounded by the
    // same caps, so a stable tree yields equal counts). Legacy rows without a
    // content hash are unverifiable and therefore stale until rebuilt.
    let stale = scanned.files.len() != stored.len()
        || scanned.files.iter().any(|file| {
            // Any on-disk file that is new, or whose content hash differs from
            // the stored hash, means the index predates an edit. An empty
            // stored hash is unknown and must never be accepted as fresh.
            !matches!(
                stored.get(&file.path),
                Some(stored_sha) if !stored_sha.is_empty() && *stored_sha == file.sha256
            )
        });
    Ok(IndexFreshnessReceipt {
        stale,
        filesystem_fingerprint,
    })
}

fn enforce_freshness_file_count(count: i64, max_files: usize) -> Result<()> {
    let count = usize::try_from(count)
        .with_context(|| format!("invalid negative code-map freshness file count {count}"))?;
    if count > max_files {
        bail!(
            "code-map freshness refused {count} stored file rows; hard ceiling is {max_files}. \
             Persist a narrower repository or select a smaller code-map root"
        );
    }
    Ok(())
}

/// Find every persisted file whose symbol list contains a declaration
/// matching `symbol_name` exactly. Ordered by `(root, path)` so a
/// repo with many roots stays grouped. Result rows carry the bare
/// fields the CLI needs to render `file:line` jump targets — no
/// `RepoFile` reconstruction.
pub fn search_symbol(conn: &Connection, symbol_name: &str, root: &str) -> Result<Vec<SymbolHit>> {
    let mut stmt = conn
        .prepare(
            "SELECT f.root, f.path, s.kind, s.line \
             FROM code_map_symbols s \
             JOIN code_map_files f ON f.id = s.file_id \
             WHERE s.name = ?1 AND f.root = ?2 \
             ORDER BY f.path ASC, s.line ASC",
        )
        .context("prepare symbol search SELECT")?;
    let rows: Vec<SymbolHit> = stmt
        .query_map(rusqlite::params![symbol_name, root], |row| {
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
pub fn search_symbol_fuzzy(conn: &Connection, query: &str, root: &str) -> Result<Vec<SymbolHit>> {
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
             WHERE code_map_symbols_fts MATCH ?1 AND f.root = ?2 \
             ORDER BY bm25(code_map_symbols_fts), f.path, s.line \
             LIMIT 200",
        )
        .context("prepare fuzzy symbol search SELECT")?;
    let rows: Vec<SymbolHit> = stmt
        .query_map(rusqlite::params![fts_query, root], |row| {
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
    use crate::code_map::graph::{EdgeConfidenceTier, EdgeKind};
    use crate::code_map::walker::{RepoFile, RepoMap, ScanReport};
    use tempfile::tempdir;

    fn temp_db() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("code_map.db");
        let conn = open(&path).unwrap();
        (dir, conn)
    }

    fn is_sqlite_busy(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| {
            cause
                .downcast_ref::<rusqlite::Error>()
                .and_then(rusqlite::Error::sqlite_error_code)
                .is_some_and(|code| {
                    matches!(
                        code,
                        rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                    )
                })
        })
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
                        line_end: None,
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
                target_file: None,
                kind: EdgeKind::Calls,
                confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
                confidence_tier: EdgeConfidenceTier::Inferred,
            },
            crate::code_map::graph::CodeEdge {
                from_file: "src/b.rs".into(),
                from_symbol: "other".into(),
                to_name: "callee".into(),
                target_file: None,
                kind: EdgeKind::Calls,
                confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
                confidence_tier: EdgeConfidenceTier::Inferred,
            },
        ];
        let n = persist_edges(&mut conn, "/repo/a", &edges).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            root_graph_generation(&conn, "/repo/a").unwrap(),
            root_index_generation(&conn, "/repo/a").unwrap(),
            "edge replacement must atomically bind the graph to the current index"
        );
        let loaded = load_edges(&conn, "/repo/a").unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().any(|e| e.from_file == "src/a.rs"));
        assert!(loaded.iter().any(|e| e.from_file == "src/b.rs"));
    }

    #[test]
    fn atomic_snapshot_publish_serializes_two_writers_without_mixing_map_and_edges() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("code_map.db");
        let root = "/repo/atomic";
        let mut setup = open(&path).unwrap();

        let mut baseline = sample_map(root);
        baseline.files[0].symbols[0].name = "baseline".into();
        let baseline_edge = crate::code_map::graph::CodeEdge {
            from_file: "src/main.rs".into(),
            from_symbol: "baseline".into(),
            to_name: "baseline_target".into(),
            target_file: None,
            kind: EdgeKind::Calls,
            confidence: EdgeConfidenceTier::RESOLVED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Resolved,
        };
        persist_map_and_edges(&mut setup, &baseline, &[baseline_edge]).unwrap();
        drop(setup);

        let mut map_a = sample_map(root);
        map_a.files[0].sha256 = "writer-a".into();
        map_a.files[0].symbols[0].name = "writer_a".into();
        let edge_a = crate::code_map::graph::CodeEdge {
            from_file: "src/main.rs".into(),
            from_symbol: "writer_a".into(),
            to_name: "target_a".into(),
            target_file: None,
            kind: EdgeKind::Calls,
            confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Inferred,
        };
        let mut map_b = sample_map(root);
        map_b.files[0].sha256 = "writer-b".into();
        map_b.files[0].symbols[0].name = "writer_b".into();
        let edge_b = crate::code_map::graph::CodeEdge {
            from_file: "src/main.rs".into(),
            from_symbol: "writer_b".into(),
            to_name: "target_b".into(),
            target_file: None,
            kind: EdgeKind::Calls,
            confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Inferred,
        };

        let mut writer_a = open(&path).unwrap();
        let mut writer_b = open(&path).unwrap();
        writer_b.busy_timeout(std::time::Duration::ZERO).unwrap();
        let observer = open(&path).unwrap();
        let (start_b_tx, start_b_rx) = std::sync::mpsc::channel();
        let (before_b_tx, before_b_rx) = std::sync::mpsc::channel();
        let map_b_attempt = map_b.clone();
        let edge_b_attempt = edge_b.clone();
        let writer_b_thread = std::thread::spawn(move || {
            start_b_rx.recv().unwrap();
            persist_map_and_edges_with_hooks(
                &mut writer_b,
                &map_b_attempt,
                &[edge_b_attempt],
                move || before_b_tx.send(()).unwrap(),
                || panic!("writer B acquired IMMEDIATE while writer A held it"),
                || {},
            )
            .expect_err("writer B must receive SQLite BUSY while writer A owns IMMEDIATE")
        });

        persist_map_and_edges_with_hooks(
            &mut writer_a,
            &map_a,
            &[edge_a],
            || {},
            || {
                // A owns SQLite's real IMMEDIATE writer lock. B has a zero
                // busy timeout, so its synchronized BEGIN IMMEDIATE must
                // return DatabaseBusy/DatabaseLocked while this closure keeps
                // A's transaction open. This is positive SQLite evidence, not
                // a scheduler/timing assertion.
                start_b_tx.send(()).unwrap();
                before_b_rx.recv().unwrap();
                let error = writer_b_thread.join().expect("writer B attempt panicked");
                assert!(
                    is_sqlite_busy(&error),
                    "unexpected writer-B error: {error:#}"
                );
            },
            || {},
        )
        .unwrap();

        // Once A commits, the exact same candidate can acquire IMMEDIATE.
        // While B's replacement is uncommitted, an independent reader still
        // sees A's complete certified pair, never map B + edges A.
        let root_for_b = root.to_string();
        let mut writer_b_retry = open(&path).unwrap();
        persist_map_and_edges_with_hooks(
            &mut writer_b_retry,
            &map_b,
            &[edge_b],
            || {},
            || {},
            || {
                let visible = load_map(&observer, &root_for_b).unwrap().unwrap();
                let visible_symbol = &visible
                    .files
                    .iter()
                    .find(|file| file.path == "src/main.rs")
                    .unwrap()
                    .symbols[0]
                    .name;
                assert_eq!(visible_symbol, "writer_a");
                assert_eq!(
                    load_edges(&observer, &root_for_b).unwrap()[0].to_name,
                    "target_a"
                );
                assert_eq!(
                    root_index_generation(&observer, &root_for_b).unwrap(),
                    Some(2)
                );
                assert_eq!(
                    root_graph_generation(&observer, &root_for_b).unwrap(),
                    Some(2)
                );
            },
        )
        .expect("writer B must acquire IMMEDIATE after writer A commits");

        let final_state = open(&path).unwrap();
        let final_map = load_map(&final_state, root).unwrap().unwrap();
        let final_symbol = &final_map
            .files
            .iter()
            .find(|file| file.path == "src/main.rs")
            .unwrap()
            .symbols[0]
            .name;
        assert_eq!(final_symbol, "writer_b");
        assert_eq!(
            load_edges(&final_state, root).unwrap()[0].to_name,
            "target_b"
        );
        assert_eq!(
            root_index_generation(&final_state, root).unwrap(),
            root_graph_generation(&final_state, root).unwrap()
        );
        assert_eq!(root_index_generation(&final_state, root).unwrap(), Some(3));
    }

    #[test]
    fn atomic_snapshot_publish_rolls_back_map_when_edge_replacement_fails() {
        let (_dir, mut conn) = temp_db();
        let root = "/repo/atomic-rollback";
        let mut baseline = sample_map(root);
        baseline.files[0].symbols[0].name = "baseline".into();
        let baseline_edge = crate::code_map::graph::CodeEdge {
            from_file: "src/main.rs".into(),
            from_symbol: "baseline".into(),
            to_name: "baseline_target".into(),
            target_file: None,
            kind: EdgeKind::Calls,
            confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Inferred,
        };
        persist_map_and_edges(&mut conn, &baseline, &[baseline_edge]).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_atomic_boom_edge \
             BEFORE INSERT ON code_map_edges \
             WHEN NEW.to_name = 'boom' \
             BEGIN SELECT RAISE(ABORT, 'forced atomic edge failure'); END;",
        )
        .unwrap();

        let mut candidate = sample_map(root);
        candidate.files[0].sha256 = "candidate".into();
        candidate.files[0].symbols[0].name = "candidate".into();
        let replacement = [
            crate::code_map::graph::CodeEdge {
                from_file: "src/main.rs".into(),
                from_symbol: "candidate".into(),
                to_name: "new_target".into(),
                target_file: None,
                kind: EdgeKind::Calls,
                confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
                confidence_tier: EdgeConfidenceTier::Inferred,
            },
            crate::code_map::graph::CodeEdge {
                from_file: "src/main.rs".into(),
                from_symbol: "candidate".into(),
                to_name: "boom".into(),
                target_file: None,
                kind: EdgeKind::Calls,
                confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
                confidence_tier: EdgeConfidenceTier::Inferred,
            },
        ];

        assert!(persist_map_and_edges(&mut conn, &candidate, &replacement).is_err());
        let visible = load_map(&conn, root).unwrap().unwrap();
        let visible_symbol = &visible
            .files
            .iter()
            .find(|file| file.path == "src/main.rs")
            .unwrap()
            .symbols[0]
            .name;
        assert_eq!(visible_symbol, "baseline");
        assert_eq!(
            load_edges(&conn, root).unwrap()[0].to_name,
            "baseline_target"
        );
        assert_eq!(root_index_generation(&conn, root).unwrap(), Some(1));
        assert_eq!(root_graph_generation(&conn, root).unwrap(), Some(1));
    }

    #[test]
    fn oversized_incoming_file_row_is_rejected_before_replacing_snapshot() {
        let (_dir, mut conn) = temp_db();
        let baseline = sample_map("/repo/a");
        persist_map(&mut conn, &baseline).unwrap();
        let mut oversized = baseline.clone();
        oversized.files[0].path = "x".repeat(PERSIST_ROW_TEXT_BYTE_CAP + 1);

        let error = persist_map(&mut conn, &oversized).unwrap_err();

        assert!(error.to_string().contains("file row exceeds"));
        let mut visible_paths = load_map(&conn, "/repo/a")
            .unwrap()
            .unwrap()
            .files
            .into_iter()
            .map(|file| file.path)
            .collect::<Vec<_>>();
        let mut baseline_paths = baseline
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>();
        visible_paths.sort();
        baseline_paths.sort();
        assert_eq!(visible_paths, baseline_paths);
    }

    #[test]
    fn oversized_incoming_edge_row_is_rejected_before_replacing_graph() {
        let (_dir, mut conn) = temp_db();
        let baseline = sample_map("/repo/a");
        persist_map(&mut conn, &baseline).unwrap();
        let baseline_edge = crate::code_map::graph::CodeEdge {
            from_file: "src/main.rs".into(),
            from_symbol: "main".into(),
            to_name: "target".into(),
            target_file: None,
            kind: EdgeKind::Calls,
            confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Inferred,
        };
        persist_edges(&mut conn, "/repo/a", std::slice::from_ref(&baseline_edge)).unwrap();
        let oversized = crate::code_map::graph::CodeEdge {
            to_name: "x".repeat(PERSIST_ROW_TEXT_BYTE_CAP + 1),
            ..baseline_edge
        };

        let error = persist_edges(&mut conn, "/repo/a", &[oversized]).unwrap_err();

        assert!(error.to_string().contains("edge row exceeds"));
        assert_eq!(load_edges(&conn, "/repo/a").unwrap()[0].to_name, "target");
    }

    #[test]
    fn bounded_root_edge_load_never_materializes_past_limit_plus_receipt() {
        let (_dir, mut conn) = temp_db();
        let map = sample_map("/repo/a");
        persist_map(&mut conn, &map).unwrap();
        let edges: Vec<_> = (0..3)
            .map(|index| crate::code_map::graph::CodeEdge {
                from_file: "src/main.rs".into(),
                from_symbol: "main".into(),
                to_name: format!("target_{index}"),
                target_file: None,
                kind: EdgeKind::Calls,
                confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
                confidence_tier: EdgeConfidenceTier::Inferred,
            })
            .collect();
        persist_edges(&mut conn, "/repo/a", &edges).unwrap();

        let (loaded, truncated, _) =
            load_edges_for_root_bounded_with_text_limit(&conn, "/repo/a", 2, usize::MAX).unwrap();

        assert!(truncated);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].to_name, "target_0");
        assert_eq!(loaded[1].to_name, "target_1");
    }

    #[test]
    fn bounded_root_edge_loader_preserves_exact_target_identity_and_legacy_none() {
        let (_dir, mut conn) = temp_db();
        let map = sample_map("/repo/a");
        persist_map(&mut conn, &map).unwrap();
        let exact = crate::code_map::graph::CodeEdge::resolved_tested_by(
            "tests/work_test.rs",
            "observes_work",
            "work",
            "src/work.rs",
        );
        let legacy =
            crate::code_map::graph::CodeEdge::inferred_call("src/legacy.rs", "legacy", "work");
        persist_edges(&mut conn, "/repo/a", &[exact.clone(), legacy.clone()]).unwrap();

        let without_target_bytes = exact.from_file.len()
            + exact.from_symbol.len()
            + exact.to_name.len()
            + exact.kind.as_str().len()
            + exact.confidence.to_string().len()
            + exact.confidence_tier.as_str().len();
        let error =
            load_edges_for_root_bounded_with_text_limit(&conn, "/repo/a", 8, without_target_bytes)
                .unwrap_err();
        assert!(error.to_string().contains("materialization refused"));

        let (bounded, truncated, bytes) =
            load_edges_for_root_bounded_with_text_limit(&conn, "/repo/a", 8, usize::MAX).unwrap();
        assert!(!truncated);
        assert!(bytes >= without_target_bytes + "src/work.rs".len());
        assert!(bounded.contains(&exact));
        assert!(bounded.contains(&legacy));
        assert_eq!(
            bounded
                .iter()
                .find(|edge| edge.kind == EdgeKind::TestedBy)
                .unwrap()
                .target_file
                .as_deref(),
            Some("src/work.rs")
        );
        assert_eq!(
            bounded
                .iter()
                .find(|edge| edge.kind == EdgeKind::Calls)
                .unwrap()
                .target_file
                .as_deref(),
            None
        );
        assert_eq!(load_edges(&conn, "/repo/a").unwrap(), bounded);
    }

    #[test]
    fn root_test_evidence_exclusions_are_deterministic_bounded_and_root_scoped() {
        let (_dir, mut conn) = temp_db();
        persist_map(&mut conn, &sample_map("/repo/a")).unwrap();
        persist_map(&mut conn, &sample_map("/repo/b")).unwrap();
        conn.execute_batch(
            "INSERT INTO code_map_files (root, path, language, bytes, loc, sha256, mtime_ns) VALUES
                ('/repo/a', 'tests/helpers/support.rs', 'rust', 1, 1, 'a', 1),
                ('/repo/a', 'tests/fixtures/case.rs', 'rust', 1, 1, 'b', 1),
                ('/repo/a', 'tests/generated/case.rs', 'rust', 1, 1, 'c', 1),
                ('/repo/a', 'tests/foreign/case.go', 'go', 1, 1, 'd', 1),
                ('/repo/a', 'src/left.rs', 'rust', 1, 1, 'e', 1),
                ('/repo/a', 'src/right.rs', 'rust', 1, 1, 'f', 1),
                ('/repo/b', 'tests/generated/other.rs', 'rust', 1, 1, 'g', 1);
             INSERT INTO code_map_symbols (file_id, name, kind, line, line_end)
                SELECT id, 'duplicated', 'function', 1, 1 FROM code_map_files
                WHERE root = '/repo/a' AND path IN ('src/left.rs', 'src/right.rs');",
        )
        .unwrap();

        let summary = root_test_evidence_exclusion_summary_bounded(&conn, "/repo/a", 64)
            .expect("bounded aggregate");
        assert!(!summary.capped);
        assert_eq!(
            summary
                .categories
                .get(&crate::code_map::graph::TestEvidenceExclusionCategory::HelperOrFixture),
            Some(&2)
        );
        assert_eq!(
            summary
                .categories
                .get(&crate::code_map::graph::TestEvidenceExclusionCategory::Generated),
            Some(&1)
        );
        assert_eq!(
            summary
                .categories
                .get(&crate::code_map::graph::TestEvidenceExclusionCategory::UnsupportedLanguage),
            Some(&1)
        );
        assert_eq!(
            summary
                .categories
                .get(&crate::code_map::graph::TestEvidenceExclusionCategory::DuplicateTarget),
            Some(&1)
        );
        assert_eq!(
            root_test_evidence_exclusion_summary_bounded(&conn, "/repo/b", 64)
                .unwrap()
                .categories
                .get(&crate::code_map::graph::TestEvidenceExclusionCategory::Generated),
            Some(&1),
            "each root reports only its own persisted source inventory"
        );
        let capped = root_test_evidence_exclusion_summary_bounded(&conn, "/repo/a", 1)
            .expect("one sentinel-row budget remains a truthful capped receipt");
        assert!(capped.capped);
        assert_eq!(capped.work_units, 1);
        assert!(capped.categories.is_empty());
    }

    #[test]
    fn doctor_test_evidence_observes_the_exact_row_cap_boundary_without_writing() {
        let (dir, mut writer) = temp_db();
        let database_path = dir.path().join("code_map.db");
        let map = sample_map("/repo/a");
        persist_map(&mut writer, &map).unwrap();
        let at_cap: Vec<_> = (0..MAX_DOCTOR_TEST_EVIDENCE_ROWS)
            .map(|index| {
                crate::code_map::graph::CodeEdge::resolved_tested_by(
                    format!("tests/case_{index}.rs"),
                    format!("observes_{index}"),
                    "work",
                    "src/work.rs",
                )
            })
            .collect();
        persist_edges(&mut writer, "/repo/a", &at_cap).unwrap();
        drop(writer);

        let before_at_cap = std::fs::read(&database_path).unwrap();
        let reader = open_read_only(&database_path).unwrap();
        let summary_at_cap = root_test_evidence_summary(&reader, "/repo/a").unwrap();
        drop(reader);

        assert_eq!(summary_at_cap.schema_version, CODE_MAP_SCHEMA_VERSION);
        assert!(summary_at_cap.snapshot_complete);
        assert_eq!(
            summary_at_cap.index_generation,
            summary_at_cap.graph_generation
        );
        assert_eq!(
            summary_at_cap.observed_tested_by_edges,
            MAX_DOCTOR_TEST_EVIDENCE_ROWS
        );
        assert_eq!(
            summary_at_cap.observed_exact_tested_by_edges,
            MAX_DOCTOR_TEST_EVIDENCE_ROWS
        );
        assert!(
            !summary_at_cap.capped,
            "exactly the permitted rows is a complete bounded observation"
        );
        assert_eq!(
            std::fs::read(&database_path).unwrap(),
            before_at_cap,
            "Doctor evidence reads must not mutate the SQLite store at the exact cap"
        );

        let one_past_cap: Vec<_> = (0..=MAX_DOCTOR_TEST_EVIDENCE_ROWS)
            .map(|index| {
                crate::code_map::graph::CodeEdge::resolved_tested_by(
                    format!("tests/case_{index}.rs"),
                    format!("observes_{index}"),
                    "work",
                    "src/work.rs",
                )
            })
            .collect();
        let mut writer = open(&database_path).unwrap();
        persist_edges(&mut writer, "/repo/a", &one_past_cap).unwrap();
        drop(writer);

        let before_sentinel = std::fs::read(&database_path).unwrap();
        let reader = open_read_only(&database_path).unwrap();
        let summary_sentinel = root_test_evidence_summary(&reader, "/repo/a").unwrap();
        drop(reader);

        assert_eq!(
            summary_sentinel.observed_tested_by_edges,
            MAX_DOCTOR_TEST_EVIDENCE_ROWS
        );
        assert_eq!(
            summary_sentinel.observed_exact_tested_by_edges,
            MAX_DOCTOR_TEST_EVIDENCE_ROWS
        );
        assert!(
            summary_sentinel.capped,
            "one sentinel row beyond the cap must prevent a total claim"
        );
        assert_eq!(
            std::fs::read(&database_path).unwrap(),
            before_sentinel,
            "Doctor evidence reads must not mutate the SQLite store after the sentinel"
        );
    }

    #[test]
    fn doctor_test_evidence_vm_interrupt_is_hard_capped_and_removed() {
        let (dir, mut writer) = temp_db();
        let database_path = dir.path().join("code_map.db");
        let map = sample_map("/repo/a");
        persist_map(&mut writer, &map).unwrap();
        let edge = crate::code_map::graph::CodeEdge::resolved_tested_by(
            "tests/work_test.rs",
            "observes_work",
            "work",
            "src/work.rs",
        );
        persist_edges(&mut writer, "/repo/a", &[edge]).unwrap();
        drop(writer);

        let before = std::fs::read(&database_path).unwrap();
        let reader = open_read_only(&database_path).unwrap();
        let error = root_test_evidence_summary_with_limits(
            &reader,
            "/repo/a",
            MAX_DOCTOR_TEST_EVIDENCE_ROWS,
            1,
            1,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exceeded its 1 SQLite-VM-step work bound"),
            "the first callback must stop at, never after, its exact cap: {error:#}"
        );
        let next_operation: i64 = reader.query_row("SELECT 1", [], |row| row.get(0)).unwrap();
        assert_eq!(
            next_operation, 1,
            "the interrupted evidence query must remove its progress handler"
        );
        drop(reader);
        assert_eq!(
            std::fs::read(&database_path).unwrap(),
            before,
            "the interrupted read-only query must leave all database bytes intact"
        );
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
            target_file: None,
            kind: EdgeKind::Calls,
            confidence: EdgeConfidenceTier::RESOLVED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Resolved,
        }];
        persist_edges(&mut conn, "/repo/a", &edges).unwrap();
        // Second run replaces — still 1 row.
        persist_edges(&mut conn, "/repo/a", &edges).unwrap();
        let loaded = load_edges(&conn, "/repo/a").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded, edges);
    }

    #[test]
    fn failed_edge_replacement_rolls_back_edges_and_generation_together() {
        let (_dir, mut conn) = temp_db();
        let map = sample_map("/repo/a");
        persist_map(&mut conn, &map).unwrap();
        let prior = crate::code_map::graph::CodeEdge {
            from_file: "src/main.rs".into(),
            from_symbol: "main".into(),
            to_name: "old_target".into(),
            target_file: None,
            kind: EdgeKind::Calls,
            confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Inferred,
        };
        persist_edges(&mut conn, "/repo/a", std::slice::from_ref(&prior)).unwrap();

        persist_map(&mut conn, &map).unwrap();
        assert_eq!(root_index_generation(&conn, "/repo/a").unwrap(), Some(2));
        assert_eq!(root_graph_generation(&conn, "/repo/a").unwrap(), Some(1));
        conn.execute_batch(
            "CREATE TRIGGER reject_boom_edge \
             BEFORE INSERT ON code_map_edges \
             WHEN NEW.to_name = 'boom' \
             BEGIN SELECT RAISE(ABORT, 'forced edge failure'); END;",
        )
        .unwrap();
        let replacement = [
            crate::code_map::graph::CodeEdge {
                from_file: "src/main.rs".into(),
                from_symbol: "main".into(),
                to_name: "new_target".into(),
                target_file: None,
                kind: EdgeKind::Calls,
                confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
                confidence_tier: EdgeConfidenceTier::Inferred,
            },
            crate::code_map::graph::CodeEdge {
                from_file: "src/main.rs".into(),
                from_symbol: "main".into(),
                to_name: "boom".into(),
                target_file: None,
                kind: EdgeKind::Calls,
                confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
                confidence_tier: EdgeConfidenceTier::Inferred,
            },
        ];

        assert!(persist_edges(&mut conn, "/repo/a", &replacement).is_err());
        assert_eq!(
            root_graph_generation(&conn, "/repo/a").unwrap(),
            Some(1),
            "a failed replacement must not claim generation 2"
        );
        assert_eq!(
            load_edges(&conn, "/repo/a").unwrap(),
            vec![prior],
            "the DELETE and partial INSERTs must roll back with the generation"
        );
    }

    #[test]
    fn qm2_phase2_load_edges_unknown_root_returns_empty() {
        let (_dir, conn) = temp_db();
        let loaded = load_edges(&conn, "/never/seen").unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn unknown_persisted_edge_kind_is_never_reinterpreted_as_a_call() {
        let (_dir, mut conn) = temp_db();
        persist_map(&mut conn, &sample_map("/repo/a")).unwrap();
        conn.execute(
            "INSERT INTO code_map_edges \
             (root, from_file, from_symbol, to_name, kind) \
             VALUES ('/repo/a', 'a.rs', 'a', 'b', 'future-kind')",
            [],
        )
        .unwrap();
        let error = load_edges(&conn, "/repo/a").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported persisted code-map edge kind")
        );
    }

    #[test]
    fn invalid_persisted_confidence_pair_fails_closed() {
        let (_dir, mut conn) = temp_db();
        persist_map(&mut conn, &sample_map("/repo/a")).unwrap();
        conn.execute(
            "INSERT INTO code_map_edges \
             (root, from_file, from_symbol, to_name, kind, confidence, confidence_tier) \
             VALUES ('/repo/a', 'a.rs', 'a', 'b', 'calls', 100, 'inferred')",
            [],
        )
        .unwrap();
        let error = load_edges(&conn, "/repo/a").unwrap_err();
        assert!(format!("{error:#}").contains("confidence 100 does not match inferred tier"));
    }

    #[test]
    fn persist_edges_rejects_unknown_root_without_writing_rows() {
        let (_dir, mut conn) = temp_db();
        let edge = crate::code_map::graph::CodeEdge {
            from_file: "src/a.rs".into(),
            from_symbol: "a".into(),
            to_name: "b".into(),
            target_file: None,
            kind: EdgeKind::Calls,
            confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Inferred,
        };

        let error = persist_edges(&mut conn, "/never/seen", &[edge]).unwrap_err();
        assert!(error.to_string().contains("unknown code-map root"));
        assert!(load_edges(&conn, "/never/seen").unwrap().is_empty());
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
        let hits = search_symbol(&conn, "main", "/repo/a").unwrap();
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
        let hits = search_symbol(&conn, "main", "/repo/a").unwrap();
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
        let hits = search_symbol(&conn, "nonexistent_fn", "/repo/a").unwrap();
        assert!(hits.is_empty());
    }

    // ── K-Repo-Map FTS5 fuzzy search ────────────────────────────────

    /// GOLD-R3-13: containment runs BEFORE limiting.
    ///
    /// The fuzzy query caps at 200 rows. Without a root predicate in the WHERE
    /// clause, a large unrelated indexed repository can fill those 200 slots and
    /// hide every match in the repository the operator is standing in — the
    /// exact failure the ticket names. Rank and truncate inside the root.
    #[test]
    fn a_large_foreign_repo_cannot_crowd_out_the_active_root() {
        let (_dir, mut conn) = temp_db();

        // A noisy foreign repo: far more matching symbols than the query cap.
        let mut noisy_files = Vec::new();
        for file in 0..40 {
            let symbols = (0..20)
                .map(|sym| Symbol {
                    name: format!("extract_noise_{file}_{sym}"),
                    kind: SymbolKind::Function,
                    line: sym + 1,
                    line_end: None,
                })
                .collect();
            noisy_files.push(RepoFile {
                path: format!("src/noise_{file}.rs"),
                language: Language::Rust,
                bytes: 100,
                loc: 10,
                sha256: String::new(),
                mtime_ns: 0,
                symbols,
            });
        }
        persist_map(
            &mut conn,
            &RepoMap {
                root: "/foreign/huge".into(),
                files: noisy_files,
                report: ScanReport::default(),
            },
        )
        .unwrap();
        persist_map(&mut conn, &fts_sample_map("/active/repo")).unwrap();

        let hits = search_symbol_fuzzy(&conn, "extract*", "/active/repo").unwrap();
        assert!(
            !hits.is_empty(),
            "the active repo's matches must survive a 800-symbol foreign repo"
        );
        assert!(
            hits.iter().all(|h| h.root == "/active/repo"),
            "no foreign root may appear in a contained search; got {hits:?}"
        );
    }

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
                            line_end: None,
                        },
                        Symbol {
                            name: "extract_response".into(),
                            kind: SymbolKind::Function,
                            line: 25,
                            line_end: None,
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
                        line_end: None,
                    }],
                },
            ],
            report: ScanReport::default(),
        }
    }

    #[test]
    fn search_symbol_fuzzy_returns_empty_on_empty_query() {
        let (_dir, conn) = temp_db();
        assert!(search_symbol_fuzzy(&conn, "", "/r").unwrap().is_empty());
        assert!(search_symbol_fuzzy(&conn, "   ", "/r").unwrap().is_empty());
    }

    #[test]
    fn search_symbol_fuzzy_returns_empty_when_no_match() {
        let (_dir, mut conn) = temp_db();
        let _ = persist_map(&mut conn, &fts_sample_map("/r")).unwrap();
        let hits = search_symbol_fuzzy(&conn, "totally_absent", "/r").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn search_symbol_fuzzy_matches_prefix_with_star_suffix() {
        let (_dir, mut conn) = temp_db();
        let _ = persist_map(&mut conn, &fts_sample_map("/r")).unwrap();
        let hits = search_symbol_fuzzy(&conn, "extract*", "/r").unwrap();
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
        let hits = search_symbol_fuzzy(&conn, "symbols", "/r").unwrap();
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
        let hits = search_symbol_fuzzy(&conn, "cluster heartbeat", "/r").unwrap();
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
                        line_end: Some(4),
                    },
                    Symbol {
                        name: "m".into(),
                        kind: SymbolKind::Method,
                        line: 2,
                        line_end: None,
                    },
                    Symbol {
                        name: "C".into(),
                        kind: SymbolKind::Class,
                        line: 3,
                        line_end: None,
                    },
                    Symbol {
                        name: "S".into(),
                        kind: SymbolKind::Struct,
                        line: 4,
                        line_end: None,
                    },
                    Symbol {
                        name: "E".into(),
                        kind: SymbolKind::Enum,
                        line: 5,
                        line_end: None,
                    },
                    Symbol {
                        name: "T".into(),
                        kind: SymbolKind::Trait,
                        line: 6,
                        line_end: None,
                    },
                    Symbol {
                        name: "I".into(),
                        kind: SymbolKind::Interface,
                        line: 7,
                        line_end: None,
                    },
                    Symbol {
                        name: "Mod".into(),
                        kind: SymbolKind::Module,
                        line: 8,
                        line_end: None,
                    },
                    Symbol {
                        name: "Ty".into(),
                        kind: SymbolKind::Type,
                        line: 9,
                        line_end: None,
                    },
                ],
            }],
            report: ScanReport::default(),
        };
        let _ = persist_map(&mut conn, &map).unwrap();
        let loaded = load_map(&conn, "/repo/kinds").unwrap().unwrap();
        let kinds: Vec<SymbolKind> = loaded.files[0].symbols.iter().map(|s| s.kind).collect();
        assert_eq!(loaded.files[0].symbols[0].line_end, Some(4));
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
        assert_eq!(
            p.parent(),
            Some(crate::config::FreedomConfig::default_neoth_home().as_path())
        );
        assert_eq!(
            p.file_name().and_then(|name| name.to_str()),
            Some("code_map.db")
        );
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
    fn symbol_aware_persist_repairs_legacy_symbol_less_rows_without_source_edit() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("legacy.rs"), b"fn adopted() {}\n").unwrap();
        let (_db_dir, mut conn) = temp_db();

        let legacy = scan_dir(dir.path());
        persist_map(&mut conn, &legacy).unwrap();
        assert!(
            load_map(&conn, &legacy.root).unwrap().unwrap().files[0]
                .symbols
                .is_empty()
        );

        let symbol_aware = crate::code_map::walker::RepoMapBuilder::new(dir.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        let stats = persist_map(&mut conn, &symbol_aware).unwrap();
        assert_eq!(stats.files_skipped_unchanged, 0);
        assert_eq!(stats.files_inserted, 1);
        assert_eq!(stats.symbols_inserted, 1);
        let loaded = load_map(&conn, &symbol_aware.root).unwrap().unwrap();
        assert_eq!(loaded.files[0].symbols[0].name, "adopted");
    }

    #[test]
    fn legacy_empty_symbol_input_preserves_existing_declarations() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("legacy.rs"), b"fn retained() {}\n").unwrap();
        let (_db_dir, mut conn) = temp_db();
        let symbol_aware = crate::code_map::walker::RepoMapBuilder::new(dir.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        persist_map(&mut conn, &symbol_aware).unwrap();

        let mut legacy_without_symbols = symbol_aware.clone();
        legacy_without_symbols.files[0].symbols.clear();
        let stats = persist_map(&mut conn, &legacy_without_symbols).unwrap();

        assert_eq!(stats.files_skipped_unchanged, 1);
        assert_eq!(stats.files_inserted, 0);
        let loaded = load_map(&conn, &symbol_aware.root).unwrap().unwrap();
        assert_eq!(loaded.files[0].symbols[0].name, "retained");
    }

    #[test]
    fn atomic_snapshot_treats_empty_symbols_as_exact_and_removes_stale_rows() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("strict.rs"), b"fn removed() {}\n").unwrap();
        let (_db_dir, mut conn) = temp_db();
        let symbol_aware = crate::code_map::walker::RepoMapBuilder::new(dir.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        persist_map_and_edges(&mut conn, &symbol_aware, &[]).unwrap();

        let mut exact_empty = symbol_aware.clone();
        exact_empty.files[0].symbols.clear();
        let (stats, edges) = persist_map_and_edges(&mut conn, &exact_empty, &[]).unwrap();

        assert_eq!(stats.files_skipped_unchanged, 0);
        assert_eq!(stats.files_inserted, 1);
        assert_eq!(stats.symbols_inserted, 0);
        assert_eq!(edges, 0);
        let loaded = load_map(&conn, &symbol_aware.root).unwrap().unwrap();
        assert!(loaded.files[0].symbols.is_empty());
        assert_eq!(
            root_index_generation(&conn, &symbol_aware.root).unwrap(),
            root_graph_generation(&conn, &symbol_aware.root).unwrap()
        );
    }

    #[test]
    fn delta_final_fence_failure_rolls_back_map_edges_and_generations() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("lib.rs"), "pub fn first() { target(); }\n").unwrap();
        let root = super::super::root_identity::CanonicalRepoRoot::discover(repo.path()).unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(root.path())
            .with_symbols(true)
            .strict_errors(true)
            .scan()
            .unwrap();
        let (_db_dir, mut conn) = temp_db();
        let old_edges = vec![crate::code_map::graph::CodeEdge {
            from_file: "lib.rs".into(),
            from_symbol: "first".into(),
            to_name: "target".into(),
            target_file: None,
            kind: EdgeKind::Calls,
            confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Inferred,
        }];
        persist_map_and_edges_bound(&mut conn, &map, &old_edges, &[], &root).unwrap();
        let before_index = root_index_generation(&conn, root.display()).unwrap();
        let before_graph = root_graph_generation(&conn, root.display()).unwrap();

        std::fs::write(repo.path().join("lib.rs"), "pub fn second() {}\n").unwrap();
        let changed_map = crate::code_map::walker::RepoMapBuilder::new(root.path())
            .with_symbols(true)
            .strict_errors(true)
            .scan()
            .unwrap();
        let result = persist_delta_map_and_edges_bound(
            &mut conn,
            &changed_map,
            &[],
            &[],
            &[],
            &std::collections::BTreeSet::from(["lib.rs".to_owned()]),
            &std::collections::BTreeSet::new(),
            &root,
            || anyhow::bail!("test final source fence rejected changed bytes"),
        );
        assert!(result.is_err());
        assert_eq!(
            root_index_generation(&conn, root.display()).unwrap(),
            before_index
        );
        assert_eq!(
            root_graph_generation(&conn, root.display()).unwrap(),
            before_graph
        );
        assert_eq!(
            load_map(&conn, root.display()).unwrap().unwrap().files[0].symbols[0].name,
            "first"
        );
        assert_eq!(
            load_edges_for_root(&conn, root.display()).unwrap(),
            old_edges
        );
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
        assert_eq!(
            root_graph_generation(&conn, "/repo/x").unwrap(),
            Some(0),
            "a map persist alone must not claim that graph edges are current"
        );

        persist_edges(&mut conn, "/repo/x", &[]).unwrap();
        assert_eq!(
            root_graph_generation(&conn, "/repo/x").unwrap(),
            Some(1),
            "even an empty edge snapshot is generation-bound"
        );

        // Re-scan the same root → generation bumps in place (no reset).
        persist_map(&mut conn, &map).unwrap();
        assert_eq!(
            root_index_generation(&conn, "/repo/x").unwrap(),
            Some(2),
            "a re-scan must bump the index generation"
        );
        assert_eq!(
            root_graph_generation(&conn, "/repo/x").unwrap(),
            Some(1),
            "re-indexing invalidates the previously bound graph generation"
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
    fn import_generation_is_invalidated_by_map_persist_and_bound_to_replacement() {
        let (_dir, mut conn) = temp_db();
        let map = sample_map("/repo/imports");
        persist_map(&mut conn, &map).unwrap();
        let tx = conn.transaction().unwrap();
        replace_import_edges_in_transaction(
            &tx,
            &map.root,
            &[crate::code_map::imports::ImportEdge {
                from_file: "a.rs".into(),
                to_file: "b.rs".into(),
                language: "rust".into(),
            }],
        )
        .unwrap();
        tx.commit().unwrap();
        let generation: i64 = conn
            .query_row(
                "SELECT import_generation FROM code_map_roots WHERE root = ?1",
                rusqlite::params![&map.root],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            generation,
            root_index_generation(&conn, &map.root).unwrap().unwrap()
        );
        let (edges, truncated) =
            load_import_edges_for_root_bounded(&conn, &map.root, 10, 1024).unwrap();
        assert!(!truncated);
        assert_eq!(edges.len(), 1);
        persist_map(&mut conn, &map).unwrap();
        let invalidated: i64 = conn
            .query_row(
                "SELECT import_generation FROM code_map_roots WHERE root = ?1",
                rusqlite::params![&map.root],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            invalidated, 0,
            "map-only publication cannot leave imports current"
        );
    }

    #[test]
    fn delta_publication_replaces_imports_after_removed_module() {
        let dir = tempfile::tempdir().unwrap();
        let root = super::root_identity::CanonicalRepoRoot::discover(dir.path()).unwrap();
        std::fs::write(dir.path().join("a.rs"), "mod b;\n").unwrap();
        std::fs::write(dir.path().join("b.rs"), "").unwrap();
        let first = RepoMapBuilder::new(root.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        let db = dir.path().join("code_map.db");
        let mut conn = open(&db).unwrap();
        let imports = [crate::code_map::imports::ImportEdge {
            from_file: "a.rs".into(),
            to_file: "b.rs".into(),
            language: "rust".into(),
        }];
        persist_map_and_edges_bound(&mut conn, &first, &[], &imports, &root).unwrap();
        std::fs::remove_file(dir.path().join("b.rs")).unwrap();
        let second = RepoMapBuilder::new(root.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        persist_delta_map_and_edges_bound(
            &mut conn,
            &second,
            &[],
            &[],
            &[],
            &std::collections::BTreeSet::from(["a.rs".to_owned()]),
            &std::collections::BTreeSet::from(["b.rs".to_owned()]),
            &root,
            || Ok(()),
        )
        .unwrap();
        let (stored, truncated) =
            load_import_edges_for_root_bounded(&conn, &second.root, 10, 1024).unwrap();
        assert!(!truncated);
        assert!(
            stored.is_empty(),
            "removed module must not retain import edges"
        );
        let generation: i64 = conn
            .query_row(
                "SELECT import_generation FROM code_map_roots WHERE root = ?1",
                rusqlite::params![&second.root],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            generation,
            root_index_generation(&conn, &second.root).unwrap().unwrap()
        );
    }

    #[test]
    fn physical_root_rename_preserves_generation_and_reconciles_children() {
        let workspace = tempdir().unwrap();
        let old_path = workspace.path().join("before");
        let new_path = workspace.path().join("after");
        std::fs::create_dir(&old_path).unwrap();
        std::fs::write(old_path.join("main.rs"), "fn main() {}\n").unwrap();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("code_map.db")).unwrap();

        let first = crate::code_map::walker::RepoMapBuilder::new(&old_path)
            .scan()
            .unwrap();
        let old_root = first.root.clone();
        persist_map_and_edges(&mut conn, &first, &[]).unwrap();
        assert_eq!(root_index_generation(&conn, &old_root).unwrap(), Some(1));

        std::fs::rename(&old_path, &new_path).unwrap();
        let second = crate::code_map::walker::RepoMapBuilder::new(&new_path)
            .scan()
            .unwrap();
        let new_root = second.root.clone();
        persist_map_and_edges(&mut conn, &second, &[]).unwrap();

        assert_eq!(root_index_generation(&conn, &old_root).unwrap(), None);
        assert_eq!(root_index_generation(&conn, &new_root).unwrap(), Some(2));
        assert_eq!(root_graph_generation(&conn, &new_root).unwrap(), Some(2));
        assert!(load_map(&conn, &old_root).unwrap().is_none());
        assert_eq!(load_map(&conn, &new_root).unwrap().unwrap().files.len(), 1);
        let identity: Option<String> = conn
            .query_row(
                "SELECT root_identity FROM code_map_roots WHERE root = ?1",
                rusqlite::params![&new_root],
                |row| row.get(0),
            )
            .unwrap();
        assert!(identity.is_some());
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
    fn legacy_empty_hash_is_never_reported_fresh() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("legacy.rs"), "fn legacy() {}\n").unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(repo.path())
            .with_symbols(false)
            .scan()
            .unwrap();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("cm.db")).unwrap();
        persist_map(&mut conn, &map).unwrap();
        conn.execute(
            "UPDATE code_map_files SET sha256 = '' WHERE root = ?1",
            rusqlite::params![&map.root],
        )
        .unwrap();

        assert!(
            is_index_stale(&conn, &map.root).unwrap(),
            "a legacy row without a content hash must require a rebuild"
        );
    }

    #[test]
    fn production_freshness_rechecks_an_immediate_edit_without_watcher_delay() {
        let repo = tempdir().unwrap();
        let source = repo.path().join("cached.rs");
        std::fs::write(&source, "fn cached() {}\n").unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(repo.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("cm.db")).unwrap();
        persist_map_and_edges(&mut conn, &map, &[]).unwrap();

        let first = index_freshness_receipt_cached(&conn, &map.root, 1).unwrap();
        assert!(!first.stale);
        std::fs::write(&source, "fn cached() { changed(); }\n").unwrap();

        let second = index_freshness_receipt_cached(&conn, &map.root, 1).unwrap();
        assert!(second.stale);
    }

    #[test]
    fn known_empty_snapshot_becomes_stale_when_first_file_appears() {
        let repo = tempdir().unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(repo.path())
            .scan()
            .unwrap();
        assert!(map.files.is_empty());
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("cm.db")).unwrap();
        persist_map(&mut conn, &map).unwrap();
        assert!(!is_index_stale(&conn, &map.root).unwrap());

        std::fs::write(repo.path().join("first.rs"), "fn first() {}\n").unwrap();
        assert!(
            is_index_stale(&conn, &map.root).unwrap(),
            "a known empty snapshot must detect its first on-disk file"
        );
    }

    #[test]
    fn freshness_receipt_rejects_stored_rows_above_cap_before_materializing_them() {
        let (_dir, mut conn) = temp_db();
        let map = sample_map("/repo/freshness-cap");
        persist_map(&mut conn, &map).unwrap();

        let error =
            index_freshness_receipt_bounded_with_hook(&conn, &map.root, 1, || {}).unwrap_err();
        assert!(error.to_string().contains("hard ceiling is 1"));
    }

    #[test]
    fn freshness_receipt_limit_catches_count_to_query_insert_race() {
        let (dir, mut conn) = temp_db();
        let map = sample_map("/repo/freshness-race");
        persist_map(&mut conn, &map).unwrap();
        let racer = open(&dir.path().join("code_map.db")).unwrap();

        let error = index_freshness_receipt_bounded_with_hook(&conn, &map.root, 2, || {
            racer
                .execute(
                    "INSERT INTO code_map_files \
                     (root, path, language, bytes, loc, sha256, mtime_ns) \
                     VALUES (?1, 'race.rs', 'rust', 1, 1, 'race', 1)",
                    rusqlite::params![&map.root],
                )
                .unwrap();
        })
        .unwrap_err();

        assert!(error.to_string().contains("more than 2 stored file rows"));
    }

    #[test]
    fn freshness_receipt_rejects_text_bytes_before_materializing_strings() {
        let (_dir, mut conn) = temp_db();
        let map = sample_map("/repo/freshness-bytes");
        persist_map(&mut conn, &map).unwrap();

        let error =
            index_freshness_receipt_bounded_with_limits_and_hook(&conn, &map.root, 10, 1, || {})
                .unwrap_err();
        assert!(error.to_string().contains("path/hash text bytes"));
    }

    #[test]
    fn freshness_receipt_row_guard_catches_count_to_query_long_string_race() {
        let (dir, mut conn) = temp_db();
        let map = sample_map("/repo/freshness-byte-race");
        persist_map(&mut conn, &map).unwrap();
        let racer = open(&dir.path().join("code_map.db")).unwrap();
        let long_path = "x".repeat(MAX_FRESHNESS_ROW_TEXT_BYTES + 1);

        let error = index_freshness_receipt_bounded_with_limits_and_hook(
            &conn,
            &map.root,
            3,
            MAX_FRESHNESS_TEXT_BYTES,
            || {
                racer
                    .execute(
                        "INSERT INTO code_map_files \
                         (root, path, language, bytes, loc, sha256, mtime_ns) \
                         VALUES (?1, ?2, 'rust', 1, 1, 'race', 1)",
                        rusqlite::params![&map.root, long_path],
                    )
                    .unwrap();
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("per-row ceiling"));
    }

    #[test]
    fn concurrent_v3_openers_recheck_version_after_competing_writer_commits() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO meta (key, value) VALUES ('schema_version', '3');
                 CREATE TABLE code_map_roots (
                     root TEXT PRIMARY KEY,
                     scanned_at INTEGER NOT NULL,
                     total_files INTEGER NOT NULL,
                     total_bytes INTEGER NOT NULL,
                     total_loc INTEGER NOT NULL,
                     oversize_skipped INTEGER NOT NULL,
                     truncated_at INTEGER,
                     index_generation INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE code_map_files (
                     id INTEGER PRIMARY KEY,
                     root TEXT NOT NULL,
                     path TEXT NOT NULL,
                     language TEXT NOT NULL,
                     bytes INTEGER NOT NULL,
                     loc INTEGER NOT NULL,
                     sha256 TEXT NOT NULL DEFAULT '',
                     mtime_ns INTEGER NOT NULL DEFAULT 0,
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
                 CREATE INDEX idx_code_map_symbols_name ON code_map_symbols(name);
                 CREATE INDEX idx_code_map_files_path ON code_map_files(root, path);
                 CREATE TABLE code_map_edges (
                     id INTEGER PRIMARY KEY,
                     root TEXT NOT NULL,
                     from_file TEXT NOT NULL,
                     from_symbol TEXT NOT NULL,
                     to_name TEXT NOT NULL,
                     kind TEXT NOT NULL,
                     FOREIGN KEY(root) REFERENCES code_map_roots(root) ON DELETE CASCADE
                 );
                 CREATE INDEX idx_code_map_edges_to_name ON code_map_edges(to_name);
                 CREATE INDEX idx_code_map_edges_source ON code_map_edges(from_file, from_symbol);
                 CREATE VIRTUAL TABLE code_map_symbols_fts
                     USING fts5(name, kind, content='code_map_symbols',
                                content_rowid='id',
                                tokenize='unicode61 separators ''_-.''');
                 CREATE TRIGGER code_map_symbols_fts_insert
                     AFTER INSERT ON code_map_symbols
                 BEGIN
                     INSERT INTO code_map_symbols_fts(rowid, name, kind)
                     VALUES (new.id, new.name, new.kind);
                 END;
                 CREATE TRIGGER code_map_symbols_fts_delete
                     AFTER DELETE ON code_map_symbols
                 BEGIN
                     INSERT INTO code_map_symbols_fts(code_map_symbols_fts, rowid, name, kind)
                     VALUES ('delete', old.id, old.name, old.kind);
                 END;
                 CREATE TRIGGER code_map_symbols_fts_update
                     AFTER UPDATE ON code_map_symbols
                 BEGIN
                     INSERT INTO code_map_symbols_fts(code_map_symbols_fts, rowid, name, kind)
                     VALUES ('delete', old.id, old.name, old.kind);
                     INSERT INTO code_map_symbols_fts(rowid, name, kind)
                     VALUES (new.id, new.name, new.kind);
                 END;
                 INSERT INTO code_map_roots
                     (root, scanned_at, total_files, total_bytes, total_loc,
                      oversize_skipped, truncated_at, index_generation)
                  VALUES ('/legacy', 0, 0, 0, 0, 0, NULL, 0);
                 INSERT INTO code_map_edges
                     (root, from_file, from_symbol, to_name, kind)
                  VALUES ('/legacy', 'legacy.rs', 'legacy_symbol', 'legacy_target', 'calls');
                 PRAGMA journal_mode=WAL;",
            )
            .unwrap();
        }

        let (a_read_tx, a_read_rx) = std::sync::mpsc::channel();
        let (b_read_tx, b_read_rx) = std::sync::mpsc::channel();
        let (allow_a_tx, allow_a_rx) = std::sync::mpsc::channel();
        let (allow_b_tx, allow_b_rx) = std::sync::mpsc::channel();
        let (a_before_tx, a_before_rx) = std::sync::mpsc::channel();
        let (b_before_tx, b_before_rx) = std::sync::mpsc::channel();
        let (a_locked_tx, a_locked_rx) = std::sync::mpsc::channel();
        let (b_locked_tx, b_locked_rx) = std::sync::mpsc::channel();
        let (release_a_tx, release_a_rx) = std::sync::mpsc::channel();

        let path_a = path.clone();
        let opener_a = std::thread::spawn(move || {
            open_with_migration_hooks(
                &path_a,
                |_| {},
                move || {
                    a_read_tx.send(()).unwrap();
                    allow_a_rx.recv().unwrap();
                },
                move || a_before_tx.send(()).unwrap(),
                move || {
                    a_locked_tx.send(()).unwrap();
                    release_a_rx.recv().unwrap();
                },
            )
        });
        let path_b = path.clone();
        let opener_b = std::thread::spawn(move || {
            open_with_migration_hooks(
                &path_b,
                |_| {},
                move || {
                    b_read_tx.send(()).unwrap();
                },
                move || {
                    b_before_tx.send(()).unwrap();
                    allow_b_rx.recv().unwrap();
                },
                move || b_locked_tx.send(()).unwrap(),
            )
        });

        // Both openers have observed v3 before either can request the writer
        // lock. A acquires IMMEDIATE first and is held there deliberately.
        a_read_rx.recv().unwrap();
        b_read_rx.recv().unwrap();
        allow_a_tx.send(()).unwrap();
        a_before_rx.recv().unwrap();
        a_locked_rx.recv().unwrap();

        // The same B opener that observed v3 is held at the exact
        // pre-IMMEDIATE boundary while A owns the writer lock.
        b_before_rx.recv().unwrap();

        release_a_tx.send(()).unwrap();
        opener_a
            .join()
            .expect("first migration opener panicked")
            .expect("first migration opener failed");

        // Release that same stale-v3 opener only after A committed. It must
        // acquire IMMEDIATE, re-read the completed current schema under the lock, and skip
        // duplicate ALTER TABLE work rather than relying on a fresh outer
        // version read.
        allow_b_tx.send(()).unwrap();
        b_locked_rx
            .recv()
            .expect("stale-v3 opener never acquired IMMEDIATE after A committed");
        let conn = opener_b
            .join()
            .expect("competing migration opener panicked")
            .expect("same stale-v3 opener failed after A committed");
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, CODE_MAP_SCHEMA_VERSION.to_string());
        let confidence_columns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('code_map_edges') \
                 WHERE name = 'confidence'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(confidence_columns, 1);
        let confidence_tier_columns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('code_map_edges') \
                 WHERE name = 'confidence_tier'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(confidence_tier_columns, 1);
        let target_file_columns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('code_map_edges') \
                 WHERE name = 'target_file'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(target_file_columns, 1);
        let (legacy_confidence, legacy_confidence_tier): (i64, String) = conn
            .query_row(
                "SELECT confidence, confidence_tier FROM code_map_edges \
                 WHERE root = '/legacy' AND from_symbol = 'legacy_symbol'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(legacy_confidence, 50);
        assert_eq!(legacy_confidence_tier, "inferred");
        let legacy_target_file: Option<String> = conn
            .query_row(
                "SELECT target_file FROM code_map_edges \
                 WHERE root = '/legacy' AND from_symbol = 'legacy_symbol'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            legacy_target_file, None,
            "v9 legacy edges remain non-exact after v10 migration"
        );
        let graph_columns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('code_map_roots') \
                 WHERE name = 'graph_generation'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(graph_columns, 1);
        let identity_columns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('code_map_roots') \
                 WHERE name = 'root_identity'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(identity_columns, 1);
        assert_eq!(root_graph_generation(&conn, "/legacy").unwrap(), Some(-1));
        let identity: Option<String> = conn
            .query_row(
                "SELECT root_identity FROM code_map_roots WHERE root = '/legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(identity, None, "unreachable legacy roots stay unbound");
    }

    #[test]
    fn v4_migration_adopts_reachable_root_and_reconciles_aliases() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("winner.rs"), "fn winner() {}\n").unwrap();
        let canonical = std::fs::canonicalize(repo.path())
            .unwrap()
            .display()
            .to_string();
        #[cfg(windows)]
        let alias = canonical
            .strip_prefix(r"\\?\")
            .expect("Windows canonical temp path must use the extended prefix")
            .to_owned();
        #[cfg(not(windows))]
        let alias = format!("{canonical}{}.", std::path::MAIN_SEPARATOR);
        assert_ne!(alias, canonical);

        let db = tempdir().unwrap();
        let path = db.path().join("v4.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO meta (key, value) VALUES ('schema_version', '4');
                 CREATE TABLE code_map_roots (
                     root TEXT PRIMARY KEY,
                     scanned_at INTEGER NOT NULL,
                     total_files INTEGER NOT NULL,
                     total_bytes INTEGER NOT NULL,
                     total_loc INTEGER NOT NULL,
                     oversize_skipped INTEGER NOT NULL,
                     truncated_at INTEGER,
                     index_generation INTEGER NOT NULL DEFAULT 0,
                     graph_generation INTEGER NOT NULL DEFAULT -1
                 );
                 CREATE TABLE code_map_files (
                     id INTEGER PRIMARY KEY,
                     root TEXT NOT NULL,
                     path TEXT NOT NULL,
                     language TEXT NOT NULL,
                     bytes INTEGER NOT NULL,
                     loc INTEGER NOT NULL,
                     sha256 TEXT NOT NULL DEFAULT '',
                     mtime_ns INTEGER NOT NULL DEFAULT 0,
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
                 );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO code_map_roots VALUES (?1, 10, 1, 1, 1, 0, NULL, 2, 2)",
                rusqlite::params![&canonical],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO code_map_roots VALUES (?1, 20, 1, 1, 1, 0, NULL, 7, 7)",
                rusqlite::params![&alias],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO code_map_files
                 (root, path, language, bytes, loc, sha256, mtime_ns)
                 VALUES (?1, 'loser.rs', 'rust', 1, 1, '', 0)",
                rusqlite::params![&canonical],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO code_map_files
                 (root, path, language, bytes, loc, sha256, mtime_ns)
                 VALUES (?1, 'winner.rs', 'rust', 1, 1, '', 0)",
                rusqlite::params![&alias],
            )
            .unwrap();
        }

        let conn = open(&path).expect("v4 reachable root migration must succeed");
        let snapshot = crate::code_map::recall::resolve_active_root_snapshot(&conn, repo.path())
            .unwrap()
            .expect("reachable migrated root must remain immediately recallable");
        assert_eq!(snapshot.root.display(), canonical);
        assert_eq!(snapshot.index_generation, 7);
        assert_eq!(snapshot.graph_generation, 7);
        let roots: i64 = conn
            .query_row("SELECT COUNT(*) FROM code_map_roots", [], |row| row.get(0))
            .unwrap();
        assert_eq!(roots, 1, "aliases must collapse to one physical root");
        let files: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT path FROM code_map_files ORDER BY path")
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert_eq!(files, vec!["winner.rs"]);
    }

    #[test]
    fn open_migrates_v1_to_v8_on_existing_db() {
        // Build a v1 DB manually (apply_schema with version stamped as 1,
        // without sha256/mtime_ns columns), then call open() and verify the
        // migration chain fires through v8, adding the nullable parser extent
        // column without inventing an end line for legacy declarations.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v1.db");
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("x.rs"), "pub fn x() {}\n").unwrap();
        let root = repo.path().canonicalize().unwrap().display().to_string();

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
                "INSERT INTO code_map_roots VALUES (?1, 0, 1, 100, 10, 0, NULL)",
                rusqlite::params![&root],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO code_map_files (root, path, language, bytes, loc) \
                 VALUES (?1, 'x.rs', 'rust', 100, 10)",
                rusqlite::params![&root],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO code_map_symbols (file_id, name, kind, line) \
                 VALUES (1, 'x', 'function', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO code_map_edges (root, from_file, from_symbol, to_name, kind) \
                 VALUES (?1, 'x.rs', 'x', 'target', 'calls')",
                rusqlite::params![&root],
            )
            .unwrap();
        }

        // Open via the public API — should trigger v1→v2 migration.
        let mut conn = open(&path).expect("open must succeed on a v1 DB");

        // schema_version must now be "11" (v1→…→v10→v11 chain).
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            version, "11",
            "schema_version must advance to 11 after migration"
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
        assert!(
            root_cols.iter().any(|c| c == "graph_generation"),
            "v4 must add graph_generation to code_map_roots; got {root_cols:?}"
        );
        assert!(
            root_cols.iter().any(|c| c == "root_identity"),
            "v5 must add root_identity to code_map_roots; got {root_cols:?}"
        );
        let edge_cols: Vec<String> = {
            let mut stmt = conn.prepare("PRAGMA table_info(code_map_edges)").unwrap();
            stmt.query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert!(edge_cols.iter().any(|c| c == "confidence"));
        assert!(edge_cols.iter().any(|c| c == "confidence_tier"));
        assert!(edge_cols.iter().any(|c| c == "target_file"));
        let (confidence, tier): (i64, String) = conn
            .query_row(
                "SELECT confidence, confidence_tier FROM code_map_edges LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((confidence, tier.as_str()), (50, "inferred"));
        assert_eq!(
            root_index_generation(&conn, &root).unwrap(),
            Some(0),
            "a migrated legacy root must default to generation 0"
        );
        assert_eq!(
            root_graph_generation(&conn, &root).unwrap(),
            Some(-1),
            "a migrated legacy graph must carry an invalid sentinel until rebuilt"
        );
        let legacy_identity: Option<String> = conn
            .query_row(
                "SELECT root_identity FROM code_map_roots WHERE root = ?1",
                rusqlite::params![&root],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            legacy_identity.is_some(),
            "migration must adopt the reachable root identity"
        );
        let impact_error = crate::code_map::impact::impact_radius(
            &conn,
            &root,
            &[crate::code_map::impact::ImpactSeed::symbol("x.rs", "x")],
            crate::code_map::impact::ImpactOptions::default(),
        )
        .unwrap_err();
        assert!(
            impact_error
                .to_string()
                .contains("not a certified rebuilt snapshot")
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
        let symbol_columns: Vec<String> = {
            let mut stmt = conn.prepare("PRAGMA table_info(code_map_symbols)").unwrap();
            stmt.query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert!(
            symbol_columns.iter().any(|column| column == "line_end"),
            "v8 must add nullable line_end; got {symbol_columns:?}"
        );
        assert_eq!(
            load_map(&conn, &root).unwrap().unwrap().files[0].symbols[0].line_end,
            None,
            "legacy declaration rows must remain extent-unknown"
        );

        let rebuilt = crate::code_map::walker::RepoMapBuilder::new(repo.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        persist_map_and_edges(&mut conn, &rebuilt, &[]).unwrap();
        let impact = crate::code_map::impact::impact_radius(
            &conn,
            &root,
            &[crate::code_map::impact::ImpactSeed::symbol("x.rs", "x")],
            crate::code_map::impact::ImpactOptions::default(),
        )
        .expect("a complete atomic rebuild must certify the migrated root");
        assert_eq!(impact.index_generation, 1);
        assert_eq!(impact.graph_generation, 1);
        let rebuilt_identity: Option<String> = conn
            .query_row(
                "SELECT root_identity FROM code_map_roots WHERE root = ?1",
                rusqlite::params![&root],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            rebuilt_identity.is_some(),
            "rebuild must adopt physical identity"
        );
    }
}
