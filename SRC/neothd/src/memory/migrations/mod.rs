//! Schema migration dispatcher.
//!
//! Phase 33a (AU-B4) — extracted before Phase 28a writes `SCHEMA_VERSION = 4`
//! because adding a fourth schema version without a registered dispatcher
//! would have meant every existing operator's `views.db` either silently
//! drops state on next open or panics. Neither is acceptable.
//!
//! ## Contract
//!
//! 1. `apply_schema(conn)` (in `memory::store`) creates the freshest schema
//!    from nothing — used for brand-new databases.
//! 2. `migrate(conn, current_version, target_version)` (here) runs the
//!    chain of [`Migration`]s between two versions, in order, transactionally.
//!    Each step is a closure that takes a `&Connection` and a `'static str`
//!    description and either succeeds or aborts the whole chain.
//! 3. The `MIGRATIONS` registry is the single source of truth for every
//!    schema change. New schema versions MUST append a migration; the
//!    `migrations_cover_every_version_step` test enforces this.
//!
//! Each migration runs in its own transaction so a partial failure leaves
//! the database at the previous version, not in a half-applied state.
//! After every successful step the `meta.schema_version` row is bumped to
//! match.

use anyhow::{Context, Result, anyhow};
use rusqlite::Connection;
use tracing::info;

/// A single schema upgrade step.
pub struct Migration {
    /// The schema version *before* this step runs.
    pub from: i64,
    /// The schema version *after* this step succeeds.
    pub to: i64,
    /// Short human description, surfaced in logs + audit trail.
    pub description: &'static str,
    /// Run the upgrade. Receives the connection with an open transaction
    /// (committed by the dispatcher on success, rolled back on failure).
    pub run: fn(&Connection) -> Result<()>,
}

/// Authoritative registry. Add new migrations here when bumping
/// `store::SCHEMA_VERSION`. Order matters — entries must be monotonically
/// `from < to` with no gaps.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        from: 3,
        to: 4,
        description: "Phase 28a R-22: add idx_consolidated + idx_longterm (memory tiers)",
        run: migration_v3_to_v4,
    },
    Migration {
        from: 4,
        to: 5,
        description: "Phase 28c R-24: add idx_groundtruth (immutable, decay-immune)",
        run: migration_v4_to_v5,
    },
    Migration {
        from: 5,
        to: 6,
        description: "R-9 vision Phase 2b: add idx_embedding (CLIP / future audio + text vectors)",
        run: migration_v5_to_v6,
    },
    Migration {
        from: 6,
        to: 7,
        description: "Phase 2 SPEC_proactive_learning: add idx_profile (Hypothalamus view)",
        run: migration_v6_to_v7,
    },
    Migration {
        from: 7,
        to: 8,
        description: "Phase 2 SPEC_profile_claim_guard H2: add idx_profile_redactions",
        run: migration_v7_to_v8,
    },
    Migration {
        from: 8,
        to: 9,
        description: "Pick #12 (Session 14): add idx_profile_outbox for WAL-first \
                      consistency in profile/apply.rs (ADR-002)",
        run: migration_v8_to_v9,
    },
    Migration {
        from: 9,
        to: 10,
        description: "ADV-03 item 4 (Session 24): add idx_profile_pending for \
                      operator-confirmation gate before profile delta apply",
        run: migration_v9_to_v10,
    },
    Migration {
        from: 10,
        to: 11,
        description: "M-05 (Session 24): pin idx_consolidated.day to ISO-8601 \
                      shape via CHECK constraint; normalise any non-conforming \
                      rows in flight from consolidated_ts",
        run: migration_v10_to_v11,
    },
    Migration {
        from: 11,
        to: 12,
        description: "NN-MEM-01: add idx_episode.pinned — decay-immune flag so \
                      critical memories skip the consolidation decay pass",
        run: migration_v11_to_v12,
    },
    Migration {
        from: 12,
        to: 13,
        description: "JV-MEM-05: add idx_episode.access_count — recall-frequency \
                      half-life extension (frequently-accessed memories decay slower)",
        run: migration_v12_to_v13,
    },
    Migration {
        from: 13,
        to: 14,
        description: "JV-MEM-09: add access_count to idx_consolidated + idx_longterm \
                      so recall frequency survives hot→warm→cold consolidation \
                      and an aged frequently-recalled row can re-promote in ranking",
        run: migration_v13_to_v14,
    },
    Migration {
        from: 14,
        to: 15,
        description: "JV-MEM-14: add idx_episode.trust — per-event source-trust tag \
                      that weights recall ranking (operator-explicit > external)",
        run: migration_v14_to_v15,
    },
    Migration {
        from: 15,
        to: 16,
        description: "GOLD-ADAPT-MEM-07: add idx_memory_links — Hebbian co-access \
                      association graph between memory rows (also back-fills the \
                      MEM-06 idx_entities/idx_relations on existing DBs)",
        run: migration_v15_to_v16,
    },
    Migration {
        from: 16,
        to: 17,
        description: "GOLD-ADAPT-MEM-15: add idx_recall_events — per-recall outcome \
                      samples (result/reinforcement counts + tier) for the \
                      recall-quality scorecard",
        run: migration_v16_to_v17,
    },
    Migration {
        from: 17,
        to: 18,
        description: "GOLD-ADAPT-MEM-01: add idx_groundtruth.fact_state + source_weight \
                      — fact trust state machine (existing rows default to 'verified'; \
                      only verified facts feed recall/council)",
        run: migration_v17_to_v18,
    },
    Migration {
        from: 18,
        to: 19,
        description: "GOLD-ADAPT-MEM-02: add idx_contradictions — contradiction \
                      detection ledger over ground-truth facts",
        run: migration_v18_to_v19,
    },
    Migration {
        from: 19,
        to: 20,
        description: "v20: idx_groundtruth.{confidence,evidence,maturity,confirmed_count} \
                      (JV-SELF-01 confidence loop / NN-MEM-03 evidence trails / NN-MEM-04 \
                      maturity labels) + idx_memory_links.{feedback_success,feedback_failure} \
                      (JV-MEM-08 Hebbian feedback)",
        run: migration_v19_to_v20,
    },
    Migration {
        from: 20,
        to: 21,
        description: "GOLD-ADAPT-ODY-26: add raw_turns + raw_turns_fts (raw-transcript FTS \
                      with before/after context rows via `neoth recall --transcript`)",
        run: migration_v20_to_v21,
    },
    Migration {
        from: 21,
        to: 22,
        description: "refines-JV-MEM-08: add idx_memory_links.stability — Ebbinghaus \
                      exponential edge decay (weight *= exp(-days/stability)) + Cepeda \
                      spacing parameter (stability += 0.1 on spaced accesses)",
        run: migration_v21_to_v22,
    },
    Migration {
        from: 22,
        to: 23,
        description: "refines-MEM-06: add idx_relations.valid_to TEXT — KG temporal \
                      invalidation column (NULL = active, non-NULL = closed timestamp). \
                      Superseded KG edges are stamped by invalidate_relation(); BFS \
                      one_hop filters to valid_to IS NULL so closed edges are invisible \
                      to recall. Wired into MEM-02 contradiction detector.",
        run: migration_v22_to_v23,
    },
    Migration {
        from: 23,
        to: 24,
        description: "G-02 CLUSTER-01: add idx_foreign_events — accepted gossip frames \
                      from paired peers (origin_peer_pk, origin_seq, event_type, payload, \
                      received_at). UNIQUE(origin_peer_pk, origin_seq) makes ingest \
                      idempotent. Separate from idx_episode: foreign ≠ operator truth.",
        run: migration_v23_to_v24,
    },
    Migration {
        from: 24,
        to: 25,
        description: "L6-PRELOAD-RESTRICTED-INDEX-01: add idx_restricted — physically \
                      separate table for exploit/payload corpora. Never read by the normal \
                      recall path; operator-attested promotion to idx_groundtruth is the \
                      only bridge (audited in ~/.neoth/promotion-audit.jsonl).",
        run: migration_v24_to_v25,
    },
];

/// v24 → v25: L6-PRELOAD-RESTRICTED-INDEX-01 — create `idx_restricted`.
///
/// Physically separate table for exploit/payload corpora ingested by
/// `neoth obsidian preload --ingest` when the manifest section carries a
/// restricted `risk_tier` (e.g. `dual-use-payloads`, `exploit-code`).
///
/// The normal recall path (`groundtruth::surface_for_recall` /
/// `groundtruth::list_for_scope`) NEVER references this table. Content
/// enters `idx_groundtruth` ONLY via explicit operator promotion
/// (`neoth obsidian promote <id>`) which stamps `promoted_at`/`promoted_by`
/// and appends an audit record to `~/.neoth/promotion-audit.jsonl`.
///
/// `CREATE TABLE IF NOT EXISTS` keeps the migration idempotent.
fn migration_v24_to_v25(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS idx_restricted (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            statement    TEXT    NOT NULL,
            source_name  TEXT    NOT NULL,
            scope        TEXT    NOT NULL,
            risk_tier    TEXT    NOT NULL,
            asserted_at  INTEGER NOT NULL,
            promoted_at  INTEGER,
            promoted_by  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_restricted_scope
            ON idx_restricted (scope);
        CREATE INDEX IF NOT EXISTS idx_restricted_risk_tier
            ON idx_restricted (risk_tier);
        CREATE INDEX IF NOT EXISTS idx_restricted_promoted
            ON idx_restricted (promoted_at);
        "#,
    )
    .context("migration_v24_to_v25: create idx_restricted")
}

/// v23 → v24: G-02 CLUSTER-01 — create `idx_foreign_events`.
///
/// Accepted gossip frames from paired peers land here after the band-filter
/// ACL passes in `cluster::wal_sync::GossipState::accept_inbound`. The table
/// is intentionally separate from `idx_episode` (foreign events are never
/// operator ground-truth). UNIQUE on `(origin_peer_pk, origin_seq)` makes
/// INSERT OR IGNORE idempotent: a re-gossiped frame is a silent no-op (the
/// conflict resolution v0 described in the wal_sync module doc).
fn migration_v23_to_v24(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS idx_foreign_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            origin_peer_pk  TEXT    NOT NULL,
            origin_seq      INTEGER NOT NULL,
            event_type      INTEGER NOT NULL,
            payload         BLOB    NOT NULL,
            received_at     INTEGER NOT NULL,
            UNIQUE (origin_peer_pk, origin_seq)
        );
        CREATE INDEX IF NOT EXISTS idx_foreign_events_peer
            ON idx_foreign_events (origin_peer_pk, received_at DESC);
        "#,
    )
    .context("migration_v23_to_v24: create idx_foreign_events")
}

/// v22 → v23: refines-MEM-06 — add `valid_to TEXT` to `idx_relations`.
///
/// NULL = the relation is currently active.
/// Non-NULL = an ISO-8601 or Unix-nanosecond string recording when the
/// relation was closed by `invalidate_relation`. Superseded KG edges are
/// invisible to recall BFS (`one_hop` filters `AND valid_to IS NULL`).
///
/// The `let _` idiom swallows the "duplicate column" error so re-running
/// this migration against a partially-migrated database is idempotent,
/// matching the pattern used by every prior migration.
fn migration_v22_to_v23(conn: &Connection) -> Result<()> {
    let _ = conn.execute(
        "ALTER TABLE idx_relations ADD COLUMN valid_to TEXT",
        [],
    );
    Ok(())
}

/// v21 → v22: refines-JV-MEM-08 — add `stability REAL NOT NULL DEFAULT 1.0`
/// to `idx_memory_links`. Existing edges default to stability=1.0 (same
/// 1-day half-life as the new formula default). The `let _` idiom swallows
/// the "duplicate column" error so re-running this migration against a
/// partially-migrated database is idempotent.
fn migration_v21_to_v22(conn: &Connection) -> Result<()> {
    let _ = conn.execute(
        "ALTER TABLE idx_memory_links ADD COLUMN stability REAL NOT NULL DEFAULT 1.0",
        [],
    );
    Ok(())
}

/// v20 → v21: GOLD-ADAPT-ODY-26 — add `raw_turns` + `raw_turns_fts` for
/// raw-transcript FTS with before/after context rows.
///
/// The `raw_turns` table starts empty on migration, so no FTS rebuild is
/// needed — the content-linked triggers keep the index current as rows land.
/// All DDL uses `IF NOT EXISTS` so re-running against a partially-migrated
/// database is idempotent.
fn migration_v20_to_v21(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS raw_turns (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT    NOT NULL,
            role       TEXT    NOT NULL CHECK (role IN ('operator', 'agent')),
            ts_unix    INTEGER NOT NULL,
            text       TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS raw_turns_session ON raw_turns (session_id, id);

        CREATE VIRTUAL TABLE IF NOT EXISTS raw_turns_fts USING fts5(
            text,
            content='raw_turns',
            content_rowid='id',
            tokenize='porter unicode61'
        );

        CREATE TRIGGER IF NOT EXISTS raw_turns_ai AFTER INSERT ON raw_turns BEGIN
            INSERT INTO raw_turns_fts(rowid, text) VALUES (new.id, new.text);
        END;

        CREATE TRIGGER IF NOT EXISTS raw_turns_ad AFTER DELETE ON raw_turns BEGIN
            INSERT INTO raw_turns_fts(raw_turns_fts, rowid, text)
                VALUES('delete', old.id, old.text);
        END;

        CREATE TRIGGER IF NOT EXISTS raw_turns_au AFTER UPDATE ON raw_turns BEGIN
            INSERT INTO raw_turns_fts(raw_turns_fts, rowid, text)
                VALUES('delete', old.id, old.text);
            INSERT INTO raw_turns_fts(rowid, text) VALUES (new.id, new.text);
        END;
        "#,
    )
    .context("v20→v21: create raw_turns + raw_turns_fts (ODY-26 raw-transcript FTS)")?;
    Ok(())
}

/// v11 → v12: add the `pinned` decay-immune flag to `idx_episode`.
/// Mirrors the canonical column in `store::apply_schema`. Idempotent —
/// re-running against a partially-migrated db ignores a duplicate column.
fn migration_v11_to_v12(conn: &Connection) -> Result<()> {
    let _ = conn.execute(
        "ALTER TABLE idx_episode ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
        [],
    );
    Ok(())
}

/// v12 → v13: add the `access_count` recall-frequency column to `idx_episode`
/// (GOLD-ADAPT-JV-MEM-05). Mirrors the canonical column in
/// `store::apply_schema`. Idempotent — re-running against a partially-migrated
/// db ignores the duplicate column.
fn migration_v12_to_v13(conn: &Connection) -> Result<()> {
    let _ = conn.execute(
        "ALTER TABLE idx_episode ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0",
        [],
    );
    Ok(())
}

/// v13 → v14: carry the recall-frequency `access_count` into the warm + cold
/// tiers (GOLD-ADAPT-JV-MEM-09) so a frequently-recalled memory keeps its count
/// through consolidation and can re-promote in ranking after ageing out of hot.
/// Mirrors the canonical columns in `store::apply_schema`. Idempotent — a
/// duplicate column on a partially-migrated db is ignored.
fn migration_v13_to_v14(conn: &Connection) -> Result<()> {
    let _ = conn.execute(
        "ALTER TABLE idx_consolidated ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE idx_longterm ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0",
        [],
    );
    Ok(())
}

/// v14 → v15: add the `trust` source-credibility tag to `idx_episode`
/// (GOLD-ADAPT-JV-MEM-14). Mirrors the canonical column in `store::apply_schema`.
/// Idempotent.
fn migration_v14_to_v15(conn: &Connection) -> Result<()> {
    let _ = conn.execute(
        "ALTER TABLE idx_episode ADD COLUMN trust INTEGER NOT NULL DEFAULT 1",
        [],
    );
    Ok(())
}

/// v15 → v16: create the MEM-07 `idx_memory_links` co-access association graph.
/// Also back-fills the MEM-06 `idx_entities`/`idx_relations` tables, which were
/// added to `apply_schema` without a migration — so an existing DB created at
/// v15 (which never re-runs `apply_schema`) gets them here. All
/// `CREATE … IF NOT EXISTS` → idempotent + backward-safe. SQL stays in sync with
/// `store::apply_schema`.
fn migration_v15_to_v16(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
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
        CREATE TABLE IF NOT EXISTS idx_memory_links (
            lo_id          INTEGER NOT NULL,
            hi_id          INTEGER NOT NULL,
            weight         REAL NOT NULL DEFAULT 1.0,
            last_co_access INTEGER NOT NULL DEFAULT 0,
            UNIQUE(lo_id, hi_id),
            CHECK(lo_id < hi_id)
        );
        CREATE INDEX IF NOT EXISTS idx_memory_links_lo ON idx_memory_links (lo_id);
        CREATE INDEX IF NOT EXISTS idx_memory_links_hi ON idx_memory_links (hi_id);
        CREATE INDEX IF NOT EXISTS idx_memory_links_weight ON idx_memory_links (weight DESC);
        "#,
    )
    .context("v15->v16: create idx_memory_links (+ back-fill MEM-06 graph tables)")?;
    Ok(())
}

/// v16 → v17: add `idx_recall_events` — per-recall outcome samples (result count,
/// reinforcement count, query tier) feeding the GOLD-ADAPT-MEM-15 recall-quality
/// scorecard. Mirrors the canonical table in `store::apply_schema`. Idempotent
/// (`CREATE TABLE IF NOT EXISTS`).
fn migration_v16_to_v17(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS idx_recall_events (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_unix          INTEGER NOT NULL,
            result_count     INTEGER NOT NULL,
            reinforced_count INTEGER NOT NULL,
            tier             TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_recall_events_id ON idx_recall_events (id DESC);
        "#,
    )
    .context("v16->v17: create idx_recall_events (recall-quality scorecard)")?;
    Ok(())
}

/// v17 → v18: add the fact-state machine columns to `idx_groundtruth`
/// (GOLD-ADAPT-MEM-01). `fact_state` defaults to `'verified'` so EVERY existing
/// row stays trusted + surfaced (backward-compat); only newly-inserted external
/// facts start as `'candidate'`. `source_weight` is a JSON `{source:count}` map.
/// Mirrors the canonical columns in `store::apply_schema`. Idempotent (the `let _`
/// swallows a duplicate-column error on a re-run).
fn migration_v17_to_v18(conn: &Connection) -> Result<()> {
    let _ = conn.execute(
        "ALTER TABLE idx_groundtruth ADD COLUMN fact_state TEXT NOT NULL DEFAULT 'verified'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE idx_groundtruth ADD COLUMN source_weight TEXT NOT NULL DEFAULT '{}'",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_groundtruth_state ON idx_groundtruth (fact_state)",
        [],
    );
    Ok(())
}

/// v18 → v19: add `idx_contradictions` — the GOLD-ADAPT-MEM-02 contradiction
/// detection ledger. Mirrors the canonical table in `store::apply_schema`.
/// Idempotent (`CREATE TABLE IF NOT EXISTS`).
fn migration_v18_to_v19(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
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
        CREATE INDEX IF NOT EXISTS idx_groundtruth_scope_state ON idx_groundtruth (scope, revoked_at, fact_state);
        "#,
    )
    .context("v18->v19: create idx_contradictions (contradiction ledger)")?;
    Ok(())
}

/// v19 → v20: fact-richness columns on `idx_groundtruth` (JV-SELF-01 confidence,
/// NN-MEM-03 evidence backlinks JSON, NN-MEM-04 maturity + confirmed_count) and
/// Hebbian feedback counters on `idx_memory_links` (JV-MEM-08). Existing rows
/// take the DEFAULTs (confidence 0.5, evidence '[]', maturity 'emerging',
/// counts 0) so nothing already stored changes meaning. Mirrors the canonical
/// columns in `store::apply_schema`. Idempotent (the `let _` swallows a
/// duplicate-column error on a re-run against a partially-migrated db).
fn migration_v19_to_v20(conn: &Connection) -> Result<()> {
    let _ = conn.execute(
        "ALTER TABLE idx_groundtruth ADD COLUMN confidence REAL NOT NULL DEFAULT 0.5",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE idx_groundtruth ADD COLUMN evidence TEXT NOT NULL DEFAULT '[]'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE idx_groundtruth ADD COLUMN maturity TEXT NOT NULL DEFAULT 'emerging'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE idx_groundtruth ADD COLUMN confirmed_count INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE idx_memory_links ADD COLUMN feedback_success INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE idx_memory_links ADD COLUMN feedback_failure INTEGER NOT NULL DEFAULT 0",
        [],
    );
    Ok(())
}

/// v3 → v4: add the two memory-tier views.
///
/// SQL stays in sync with `store::apply_schema`. For a fresh database
/// `apply_schema` creates these tables directly; for an existing v3 db this
/// function runs inside the migration transaction. The duplication is
/// intentional — `apply_schema` is the canonical "from scratch" path and a
/// migration that mutates the same shape must not call into it (mixing
/// schema versions in one transaction has bitten projects before).
fn migration_v3_to_v4(conn: &Connection) -> Result<()> {
    // ALTER TABLE in SQLite is fine for ADD COLUMN. Wrap each in a try
    // because the column may already exist when the migration is re-run
    // against a partially-migrated db (idempotency).
    let _ = conn.execute(
        "ALTER TABLE idx_episode ADD COLUMN importance REAL NOT NULL DEFAULT 0.5",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE idx_episode ADD COLUMN last_access_ts INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_episode_importance ON idx_episode (importance DESC)",
        [],
    );

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS idx_consolidated (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            kind            TEXT NOT NULL CHECK (kind IN ('summary', 'retained')),
            day             TEXT NOT NULL,
            event_id        INTEGER,
            text            TEXT NOT NULL,
            text_hash       TEXT NOT NULL,
            importance      REAL NOT NULL,
            consolidated_ts INTEGER NOT NULL,
            last_access_ts  INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_consolidated_day        ON idx_consolidated (day DESC);
        CREATE INDEX IF NOT EXISTS idx_consolidated_kind_day   ON idx_consolidated (kind, day DESC);
        CREATE INDEX IF NOT EXISTS idx_consolidated_importance ON idx_consolidated (importance DESC);
        CREATE INDEX IF NOT EXISTS idx_consolidated_event_id   ON idx_consolidated (event_id);

        CREATE TABLE IF NOT EXISTS idx_longterm (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id        INTEGER NOT NULL UNIQUE,
            text            TEXT NOT NULL,
            text_hash       TEXT NOT NULL,
            importance      REAL NOT NULL,
            promoted_ts     INTEGER NOT NULL,
            last_access_ts  INTEGER NOT NULL,
            archive_path    TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_longterm_importance ON idx_longterm (importance DESC);
        CREATE INDEX IF NOT EXISTS idx_longterm_event_id   ON idx_longterm (event_id);
        "#,
    )
    .context("v3→v4: create memory-tier tables")?;
    Ok(())
}

/// v5 → v6: add the embedding store (CLIP image embeddings, future
/// audio + text projections). Brute-force cosine search lives in
/// `memory::embeddings`; this migration only creates the table +
/// indexes.
fn migration_v5_to_v6(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
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
        "#,
    )
    .context("v5→v6: create idx_embedding")?;
    Ok(())
}

/// v6 → v7: add the user-profile materialised view. One row per
/// accepted `PROFILE_DELTA` WAL event the apply Effect Adapter emits.
/// `superseded_at` lets the profile-summary builder query the live
/// state cheaply; in v0.1 the apply path doesn't yet supersede (single-
/// shot append-only), so the column stays NULL until the contradiction-
/// resolver lands alongside reinforce/supersede event types.
fn migration_v6_to_v7(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
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
        "#,
    )
    .context("v6→v7: create idx_profile")?;
    Ok(())
}

/// v7 → v8: add the redaction registry (SPEC_profile_claim_guard H2).
fn migration_v7_to_v8(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
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
        "#,
    )
    .context("v7→v8: create idx_profile_redactions")?;
    Ok(())
}

/// v8 → v9: add the outbox table that closes the WAL-first consistency
/// hole in `profile/apply.rs` (Pick #12, Session 14, Codex-flagged).
///
/// Schema mirrors the version baked into `apply_schema` so fresh
/// databases and migrated databases reach the same shape.
fn migration_v8_to_v9(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
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
        "#,
    )
    .context("v8→v9: create idx_profile_outbox")?;
    Ok(())
}

/// v10 → v11: M-05 — table-rebuild `idx_consolidated` with a CHECK
/// constraint that pins `day` to ISO-8601 `YYYY-MM-DD` shape + valid
/// month/day ranges. Any pre-existing non-conforming row is normalised
/// in flight by re-deriving the day from `consolidated_ts` (nanoseconds
/// → unix seconds → `strftime('%Y-%m-%d', ..., 'unixepoch')`).
///
/// Rebuild is necessary because SQLite has no `ALTER TABLE ... ADD CHECK`.
/// The dance is: rename old → temp, create new with constraint, INSERT
/// SELECT through a normaliser CASE, drop temp, recreate indexes. The
/// whole sequence runs inside the migration's transaction so a partial
/// failure leaves the DB at v10 with `idx_consolidated` intact.
fn migration_v10_to_v11(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        ALTER TABLE idx_consolidated RENAME TO idx_consolidated_pre_v11;

        CREATE TABLE idx_consolidated (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            kind          TEXT NOT NULL CHECK (kind IN ('summary', 'retained')),
            day           TEXT NOT NULL CHECK (
                day GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]'
                AND CAST(substr(day, 6, 2) AS INTEGER) BETWEEN 1 AND 12
                AND CAST(substr(day, 9, 2) AS INTEGER) BETWEEN 1 AND 31
            ),
            event_id      INTEGER,
            text          TEXT NOT NULL,
            text_hash     TEXT NOT NULL,
            importance    REAL NOT NULL,
            consolidated_ts INTEGER NOT NULL,
            last_access_ts  INTEGER NOT NULL
        );

        -- Normalise bad day strings on the fly. SQLite's strftime with
        -- 'unixepoch' modifier converts the seconds-since-epoch to the
        -- canonical ISO-8601 date; consolidated_ts is nanoseconds so
        -- divide by 1_000_000_000 first.
        INSERT INTO idx_consolidated (
            id, kind, day, event_id, text, text_hash, importance,
            consolidated_ts, last_access_ts
        )
        SELECT
            id, kind,
            CASE
                WHEN day GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]'
                     AND CAST(substr(day, 6, 2) AS INTEGER) BETWEEN 1 AND 12
                     AND CAST(substr(day, 9, 2) AS INTEGER) BETWEEN 1 AND 31
                THEN day
                ELSE COALESCE(
                    strftime('%Y-%m-%d', consolidated_ts / 1000000000, 'unixepoch'),
                    '1970-01-01'
                )
            END AS day,
            event_id, text, text_hash, importance,
            consolidated_ts, last_access_ts
        FROM idx_consolidated_pre_v11;

        DROP TABLE idx_consolidated_pre_v11;

        CREATE INDEX IF NOT EXISTS idx_consolidated_day        ON idx_consolidated (day DESC);
        CREATE INDEX IF NOT EXISTS idx_consolidated_kind_day   ON idx_consolidated (kind, day DESC);
        CREATE INDEX IF NOT EXISTS idx_consolidated_importance ON idx_consolidated (importance DESC);
        CREATE INDEX IF NOT EXISTS idx_consolidated_event_id   ON idx_consolidated (event_id);
        "#,
    )
    .context("v10→v11: rebuild idx_consolidated with ISO-8601 CHECK + normalise day column")?;
    Ok(())
}

/// v9 → v10: ADV-03 item 4 — add `idx_profile_pending` so the
/// `approval_gate` (Stage 5b) can park operator-pending profile
/// deltas in daemon mode. `extraction_id UNIQUE` makes the gate
/// idempotent against duplicate-extract races (the same window
/// can't queue twice).
fn migration_v9_to_v10(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
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
    .context("v9→v10: create idx_profile_pending")?;
    Ok(())
}

/// v4 → v5: add the ground-truth view. Decay-immune, scope-tagged, revocable.
fn migration_v4_to_v5(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
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
        "#,
    )
    .context("v4→v5: create idx_groundtruth")?;
    Ok(())
}

/// Migrate `conn` from `current` up to `target`. No-op when already at or
/// above the target.
///
/// Returns the final version reached. On failure, the database is left at
/// the highest version that completed successfully — never half-applied.
pub fn migrate(conn: &mut Connection, current: i64, target: i64) -> Result<i64> {
    if current >= target {
        return Ok(current);
    }
    if current < 0 {
        return Err(anyhow!(
            "negative current schema version {} — refusing to migrate",
            current,
        ));
    }

    let mut achieved = current;
    let mut idx = 0usize;
    while achieved < target {
        let step = next_step_from(achieved).ok_or_else(|| {
            anyhow!(
                "no registered migration covers version {} → {} \
                 (target {}). Add an entry to MIGRATIONS.",
                achieved,
                achieved + 1,
                target,
            )
        })?;

        if step.to > target {
            // Don't overshoot: dispatcher should only step up to the caller's
            // explicit target. A migration crossing the boundary is a bug in
            // the registry (every Migration should advance by exactly 1).
            return Err(anyhow!(
                "migration #{} overshoots target {}: {} → {} ({})",
                idx,
                target,
                step.from,
                step.to,
                step.description,
            ));
        }

        info!(
            "schema migration {} → {}: {}",
            step.from, step.to, step.description,
        );

        let tx = conn.transaction().context("begin migration transaction")?;
        (step.run)(&tx).with_context(|| {
            format!(
                "run migration {} → {}: {}",
                step.from, step.to, step.description,
            )
        })?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?1)",
            [step.to.to_string()],
        )
        .context("stamp meta.schema_version after migration")?;
        tx.commit().context("commit migration transaction")?;

        achieved = step.to;
        idx += 1;
    }

    Ok(achieved)
}

/// Read the current schema version from `meta.schema_version`. Returns
/// `0` if the row is missing (fresh database / pre-v1 corpus) — and
/// only for that specific case. Every other DB error (locked, corrupt,
/// permission denied) propagates so the migration engine doesn't
/// silently re-apply migrations against a partially-set-up database.
///
/// Pick #32 (Session 14, audit-fix): the prior `.ok().unwrap_or(0)`
/// shape converted EVERY error to version 0, including real DB
/// failures that should abort the migration run. Now uses
/// `optional()` which is the canonical rusqlite pattern for
/// "QueryReturnedNoRows → None, every other error propagates".
pub fn current_version(conn: &Connection) -> Result<i64> {
    use rusqlite::OptionalExtension;
    let v: Option<i64> = conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .optional()
        .context("read schema_version from meta")?;
    Ok(v.unwrap_or(0))
}

fn next_step_from(from: i64) -> Option<&'static Migration> {
    MIGRATIONS.iter().find(|m| m.from == from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_with_meta(version: i64) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            .unwrap();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
            [version.to_string()],
        )
        .unwrap();
        conn
    }

    #[test]
    fn migrate_is_noop_when_already_at_target() {
        let mut conn = open_with_meta(3);
        let final_v = migrate(&mut conn, 3, 3).unwrap();
        assert_eq!(final_v, 3);
    }

    #[test]
    fn migrate_is_noop_when_above_target() {
        let mut conn = open_with_meta(5);
        let final_v = migrate(&mut conn, 5, 3).unwrap();
        assert_eq!(final_v, 5);
    }

    #[test]
    fn migrate_rejects_negative_current() {
        let mut conn = open_with_meta(0);
        let r = migrate(&mut conn, -1, 1);
        assert!(r.is_err());
    }

    #[test]
    fn migrate_errors_when_step_missing() {
        // Try to migrate beyond the registered chain end. Today v4 is the
        // highest registered target — anything past that must error rather
        // than silently succeed. Update the target as new migrations land.
        let mut conn = open_with_meta(MIGRATIONS.iter().map(|m| m.to).max().unwrap_or(0));
        let target = MIGRATIONS.iter().map(|m| m.to).max().unwrap_or(0) + 1;
        let r = migrate(&mut conn, target - 1, target);
        assert!(r.is_err(), "expected error when step missing, got {:?}", r);
        assert!(format!("{:?}", r).contains("no registered migration"));
    }

    #[test]
    fn current_version_returns_zero_when_meta_empty() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            .unwrap();
        assert_eq!(current_version(&conn).unwrap(), 0);
    }

    #[test]
    fn current_version_reads_stamp() {
        let conn = open_with_meta(7);
        assert_eq!(current_version(&conn).unwrap(), 7);
    }

    #[test]
    fn registry_includes_v3_to_v4() {
        // Phase 28a R-22 lands here. Regression guard: if anyone removes
        // the migration the test fails loudly before the schema bump
        // ships broken.
        assert!(
            MIGRATIONS.iter().any(|m| m.from == 3 && m.to == 4),
            "MIGRATIONS must contain v3→v4 (Phase 28a)",
        );
    }

    #[test]
    fn migrate_v3_to_v4_creates_memory_tier_tables() {
        // Bootstrap a v3 database, run the migration, verify the new
        // tables exist + the meta stamp advanced.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            .unwrap();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', '3')",
            [],
        )
        .unwrap();

        let final_v = migrate(&mut conn, 3, 4).expect("migrate v3→v4");
        assert_eq!(final_v, 4);

        // Tables must be queryable.
        let n_consolidated: i64 = conn
            .query_row("SELECT count(*) FROM idx_consolidated", [], |r| r.get(0))
            .expect("idx_consolidated exists");
        assert_eq!(n_consolidated, 0);
        let n_longterm: i64 = conn
            .query_row("SELECT count(*) FROM idx_longterm", [], |r| r.get(0))
            .expect("idx_longterm exists");
        assert_eq!(n_longterm, 0);

        // Stamp advanced.
        let stamped: i64 = conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stamped, 4);
    }

    /// Phase 33c BS-7 golden snapshot: build a v3-shape db with real
    /// rows, run the full migration chain, assert data preservation +
    /// new columns + every later table exists.
    #[test]
    fn migrate_full_chain_preserves_data_and_adds_columns() {
        let mut conn = Connection::open_in_memory().unwrap();
        // Build the v3 shape from scratch so the test catches forgotten
        // ALTER additions even when the rest of the schema is missing.
        conn.execute_batch(
            r#"
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO meta (key, value) VALUES ('schema_version', '3');
            CREATE TABLE idx_episode (
                event_id    INTEGER PRIMARY KEY,
                event_type  INTEGER NOT NULL,
                ts_ns       INTEGER NOT NULL,
                text        TEXT NOT NULL,
                text_hash   TEXT NOT NULL,
                channel     TEXT,
                sender_id   TEXT,
                operator_id TEXT
            );
            INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, channel, sender_id, operator_id)
                VALUES (1, 1, 1000, 'hello world', 'h1', 'cli', NULL, 'operator');
            INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash)
                VALUES (2, 1, 2000, 'second', 'h2');
            "#,
        )
        .unwrap();

        let target: i64 = MIGRATIONS.iter().map(|m| m.to).max().unwrap_or(3);
        let reached = migrate(&mut conn, 3, target).expect("migration chain");
        assert_eq!(reached, target, "chain should reach latest");

        // Pre-existing rows survive intact + ALTER defaults landed.
        let (id, text, imp, last_access): (i64, String, f64, i64) = conn
            .query_row(
                "SELECT event_id, text, importance, last_access_ts \
                 FROM idx_episode WHERE event_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("row 1 survives");
        assert_eq!(id, 1);
        assert_eq!(text, "hello world");
        assert!((imp - 0.5).abs() < 1e-6);
        assert_eq!(last_access, 0);
        let n: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2, "no row loss during ALTER");

        // Every later-version table exists and is queryable.
        for table in &["idx_consolidated", "idx_longterm"] {
            let n: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap_or_else(|e| panic!("table {table} missing: {e}"));
            assert_eq!(n, 0);
        }
        if target >= 5 {
            let n: i64 = conn
                .query_row("SELECT count(*) FROM idx_groundtruth", [], |r| r.get(0))
                .expect("idx_groundtruth must exist at v5+");
            assert_eq!(n, 0);
        }
    }

    /// Partial chain — caller stops at v4 even when v5 is registered.
    #[test]
    fn migrate_stops_at_explicit_intermediate_target() {
        let conn = open_with_meta(3);
        // Tables idx_episode etc. don't exist in this minimal fixture, but
        // the v3→v4 migration uses `IF NOT EXISTS` so it tolerates that.
        let mut conn = conn;
        let reached = migrate(&mut conn, 3, 4).expect("stop at v4");
        assert_eq!(reached, 4);

        let v5_exists: bool = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master \
                 WHERE type='table' AND name='idx_groundtruth'",
                [],
                |r| r.get::<_, i64>(0).map(|n| n > 0),
            )
            .unwrap();
        assert!(!v5_exists, "v5 must NOT run when target=4");
    }

    #[test]
    fn migrate_v3_to_v4_rejects_bad_kind_check_constraint() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            .unwrap();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', '3')",
            [],
        )
        .unwrap();
        migrate(&mut conn, 3, 4).expect("migrate");
        // The CHECK(kind IN ('summary','retained')) constraint must reject
        // anything else. Regression guard against accidental schema drift.
        let bad = conn.execute(
            "INSERT INTO idx_consolidated
                (kind, day, text, text_hash, importance,
                 consolidated_ts, last_access_ts)
             VALUES ('bogus', '2026-05-14', 't', 'h', 0.5, 0, 0)",
            [],
        );
        assert!(bad.is_err(), "CHECK constraint must reject unknown kind");
    }

    /// The registry must form a continuous chain — every version step
    /// between MIN(from) and MAX(to) must be covered exactly once.
    /// Catches gap bugs like "v3→v4 and v5→v6 but no v4→v5".
    #[test]
    fn migrations_have_no_gaps_and_no_duplicates() {
        let mut steps: Vec<(i64, i64)> = MIGRATIONS.iter().map(|m| (m.from, m.to)).collect();
        steps.sort();
        for w in steps.windows(2) {
            assert_eq!(
                w[0].1, w[1].0,
                "gap between migrations {:?} and {:?}",
                w[0], w[1],
            );
        }
        let froms: std::collections::HashSet<i64> = steps.iter().map(|(f, _)| *f).collect();
        assert_eq!(
            froms.len(),
            steps.len(),
            "duplicate `from` value in MIGRATIONS",
        );
        for m in MIGRATIONS {
            assert!(
                m.to == m.from + 1,
                "migration {} → {} must advance by exactly 1",
                m.from,
                m.to,
            );
        }
    }

    /// BS-7 (Phase 33c blind-spot): golden-snapshot regression for the full
    /// v3 → current migration chain.
    ///
    /// Builds a minimal v3-era schema from raw SQL (matches the v3 release
    /// shape: meta + wal_cursor + idx_episode WITHOUT the v4 columns + the
    /// ctx-mode tables that landed in v3), stamps `meta.schema_version = 3`,
    /// then runs the registered migration chain to the current target. Asserts:
    ///   - final version stamp matches `MIGRATIONS` head
    ///   - every post-v3 table is queryable (idx_consolidated, idx_longterm,
    ///     idx_groundtruth)
    ///   - idx_episode gained the v4 columns (importance + last_access_ts)
    ///   - pre-existing v3 rows survived the column ADD
    fn build_v3_era_schema(conn: &Connection) {
        conn.execute_batch(
            r#"
            CREATE TABLE meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE wal_cursor (
                segment_path TEXT PRIMARY KEY,
                next_offset  INTEGER NOT NULL,
                updated_ts   INTEGER NOT NULL
            );
            -- v3 idx_episode: no importance, no last_access_ts (those land in v4).
            CREATE TABLE idx_episode (
                event_id   INTEGER PRIMARY KEY,
                event_type INTEGER NOT NULL,
                ts_ns      INTEGER NOT NULL,
                text       TEXT NOT NULL,
                text_hash  TEXT NOT NULL,
                channel    TEXT,
                sender_id  TEXT,
                operator_id TEXT
            );
            CREATE TABLE idx_provider (
                event_id      INTEGER PRIMARY KEY,
                event_type    INTEGER NOT NULL,
                ts_ns         INTEGER NOT NULL,
                provider      TEXT NOT NULL,
                model         TEXT,
                text_hash     TEXT,
                bytes         INTEGER,
                latency_ns    INTEGER,
                input_tokens  INTEGER,
                output_tokens INTEGER
            );
            -- v3 ctx-mode tables. Schema kept terse for the fixture.
            CREATE TABLE sources (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                label           TEXT NOT NULL UNIQUE,
                content_hash    TEXT,
                file_path       TEXT,
                content_type    TEXT,
                source_category TEXT,
                chunk_count     INTEGER NOT NULL DEFAULT 0,
                indexed_ts      INTEGER NOT NULL
            );
            CREATE TABLE vocabulary (
                term      TEXT PRIMARY KEY,
                frequency INTEGER NOT NULL DEFAULT 1
            );
            "#,
        )
        .unwrap();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', '3')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn v3_era_schema_migrates_to_current_target() {
        let mut conn = Connection::open_in_memory().unwrap();
        build_v3_era_schema(&conn);

        // Seed one v3-era row so we can verify it survives the column ADD.
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, channel, sender_id, operator_id) \
             VALUES (42, 1, 1700000000000000000, 'survives migration', 'h', 'cli', 'operator', 'operator')",
            [],
        )
        .unwrap();

        let target = MIGRATIONS
            .iter()
            .map(|m| m.to)
            .max()
            .expect("registry non-empty");
        let achieved = migrate(&mut conn, 3, target).expect("v3 → current");
        assert_eq!(achieved, target, "must reach current head");

        // meta stamp advanced.
        let stamped = current_version(&conn).unwrap();
        assert_eq!(stamped, target);

        // Every post-v3 table must be queryable.
        for table in &["idx_consolidated", "idx_longterm", "idx_groundtruth"] {
            let _: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap_or_else(|e| panic!("post-v3 table {table} missing: {e}"));
        }

        // idx_episode gained the v4 columns + pre-existing row survived.
        let (text, importance, last_access): (String, f64, i64) = conn
            .query_row(
                "SELECT text, importance, last_access_ts \
                 FROM idx_episode WHERE event_id = 42",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("v3 row + v4 columns visible");
        assert_eq!(text, "survives migration");
        assert!((importance - 0.5).abs() < 1e-9, "DEFAULT 0.5 applied");
        assert_eq!(last_access, 0, "DEFAULT 0 applied");
    }

    // ── M-05 (Session 24) idx_consolidated.day CHECK constraint ───────

    #[test]
    fn fresh_schema_rejects_bad_day_shape() {
        // Fresh DB applies the v11 baseline directly; the CHECK must
        // reject anything that isn't ISO-8601 'YYYY-MM-DD'.
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("v.db")).unwrap();
        for bad in &[
            "2026/05/25",
            "May 25",
            "2026-13-01",
            "2026-05-32",
            "2026-5-1",
        ] {
            let r = conn.execute(
                "INSERT INTO idx_consolidated \
                 (kind, day, text, text_hash, importance, consolidated_ts, last_access_ts) \
                 VALUES ('retained', ?1, 't', 'h', 0.5, 0, 0)",
                [bad],
            );
            assert!(
                r.is_err(),
                "CHECK must reject {bad:?}, got {:?}",
                r.as_ref().map(|n| format!("rows affected: {n}")),
            );
        }
    }

    #[test]
    fn fresh_schema_accepts_iso_8601_day() {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("v.db")).unwrap();
        for ok in &["2026-05-25", "1970-01-01", "9999-12-31"] {
            let r = conn.execute(
                "INSERT INTO idx_consolidated \
                 (kind, day, text, text_hash, importance, consolidated_ts, last_access_ts) \
                 VALUES ('retained', ?1, 't', 'h', 0.5, 0, 0)",
                [ok],
            );
            assert!(r.is_ok(), "CHECK must accept {ok:?}: {:?}", r.err());
        }
    }

    #[test]
    fn migrate_v10_to_v11_normalises_bad_day_strings_from_consolidated_ts() {
        // Build a v10 DB with one good row + one bad-day row; run v10→v11;
        // verify the bad row's day got rewritten from consolidated_ts.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO meta (key, value) VALUES ('schema_version', '10');
            CREATE TABLE idx_consolidated (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                kind            TEXT NOT NULL CHECK (kind IN ('summary', 'retained')),
                day             TEXT NOT NULL,
                event_id        INTEGER,
                text            TEXT NOT NULL,
                text_hash       TEXT NOT NULL,
                importance      REAL NOT NULL,
                consolidated_ts INTEGER NOT NULL,
                last_access_ts  INTEGER NOT NULL
            );
            -- Good row: stays as-is.
            INSERT INTO idx_consolidated
                (kind, day, text, text_hash, importance, consolidated_ts, last_access_ts)
                VALUES ('retained', '2024-01-15', 'good', 'h1', 0.5,
                        1705276800000000000, 0);
            -- Bad row: malformed day, consolidated_ts encodes 2024-01-15
            -- (1_705_276_800 unix seconds × 1e9 ns).
            INSERT INTO idx_consolidated
                (kind, day, text, text_hash, importance, consolidated_ts, last_access_ts)
                VALUES ('retained', '15/01/2024', 'bad', 'h2', 0.5,
                        1705276800000000000, 0);
            "#,
        )
        .unwrap();

        let reached = migrate(&mut conn, 10, 11).expect("v10→v11");
        assert_eq!(reached, 11);

        let days: Vec<(String, String)> = conn
            .prepare("SELECT text, day FROM idx_consolidated ORDER BY id ASC")
            .unwrap()
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            days,
            vec![
                ("good".to_string(), "2024-01-15".to_string()),
                ("bad".to_string(), "2024-01-15".to_string()),
            ],
            "bad day must be rewritten from consolidated_ts",
        );

        // CHECK now active: post-migration INSERT with garbage must fail.
        let r = conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('retained', 'garbage', 't', 'h', 0.5, 0, 0)",
            [],
        );
        assert!(r.is_err(), "post-migration CHECK must reject 'garbage'");
    }

    /// BS-7 sibling: starting at v4 must climb cleanly to current (skipping the
    /// v3→v4 step). Catches a migration that secretly depends on v3-only state.
    #[test]
    fn v4_era_schema_migrates_to_current_target() {
        let mut conn = Connection::open_in_memory().unwrap();
        build_v3_era_schema(&conn);
        // Stamp + apply v3→v4 first to land in a "v4 era" state, then run the
        // remaining chain. This mirrors what an operator who upgraded
        // mid-stream sees on the second `neoth serve` after the v5 release.
        migrate(&mut conn, 3, 4).expect("v3 → v4 setup");
        let target = MIGRATIONS
            .iter()
            .map(|m| m.to)
            .max()
            .expect("registry non-empty");
        if target <= 4 {
            return; // No further chain registered yet — test is a no-op.
        }
        let achieved = migrate(&mut conn, 4, target).expect("v4 → current");
        assert_eq!(achieved, target);
        let stamped = current_version(&conn).unwrap();
        assert_eq!(stamped, target);
    }
}
