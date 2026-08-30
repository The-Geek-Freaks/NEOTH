//! SQLite-backed views over the WAL.
//!
//! Schema is opened idempotently — running `neoth serve` a second time
//! against an existing `~/.neoth/views.db` adds nothing if the schema is
//! current. Schema version tracked in `meta` table; future upgrades migrate
//! in-place.

use std::{
    ffi::OsString,
    fs::OpenOptions,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use rusqlite::Connection;

pub(crate) struct PrivateHistoryConnection {
    // Rust drops fields in declaration order: SQLite first, then the exact-file
    // fence, then the exact private-parent fence, and only then the retained
    // namespace/ancestor fence.
    connection: Connection,
    _file_fence: Option<std::fs::File>,
    #[cfg(windows)]
    _parent_fence: std::fs::File,
    _namespace_fence: crate::connectors::local_import::ApprovedImportRoot,
}

enum PreparedHistoryTarget {
    Generic,
    Existing(std::fs::File),
    Fresh(std::fs::File),
}

impl std::ops::Deref for PrivateHistoryConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl std::ops::DerefMut for PrivateHistoryConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

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
/// v35 binds the first operator resolution decision (`approve`/`decline`) to
///     the pending row before either path performs side effects. Retries may
///     resume the same decision; the opposite decision fails closed.
/// v36 creates the metadata-only transcript-mining provenance/outbox/revocation
///     foundation. Existing raw turns and WAL frames stay permanently
///     `legacy_unbound`: they are never inferred or backfilled into authority.
/// v37 adds the empty, fixed-header raw-frame plan used by a later authenticated
///     WAL read-back path. It stores no raw text or frame payload. Every
///     pre-v37 raw row receives plan epoch 0 and can never receive a plan.
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
/// v21: GOLD-ADAPT-ODY-26 — raw_turns table + raw_turns_fts FTS5 virtual table
///      (porter-stemmed, content-linked to raw_turns) for raw-transcript FTS
///      with before/after context rows. `neoth recall --transcript <query>`.
/// v22: refines-JV-MEM-08 — add `idx_memory_links.stability REAL DEFAULT 1.0`
///      for Ebbinghaus exponential edge decay (`weight *= exp(-days/stability)`)
///      and Cepeda spacing (`stability += 0.1` when access gap > spaced interval).
/// v23: refines-MEM-06 — add `idx_relations.valid_to TEXT` (NULL = active,
///      non-NULL = ISO-8601/Unix-ns string = relation closed at that timestamp).
///      Superseded KG edges are stamped via `invalidate_relation`; the BFS
///      `one_hop` filters to `valid_to IS NULL` so closed edges are invisible
///      to recall. The contradiction detector calls `invalidate_relation`
///      best-effort whenever a negation-contradiction or temporal-supersede
///      auto-resolution closes a ground-truth fact.
/// v25: L6-PRELOAD-RESTRICTED-INDEX-01 — add `idx_restricted`, a physically
///      separate table for exploit/payload corpora that must NEVER be read by
///      the normal recall path. Columns mirror `idx_groundtruth`'s chunk shape
///      plus `risk_tier`, `source_name`, `promoted_at`, `promoted_by`.
///      Operator-attested promotion to idx_groundtruth is the only bridge
///      (written by `neoth obsidian promote`, audited in
///      `~/.neoth/promotion-audit.jsonl`).
/// v26: GOLD-ADAPT-GRAPH-03 — add `idx_memory_communities` for persisted
///      Louvain assignments used by the recall community boost.
/// v27: OMI-MULTIMODAL-01 — add the durable OMI reconciliation ledger:
///      conversations, timestamp/speaker-aligned transcript segments, media
///      metadata, one-time action mappings, and poll/live-stream state. Raw
///      transcript text is nullable and is only populated when the operator's
///      explicit retention control is enabled; media bytes never land here.
/// v28: persist scope-qualified, canonical bulk-text identities so repeated
///      imports remain idempotent across processes and restarts. The complete
///      normalised statement is the equality guard; xxh3 is lookup-only.
/// v29: GOLD-R3-09 durable mesh synchronization state: per-peer ACK cursors,
///      exact pending frames, monotonic local origin sequences, contiguous
///      inbound high-water state, canonical foreign content and typed conflicts.
/// v30: durable operator resolution for typed mesh conflicts.
/// v31: bind inbound mesh receipts to the canonical full frame so a duplicate
///      cannot mutate its causal vector clock after the content was committed.
/// v32: persist the bounded, node-global mesh vector frontier independently of
///      per-destination delivery sequences.
/// v33: add the durable operator-requested mesh-sync queue. One coalesced row
///      per paired peer lets the CLI/GUI request an accelerated catch-up while
///      the daemon remains the only process that owns either live transport.
/// v34: fence live mesh state to one exact stable/auth/membership incarnation;
///      migrated v33 rows remain terminal `legacy_unbound` quarantine state.
/// v35: persist the first operator decision for a profile-resolution request.
/// v36: establish the sealed transcript-mining provenance prerequisite.
/// v37: add post-v37 exact raw-frame plans without promoting any v36 row.
pub const SCHEMA_VERSION: i64 = 37;

/// Current P1-08 metadata schema, split so the v36→v37 migration can rebuild
/// the altered strict tables before the final trigger set is installed.  The
/// plan retains a fixed 96-byte WAL *header* and its digest, never raw-frame
/// bytes or raw text.  Stage 3b must reproduce that header exactly, append it,
/// and authenticate a read-back before it marks the plan verified.
pub(crate) const TRANSCRIPT_MINING_V37_TABLES_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS transcript_mining_provenance (
        provenance_id          TEXT PRIMARY KEY NOT NULL
            CHECK(length(provenance_id) BETWEEN 1 AND 64 AND provenance_id NOT GLOB '*[^a-z0-9_-]*'),
        lifecycle_id           TEXT NOT NULL UNIQUE
            CHECK(length(lifecycle_id) BETWEEN 1 AND 64 AND lifecycle_id NOT GLOB '*[^a-z0-9_-]*'),
        raw_turn_id            INTEGER NOT NULL CHECK(raw_turn_id > 0),
        raw_session_sha256     BLOB NOT NULL CHECK(length(raw_session_sha256) = 32),
        raw_text_sha256        BLOB NOT NULL CHECK(length(raw_text_sha256) = 32),
        raw_role               TEXT NOT NULL CHECK(raw_role = 'operator'),
        source_kind            TEXT NOT NULL CHECK(source_kind = 'operator_raw_text_v1'),
        retention              TEXT NOT NULL CHECK(retention IN ('minutes15', 'hours24', 'days30')),
        lifecycle              TEXT NOT NULL DEFAULT 'pending'
            CHECK(lifecycle IN ('pending', 'active', 'revoked', 'cancelled', 'legacy_unbound')),
        created_at_unix        INTEGER NOT NULL,
        expires_at_unix        INTEGER NOT NULL CHECK(expires_at_unix > created_at_unix),
        revoked_at_unix        INTEGER,
        terminal_cause         TEXT CHECK(terminal_cause IS NULL OR terminal_cause IN (
            'raw_turn_deleted', 'operator_revoked', 'retention_expired'
        )),
        CHECK(
            (lifecycle IN ('pending', 'active', 'legacy_unbound')
                AND revoked_at_unix IS NULL AND terminal_cause IS NULL)
            OR (lifecycle IN ('revoked', 'cancelled') AND revoked_at_unix IS NOT NULL)
        )
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS transcript_mining_provenance_raw_turn
        ON transcript_mining_provenance(raw_turn_id);
    CREATE INDEX IF NOT EXISTS transcript_mining_provenance_lifecycle_expiry
        ON transcript_mining_provenance(lifecycle, expires_at_unix);

    CREATE TABLE IF NOT EXISTS transcript_mining_modern_raw_witness (
        raw_turn_id            INTEGER PRIMARY KEY NOT NULL CHECK(raw_turn_id > 0),
        subject_sha256         BLOB NOT NULL CHECK(length(subject_sha256) = 32),
        raw_role               TEXT NOT NULL CHECK(raw_role = 'operator'),
        source_kind            TEXT NOT NULL CHECK(source_kind = 'operator_raw_text_v1'),
        witnessed_at_unix      INTEGER NOT NULL
    ) STRICT;

    -- This is a prepare-time locator, not a physical frame claim.  The fixed
    -- header has no payload bytes; the SHA-256 below covers those 96 header
    -- bytes only.  Stage 3a reserves physical verification, delivery, and
    -- activation states but deliberately makes them unreachable: these
    -- candidate fields are not a substitute for an authenticated WAL reader.
    CREATE TABLE IF NOT EXISTS transcript_mining_raw_frame_plan (
        frame_plan_id                 TEXT PRIMARY KEY NOT NULL
            CHECK(length(frame_plan_id) BETWEEN 1 AND 64 AND frame_plan_id NOT GLOB '*[^a-z0-9_-]*'),
        provenance_id                 TEXT NOT NULL UNIQUE
            CHECK(length(provenance_id) BETWEEN 1 AND 64 AND provenance_id NOT GLOB '*[^a-z0-9_-]*'),
        lifecycle_id                  TEXT NOT NULL UNIQUE
            CHECK(length(lifecycle_id) BETWEEN 1 AND 64 AND lifecycle_id NOT GLOB '*[^a-z0-9_-]*'),
        raw_turn_id                   INTEGER NOT NULL UNIQUE CHECK(raw_turn_id > 0),
        raw_event_type                INTEGER NOT NULL CHECK(raw_event_type = 1),
        raw_event_subtype             INTEGER NOT NULL CHECK(raw_event_subtype = 0),
        planned_wal_format_version    INTEGER NOT NULL CHECK(planned_wal_format_version = 2),
        planned_event_schema_version  INTEGER NOT NULL CHECK(planned_event_schema_version = 4),
        planned_event_id              BLOB NOT NULL CHECK(length(planned_event_id) = 8),
        planned_hlc_physical_ns       BLOB NOT NULL CHECK(length(planned_hlc_physical_ns) = 8),
        planned_hlc_logical           INTEGER NOT NULL
            CHECK(planned_hlc_logical BETWEEN 0 AND 4294967295),
        planned_header                BLOB NOT NULL CHECK(length(planned_header) = 96),
        planned_header_sha256         BLOB NOT NULL UNIQUE CHECK(length(planned_header_sha256) = 32),
        state                         TEXT NOT NULL DEFAULT 'planned'
            CHECK(state IN ('planned', 'verified', 'cancelled')),
        raw_frame_sha256              BLOB CHECK(raw_frame_sha256 IS NULL OR length(raw_frame_sha256) = 32),
        planned_at_unix               INTEGER NOT NULL,
        raw_frame_delivered_at_unix   INTEGER,
        cancelled_at_unix             INTEGER,
        CHECK(
            (state = 'planned'
                AND raw_frame_sha256 IS NULL
                AND raw_frame_delivered_at_unix IS NULL
                AND cancelled_at_unix IS NULL)
            OR (state = 'verified'
                AND raw_frame_sha256 IS NOT NULL
                AND length(raw_frame_sha256) = 32
                AND raw_frame_delivered_at_unix IS NOT NULL
                AND cancelled_at_unix IS NULL)
            OR (state = 'cancelled'
                AND raw_frame_sha256 IS NULL
                AND raw_frame_delivered_at_unix IS NULL
                AND cancelled_at_unix IS NOT NULL)
        ),
        FOREIGN KEY(provenance_id) REFERENCES transcript_mining_provenance(provenance_id)
            DEFERRABLE INITIALLY DEFERRED
    ) STRICT;
    CREATE INDEX IF NOT EXISTS transcript_mining_raw_frame_plan_state
        ON transcript_mining_raw_frame_plan(state, planned_at_unix);
    CREATE UNIQUE INDEX IF NOT EXISTS transcript_mining_raw_frame_plan_locator
        ON transcript_mining_raw_frame_plan(
            planned_event_id, planned_hlc_physical_ns, planned_hlc_logical
        );

    -- The paired BEFORE/AFTER raw-turn delete triggers use this internal
    -- context row for one statement. A successful delete consumes it, and an
    -- aborted statement or transaction rolls it back. Its shape cannot alone
    -- authorize a terminal state while the raw row still exists.
    CREATE TABLE IF NOT EXISTS transcript_mining_delete_context (
        raw_turn_id            INTEGER PRIMARY KEY NOT NULL CHECK(raw_turn_id > 0),
        terminal_cause         TEXT NOT NULL CHECK(terminal_cause = 'raw_turn_deleted'),
        occurred_at_unix       INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS transcript_mining_revocation_receipts (
        receipt_id             TEXT PRIMARY KEY NOT NULL
            CHECK(length(receipt_id) BETWEEN 1 AND 96 AND receipt_id NOT GLOB '*[^a-z0-9_-]*'),
        provenance_id          TEXT NOT NULL
            CHECK(length(provenance_id) BETWEEN 1 AND 64 AND provenance_id NOT GLOB '*[^a-z0-9_-]*'),
        lifecycle_id           TEXT NOT NULL
            CHECK(length(lifecycle_id) BETWEEN 1 AND 64 AND lifecycle_id NOT GLOB '*[^a-z0-9_-]*'),
        raw_turn_id            INTEGER NOT NULL CHECK(raw_turn_id > 0),
        revocation             TEXT NOT NULL CHECK(revocation IN (
            'raw_turn_deleted', 'operator_revoked', 'retention_expired'
        )),
        lifecycle              TEXT NOT NULL CHECK(lifecycle IN ('revoked', 'cancelled')),
        occurred_at_unix       INTEGER NOT NULL
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS transcript_mining_revocation_once
        ON transcript_mining_revocation_receipts(provenance_id, revocation);

    CREATE TABLE IF NOT EXISTS transcript_mining_wal_outbox (
        outbox_id                  TEXT PRIMARY KEY NOT NULL
            CHECK(length(outbox_id) BETWEEN 1 AND 64 AND outbox_id NOT GLOB '*[^a-z0-9_-]*'),
        provenance_id              TEXT NOT NULL
            CHECK(length(provenance_id) BETWEEN 1 AND 64 AND provenance_id NOT GLOB '*[^a-z0-9_-]*'),
        lifecycle_id               TEXT NOT NULL
            CHECK(length(lifecycle_id) BETWEEN 1 AND 64 AND lifecycle_id NOT GLOB '*[^a-z0-9_-]*'),
        logical_subtype            TEXT NOT NULL CHECK(logical_subtype IN ('bound', 'revoked')),
        event_subtype              INTEGER NOT NULL CHECK(
            (logical_subtype = 'bound' AND event_subtype = 40)
            OR (logical_subtype = 'revoked' AND event_subtype = 41)
        ),
        payload                    BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 1024),
        payload_sha256             BLOB NOT NULL CHECK(length(payload_sha256) = 32),
        bound_payload_sha256       BLOB CHECK(bound_payload_sha256 IS NULL OR length(bound_payload_sha256) = 32),
        revocation_receipt_id      TEXT
            CHECK(revocation_receipt_id IS NULL OR (
                length(revocation_receipt_id) BETWEEN 1 AND 96
                AND revocation_receipt_id NOT GLOB '*[^a-z0-9_-]*'
            )),
        state                      TEXT NOT NULL DEFAULT 'pending'
            CHECK(state IN ('pending', 'delivered', 'cancelled')),
        enqueued_at_unix           INTEGER NOT NULL,
        delivered_at_unix          INTEGER,
        delivered_frame_sha256     BLOB CHECK(
            delivered_frame_sha256 IS NULL OR length(delivered_frame_sha256) = 32
        ),
        CHECK(
            (logical_subtype = 'bound'
                AND bound_payload_sha256 IS NULL AND revocation_receipt_id IS NULL)
            OR (logical_subtype = 'revoked'
                AND bound_payload_sha256 IS NOT NULL
                AND length(bound_payload_sha256) = 32
                AND revocation_receipt_id IS NOT NULL)
        ),
        CHECK(
            (state IN ('pending', 'cancelled')
                AND delivered_at_unix IS NULL AND delivered_frame_sha256 IS NULL)
            OR (state = 'delivered' AND delivered_at_unix IS NOT NULL)
        ),
        UNIQUE(provenance_id, logical_subtype),
        UNIQUE(lifecycle_id, logical_subtype),
        FOREIGN KEY(provenance_id) REFERENCES transcript_mining_provenance(provenance_id),
        FOREIGN KEY(revocation_receipt_id)
            REFERENCES transcript_mining_revocation_receipts(receipt_id)
    ) STRICT;
    CREATE INDEX IF NOT EXISTS transcript_mining_wal_outbox_pending
        ON transcript_mining_wal_outbox(state, enqueued_at_unix);
    CREATE INDEX IF NOT EXISTS transcript_mining_wal_outbox_provenance
        ON transcript_mining_wal_outbox(provenance_id, state);
    CREATE UNIQUE INDEX IF NOT EXISTS transcript_mining_wal_outbox_logical_subtype
        ON transcript_mining_wal_outbox(provenance_id, lifecycle_id, logical_subtype);
"#;

/// V37 trigger set. It deliberately grants no producer, append, attestation,
/// delivery, or activation capability: physical proof states are reserve-only
/// until a later connection-local/nonconstructible authority seam exists. It
/// only rejects invalid cross-table states and makes direct raw deletion
/// monotonic inside SQLite's transaction.
pub(crate) const TRANSCRIPT_MINING_V37_TRIGGERS_SQL: &str = r#"
    -- SQLite's OR REPLACE can delete a conflicting row without using the
    -- ordinary DELETE statement path. These explicit collision guards keep
    -- immutable authority/evidence from being replaced through that shortcut.
    --
    -- Stage 3a deliberately has no authenticated header constructor or
    -- canonical payload validator.  Do not let an ordinary SQLite client turn
    -- this reserved 96-byte locator field into an opaque side channel for raw
    -- text, subject identifiers, or secrets.  Stage 3b must replace this
    -- gate with its connection-local, nonconstructible attestation seam before
    -- it can create even a `planned` row.
    CREATE TRIGGER IF NOT EXISTS transcript_mining_plan_stage3a_reserved
    BEFORE INSERT ON transcript_mining_raw_frame_plan
    BEGIN
        SELECT RAISE(ABORT, 'stage 3a reserves raw frame plan creation for authenticated attestation');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_witness_no_replace
    BEFORE INSERT ON transcript_mining_modern_raw_witness
    WHEN EXISTS (
        SELECT 1 FROM transcript_mining_modern_raw_witness
        WHERE raw_turn_id = NEW.raw_turn_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'modern raw witness replacement forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_witness_raw_turn_exists
    BEFORE INSERT ON transcript_mining_modern_raw_witness
    WHEN NOT EXISTS (
        SELECT 1 FROM raw_turns
        WHERE id = NEW.raw_turn_id
          AND role = NEW.raw_role
          AND transcript_mining_authority_epoch = 1
          AND transcript_mining_raw_frame_plan_epoch = 1
    )
    BEGIN
        SELECT RAISE(ABORT, 'witness raw turn missing or pre-plan epoch');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_witness_immutable_update
    BEFORE UPDATE ON transcript_mining_modern_raw_witness
    BEGIN
        SELECT RAISE(ABORT, 'modern raw witness immutable');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_witness_immutable_delete
    BEFORE DELETE ON transcript_mining_modern_raw_witness
    BEGIN
        SELECT RAISE(ABORT, 'modern raw witness deletion forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_plan_no_replace
    BEFORE INSERT ON transcript_mining_raw_frame_plan
    WHEN EXISTS (
        SELECT 1 FROM transcript_mining_raw_frame_plan
        WHERE frame_plan_id = NEW.frame_plan_id
           OR provenance_id = NEW.provenance_id
           OR lifecycle_id = NEW.lifecycle_id
           OR raw_turn_id = NEW.raw_turn_id
           OR planned_header_sha256 = NEW.planned_header_sha256
           OR (planned_event_id = NEW.planned_event_id
               AND planned_hlc_physical_ns = NEW.planned_hlc_physical_ns
               AND planned_hlc_logical = NEW.planned_hlc_logical)
    )
    BEGIN
        SELECT RAISE(ABORT, 'raw frame plan replacement forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_plan_raw_turn_exists
    BEFORE INSERT ON transcript_mining_raw_frame_plan
    WHEN NEW.state <> 'planned'
      OR NEW.raw_frame_sha256 IS NOT NULL
      OR NEW.raw_frame_delivered_at_unix IS NOT NULL
      OR NEW.cancelled_at_unix IS NOT NULL
      OR NOT EXISTS (
          SELECT 1
          FROM raw_turns AS raw
          JOIN transcript_mining_modern_raw_witness AS witness
            ON witness.raw_turn_id = raw.id
          WHERE raw.id = NEW.raw_turn_id
            AND raw.role = witness.raw_role
            AND raw.role = 'operator'
            AND raw.transcript_mining_authority_epoch = 1
            AND raw.transcript_mining_raw_frame_plan_epoch = 1
            AND witness.source_kind = 'operator_raw_text_v1'
      )
    BEGIN
        SELECT RAISE(ABORT, 'raw frame plan requires prepared fresh witnessed raw turn');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_plan_immutable
    BEFORE UPDATE ON transcript_mining_raw_frame_plan
    WHEN NEW.frame_plan_id IS NOT OLD.frame_plan_id
      OR NEW.provenance_id IS NOT OLD.provenance_id
      OR NEW.lifecycle_id IS NOT OLD.lifecycle_id
      OR NEW.raw_turn_id IS NOT OLD.raw_turn_id
      OR NEW.raw_event_type IS NOT OLD.raw_event_type
      OR NEW.raw_event_subtype IS NOT OLD.raw_event_subtype
      OR NEW.planned_wal_format_version IS NOT OLD.planned_wal_format_version
      OR NEW.planned_event_schema_version IS NOT OLD.planned_event_schema_version
      OR NEW.planned_event_id IS NOT OLD.planned_event_id
      OR NEW.planned_hlc_physical_ns IS NOT OLD.planned_hlc_physical_ns
      OR NEW.planned_hlc_logical IS NOT OLD.planned_hlc_logical
      OR NEW.planned_header IS NOT OLD.planned_header
      OR NEW.planned_header_sha256 IS NOT OLD.planned_header_sha256
      OR NEW.planned_at_unix IS NOT OLD.planned_at_unix
      OR NOT (
          -- Stage 3a has no connection-local, nonconstructible WAL
          -- attestation capability.  It therefore permits only raw-delete
          -- cancellation here; Stage 3b must add that separate authority
          -- seam (or a later migration) before verified can become writable.
          (OLD.state = 'planned' AND NEW.state = 'cancelled'
              AND NEW.raw_frame_sha256 IS NULL
              AND NEW.raw_frame_delivered_at_unix IS NULL
              AND NEW.cancelled_at_unix IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM transcript_mining_provenance AS provenance
                  JOIN transcript_mining_revocation_receipts AS receipt
                    ON receipt.provenance_id = provenance.provenance_id
                   AND receipt.lifecycle_id = provenance.lifecycle_id
                   AND receipt.raw_turn_id = provenance.raw_turn_id
                   AND receipt.revocation = provenance.terminal_cause
                   AND receipt.lifecycle = provenance.lifecycle
                   AND receipt.occurred_at_unix = provenance.revoked_at_unix
                  WHERE provenance.provenance_id = OLD.provenance_id
                    AND provenance.lifecycle_id = OLD.lifecycle_id
                    AND provenance.raw_turn_id = OLD.raw_turn_id
                    AND provenance.lifecycle IN ('revoked', 'cancelled')
                    AND provenance.terminal_cause = 'raw_turn_deleted'
                    AND provenance.revoked_at_unix = NEW.cancelled_at_unix
              )
          )
      )
    BEGIN
        SELECT RAISE(ABORT, 'raw frame plan immutable or invalid transition');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_plan_immutable_delete
    BEFORE DELETE ON transcript_mining_raw_frame_plan
    BEGIN
        SELECT RAISE(ABORT, 'raw frame plan deletion forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_raw_turn_no_replace
    BEFORE INSERT ON raw_turns
    WHEN NEW.id IS NOT NULL AND NEW.id > 0 AND (
        EXISTS (
            SELECT 1 FROM transcript_mining_provenance
            WHERE raw_turn_id = NEW.id
        )
        OR EXISTS (
            SELECT 1 FROM transcript_mining_raw_frame_plan
            WHERE raw_turn_id = NEW.id
        )
        OR EXISTS (
            SELECT 1 FROM transcript_mining_modern_raw_witness
            WHERE raw_turn_id = NEW.id
        )
    )
    BEGIN
        SELECT RAISE(ABORT, 'mining-bound raw turn replacement forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_raw_turn_immutable
    BEFORE UPDATE OF id, text, session_id, role, ts_unix, transcript_mining_authority_epoch,
        transcript_mining_raw_frame_plan_epoch ON raw_turns
    WHEN EXISTS (
        SELECT 1 FROM transcript_mining_provenance
        WHERE raw_turn_id = OLD.id AND lifecycle IN ('pending', 'active')
    ) OR EXISTS (
        SELECT 1 FROM transcript_mining_raw_frame_plan
        WHERE raw_turn_id = OLD.id AND state IN ('planned', 'verified')
    )
    BEGIN
        SELECT RAISE(ABORT, 'bound or planned raw turn immutable');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_authority_epoch_immutable
    BEFORE UPDATE OF transcript_mining_authority_epoch,
        transcript_mining_raw_frame_plan_epoch ON raw_turns
    BEGIN
        SELECT RAISE(ABORT, 'raw turn mining epochs immutable');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_provenance_no_replace
    BEFORE INSERT ON transcript_mining_provenance
    WHEN EXISTS (
        SELECT 1 FROM transcript_mining_provenance
        WHERE provenance_id = NEW.provenance_id
           OR lifecycle_id = NEW.lifecycle_id
           OR raw_turn_id = NEW.raw_turn_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'mining provenance replacement forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_raw_turn_exists
    BEFORE INSERT ON transcript_mining_provenance
    WHEN NEW.lifecycle <> 'pending'
      OR NEW.terminal_cause IS NOT NULL
      OR NOT EXISTS (
          SELECT 1
          FROM raw_turns AS raw
          JOIN transcript_mining_modern_raw_witness AS witness
            ON witness.raw_turn_id = raw.id
          JOIN transcript_mining_raw_frame_plan AS plan
            ON plan.raw_turn_id = raw.id
          WHERE raw.id = NEW.raw_turn_id
            AND raw.role = NEW.raw_role
            AND raw.role = 'operator'
            AND raw.transcript_mining_authority_epoch = 1
            AND raw.transcript_mining_raw_frame_plan_epoch = 1
            AND witness.raw_role = NEW.raw_role
            AND witness.source_kind = NEW.source_kind
            AND plan.provenance_id = NEW.provenance_id
            AND plan.lifecycle_id = NEW.lifecycle_id
            AND plan.state = 'planned'
      )
    BEGIN
        SELECT RAISE(ABORT, 'provenance requires a fresh planned raw frame');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_binding_immutable
    BEFORE UPDATE OF provenance_id, lifecycle_id, raw_turn_id, raw_session_sha256,
        raw_text_sha256, raw_role, source_kind, retention, created_at_unix, expires_at_unix
    ON transcript_mining_provenance
    BEGIN
        SELECT RAISE(ABORT, 'mining binding immutable');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_lifecycle_fenced
    BEFORE UPDATE OF lifecycle, revoked_at_unix, terminal_cause
    ON transcript_mining_provenance
    WHEN (OLD.lifecycle = 'pending' AND NEW.lifecycle NOT IN ('pending', 'cancelled'))
      OR (OLD.lifecycle = 'active' AND NEW.lifecycle NOT IN ('active', 'revoked'))
      OR (OLD.lifecycle IN ('revoked', 'cancelled', 'legacy_unbound')
          AND (NEW.lifecycle <> OLD.lifecycle
               OR NEW.revoked_at_unix IS NOT OLD.revoked_at_unix
               OR NEW.terminal_cause IS NOT OLD.terminal_cause))
      OR (NEW.lifecycle IN ('pending', 'active')
          AND (NEW.revoked_at_unix IS NOT NULL OR NEW.terminal_cause IS NOT NULL))
      OR (NEW.lifecycle IN ('revoked', 'cancelled') AND (
          NEW.terminal_cause IS NULL
          OR NEW.terminal_cause <> 'raw_turn_deleted'
          OR EXISTS (SELECT 1 FROM raw_turns WHERE id = NEW.raw_turn_id)
          OR NOT EXISTS (
              SELECT 1 FROM transcript_mining_delete_context
              WHERE raw_turn_id = NEW.raw_turn_id
                AND terminal_cause = NEW.terminal_cause
                AND occurred_at_unix = NEW.revoked_at_unix
          )
      ))
      -- Stage 3a reserves `active` for a future authenticated attestation
      -- writer; ordinary SQLite updates cannot create it.
    BEGIN
        SELECT RAISE(ABORT, 'mining lifecycle transition forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_delete_context_raw_turn_exists
    BEFORE INSERT ON transcript_mining_delete_context
    WHEN NOT EXISTS (SELECT 1 FROM raw_turns WHERE id = NEW.raw_turn_id)
    BEGIN
        SELECT RAISE(ABORT, 'delete context requires extant raw turn');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_delete_context_immutable
    BEFORE UPDATE ON transcript_mining_delete_context
    BEGIN
        SELECT RAISE(ABORT, 'delete context immutable');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_receipt_binding_matches
    BEFORE INSERT ON transcript_mining_revocation_receipts
    WHEN NOT EXISTS (
        SELECT 1
        FROM transcript_mining_provenance AS provenance
        JOIN transcript_mining_delete_context AS context
          ON context.raw_turn_id = provenance.raw_turn_id
         AND context.terminal_cause = provenance.terminal_cause
         AND context.occurred_at_unix = provenance.revoked_at_unix
        WHERE provenance.provenance_id = NEW.provenance_id
          AND provenance.lifecycle_id = NEW.lifecycle_id
          AND provenance.raw_turn_id = NEW.raw_turn_id
          AND provenance.lifecycle = NEW.lifecycle
          AND provenance.terminal_cause = NEW.revocation
          AND provenance.revoked_at_unix = NEW.occurred_at_unix
          AND provenance.lifecycle IN ('revoked', 'cancelled')
          AND NOT EXISTS (SELECT 1 FROM raw_turns WHERE id = NEW.raw_turn_id)
    )
    BEGIN
        SELECT RAISE(ABORT, 'receipt requires matching transaction-local terminal cause');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_receipt_no_replace
    BEFORE INSERT ON transcript_mining_revocation_receipts
    WHEN EXISTS (
        SELECT 1 FROM transcript_mining_revocation_receipts
        WHERE receipt_id = NEW.receipt_id
           OR (provenance_id = NEW.provenance_id
               AND revocation = NEW.revocation)
    )
    BEGIN
        SELECT RAISE(ABORT, 'revocation receipt replacement forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_receipt_immutable
    BEFORE UPDATE ON transcript_mining_revocation_receipts
    BEGIN
        SELECT RAISE(ABORT, 'revocation receipt immutable');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_receipt_immutable_delete
    BEFORE DELETE ON transcript_mining_revocation_receipts
    BEGIN
        SELECT RAISE(ABORT, 'revocation receipt deletion forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_outbox_no_replace
    BEFORE INSERT ON transcript_mining_wal_outbox
    WHEN EXISTS (
        SELECT 1 FROM transcript_mining_wal_outbox
        WHERE outbox_id = NEW.outbox_id
           OR (provenance_id = NEW.provenance_id
               AND logical_subtype = NEW.logical_subtype)
           OR (lifecycle_id = NEW.lifecycle_id
               AND logical_subtype = NEW.logical_subtype)
    )
    BEGIN
        SELECT RAISE(ABORT, 'mining outbox replacement forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_outbox_bound_admission
    BEFORE INSERT ON transcript_mining_wal_outbox
    WHEN NEW.logical_subtype = 'bound' AND (
        NEW.state <> 'pending'
        OR NEW.delivered_at_unix IS NOT NULL
        OR NEW.delivered_frame_sha256 IS NOT NULL
        OR NEW.bound_payload_sha256 IS NOT NULL
        OR NEW.revocation_receipt_id IS NOT NULL
        OR NOT EXISTS (
            SELECT 1
            FROM transcript_mining_provenance AS provenance
            JOIN transcript_mining_raw_frame_plan AS plan
              ON plan.provenance_id = provenance.provenance_id
             AND plan.lifecycle_id = provenance.lifecycle_id
             AND plan.raw_turn_id = provenance.raw_turn_id
            WHERE provenance.provenance_id = NEW.provenance_id
              AND provenance.lifecycle_id = NEW.lifecycle_id
              AND provenance.lifecycle IN ('pending', 'active')
              AND provenance.terminal_cause IS NULL
              AND provenance.expires_at_unix > CAST(strftime('%s','now') AS INTEGER)
              AND plan.state = 'verified'
              AND length(plan.raw_frame_sha256) = 32
        )
    )
    BEGIN
        SELECT RAISE(ABORT, 'bound outbox requires verified live binding');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_outbox_revoked_admission
    BEFORE INSERT ON transcript_mining_wal_outbox
    WHEN NEW.logical_subtype = 'revoked' AND (
        NEW.state <> 'pending'
        OR NEW.delivered_at_unix IS NOT NULL
        OR NEW.delivered_frame_sha256 IS NOT NULL
        OR NOT EXISTS (
            SELECT 1
            FROM transcript_mining_provenance AS provenance
            JOIN transcript_mining_revocation_receipts AS receipt
              ON receipt.receipt_id = NEW.revocation_receipt_id
             AND receipt.provenance_id = provenance.provenance_id
             AND receipt.lifecycle_id = provenance.lifecycle_id
             AND receipt.raw_turn_id = provenance.raw_turn_id
             AND receipt.lifecycle = provenance.lifecycle
             AND receipt.revocation = provenance.terminal_cause
             AND receipt.occurred_at_unix = provenance.revoked_at_unix
            JOIN transcript_mining_wal_outbox AS bound
              ON bound.provenance_id = provenance.provenance_id
             AND bound.lifecycle_id = provenance.lifecycle_id
             AND bound.logical_subtype = 'bound'
             AND bound.event_subtype = 40
            WHERE provenance.provenance_id = NEW.provenance_id
              AND provenance.lifecycle_id = NEW.lifecycle_id
              AND provenance.lifecycle IN ('revoked', 'cancelled')
              AND provenance.terminal_cause IS NOT NULL
              AND bound.state = 'delivered'
              AND length(bound.delivered_frame_sha256) = 32
              AND bound.payload_sha256 = NEW.bound_payload_sha256
        )
    )
    BEGIN
        SELECT RAISE(ABORT, 'revoked outbox requires terminal receipt and delivered binding');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_outbox_binding_immutable
    BEFORE UPDATE OF outbox_id, provenance_id, lifecycle_id, logical_subtype,
        event_subtype, payload, payload_sha256, bound_payload_sha256,
        revocation_receipt_id, enqueued_at_unix ON transcript_mining_wal_outbox
    BEGIN
        SELECT RAISE(ABORT, 'outbox binding immutable');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_outbox_terminal
    BEFORE UPDATE OF state, delivered_at_unix, delivered_frame_sha256
    ON transcript_mining_wal_outbox
    WHEN (OLD.state = 'pending' AND NOT (
            (NEW.state = 'pending'
                AND NEW.delivered_at_unix IS NULL AND NEW.delivered_frame_sha256 IS NULL)
            OR (NEW.state = 'cancelled'
                AND NEW.logical_subtype = 'bound'
                AND NEW.delivered_at_unix IS NULL AND NEW.delivered_frame_sha256 IS NULL
                AND EXISTS (
                    SELECT 1
                    FROM transcript_mining_provenance AS provenance
                    JOIN transcript_mining_revocation_receipts AS receipt
                      ON receipt.provenance_id = provenance.provenance_id
                     AND receipt.lifecycle_id = provenance.lifecycle_id
                     AND receipt.raw_turn_id = provenance.raw_turn_id
                     AND receipt.lifecycle = provenance.lifecycle
                     AND receipt.revocation = provenance.terminal_cause
                     AND receipt.occurred_at_unix = provenance.revoked_at_unix
                    WHERE provenance.provenance_id = NEW.provenance_id
                      AND provenance.lifecycle_id = NEW.lifecycle_id
                      AND provenance.lifecycle IN ('revoked', 'cancelled')
                )
            )
        ))
      OR (OLD.state IN ('delivered', 'cancelled')
          AND (NEW.state <> OLD.state
               OR NEW.delivered_at_unix IS NOT OLD.delivered_at_unix
               OR NEW.delivered_frame_sha256 IS NOT OLD.delivered_frame_sha256))
    BEGIN
        SELECT RAISE(ABORT, 'mining outbox terminal state immutable');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_outbox_immutable_delete
    BEFORE DELETE ON transcript_mining_wal_outbox
    BEGIN
        SELECT RAISE(ABORT, 'mining outbox deletion forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_provenance_immutable_delete
    BEFORE DELETE ON transcript_mining_provenance
    BEGIN
        SELECT RAISE(ABORT, 'mining provenance deletion forbidden');
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_raw_turn_delete_context
    BEFORE DELETE ON raw_turns
    BEGIN
        INSERT OR REPLACE INTO transcript_mining_delete_context
            (raw_turn_id, terminal_cause, occurred_at_unix)
        VALUES (OLD.id, 'raw_turn_deleted', CAST(strftime('%s','now') AS INTEGER));
    END;

    CREATE TRIGGER IF NOT EXISTS transcript_mining_raw_turn_deleted
    AFTER DELETE ON raw_turns
    BEGIN
        UPDATE transcript_mining_provenance
        SET lifecycle = CASE lifecycle
                WHEN 'active' THEN 'revoked'
                WHEN 'pending' THEN 'cancelled'
                ELSE lifecycle
            END,
            revoked_at_unix = (
                SELECT occurred_at_unix FROM transcript_mining_delete_context
                WHERE raw_turn_id = OLD.id
            ),
            terminal_cause = (
                SELECT terminal_cause FROM transcript_mining_delete_context
                WHERE raw_turn_id = OLD.id
            )
        WHERE raw_turn_id = OLD.id AND lifecycle IN ('pending', 'active');

        INSERT OR IGNORE INTO transcript_mining_revocation_receipts
            (receipt_id, provenance_id, lifecycle_id, raw_turn_id, revocation, lifecycle, occurred_at_unix)
        SELECT 'raw-delete-' || provenance_id, provenance_id, lifecycle_id, raw_turn_id,
               terminal_cause, lifecycle, revoked_at_unix
        FROM transcript_mining_provenance
        WHERE raw_turn_id = OLD.id
          AND lifecycle IN ('revoked', 'cancelled')
          AND terminal_cause = 'raw_turn_deleted';

        UPDATE transcript_mining_raw_frame_plan
        SET state = 'cancelled',
            cancelled_at_unix = (
                SELECT occurred_at_unix FROM transcript_mining_delete_context
                WHERE raw_turn_id = OLD.id
            )
        WHERE raw_turn_id = OLD.id AND state = 'planned';

        UPDATE transcript_mining_wal_outbox
        SET state = 'cancelled'
        WHERE logical_subtype = 'bound'
          AND state = 'pending'
          AND provenance_id IN (
              SELECT provenance_id FROM transcript_mining_provenance
              WHERE raw_turn_id = OLD.id AND lifecycle IN ('revoked', 'cancelled')
                AND terminal_cause = 'raw_turn_deleted'
          );

        DELETE FROM transcript_mining_delete_context WHERE raw_turn_id = OLD.id;
    END;
"#;

/// `<NEOTH_HOME>/views.db`, falling back to `~/.neoth/views.db`.
///
/// Standalone CLI commands use this path too, so it must share the exact home
/// resolver used by the daemon/config surfaces instead of silently escaping a
/// custom instance into the process user's default home.
pub fn default_path() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home().join("views.db")
}

/// Isolated operator-review journal used by the History CLI by default.
pub fn default_history_path() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home()
        .join("history")
        .join("history.db")
}

/// Open the review journal only after its directory, database, and existing
/// SQLite sidecars have proved owner-private. A fresh empty file is created
/// under the private parent before SQLite can write schema or journal bytes.
pub(crate) fn open_private_history(path: &Path) -> Result<PrivateHistoryConnection> {
    open_private_history_with_hooks(path, || {}, || {})
}

#[cfg(test)]
fn open_private_history_with_hook(
    path: &Path,
    before_sqlite_open: impl FnOnce(),
) -> Result<PrivateHistoryConnection> {
    open_private_history_with_hooks(path, before_sqlite_open, || {})
}

fn open_private_history_with_hooks(
    path: &Path,
    before_sqlite_open: impl FnOnce(),
    after_identity_proof: impl FnOnce(),
) -> Result<PrivateHistoryConnection> {
    // The caller selects the History namespace, but it can legitimately be
    // spelled through an OS-owned alias (macOS `/var` resolves to
    // `/private/var`). Resolve that approved namespace exactly once before
    // any database/sidecar operation, then use only the physical spelling.
    // All descendants remain subject to the existing no-follow and identity
    // checks below; a later alias swap cannot redirect SQLite into another
    // database such as `views.db`.
    let path = anchor_private_history_target(path)?;
    let prepared = prepare_private_history_target(&path)?;
    let namespace_fence =
        crate::connectors::local_import::approve_import_root(private_history_parent(&path)?)
            .context("pin private history database namespace")?;
    #[cfg(windows)]
    let parent_fence = open_private_history_parent_delete_fence(
        private_history_parent(&path)?,
        &namespace_fence,
    )?;
    verify_private_history_target(&path, true)?;
    before_sqlite_open();
    let mut connection =
        open_with_prepared_history_target_and_hook(&path, &prepared, after_identity_proof)?;
    let history_schema = connection
        .transaction()
        .context("begin isolated History schema transaction")?;
    history_schema
        .execute_batch(crate::memory::history_onboarding::HISTORY_ONBOARDING_V38_SQL)
        .context("initialize isolated History review journal")?;
    history_schema
        .execute(
            "INSERT INTO meta(key,value) VALUES('history_schema_version','1')
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [],
        )
        .context("record isolated History schema version")?;
    history_schema
        .commit()
        .context("commit isolated History schema transaction")?;
    match &prepared {
        PreparedHistoryTarget::Generic => {}
        PreparedHistoryTarget::Existing(file) | PreparedHistoryTarget::Fresh(file) => {
            verify_fresh_history_path_identity(&path, file)?;
        }
    }
    harden_new_history_sidecars(&path)?;
    verify_private_history_target(&path, true)?;
    Ok(PrivateHistoryConnection {
        connection,
        _file_fence: match prepared {
            PreparedHistoryTarget::Generic => None,
            PreparedHistoryTarget::Existing(file) | PreparedHistoryTarget::Fresh(file) => {
                Some(file)
            }
        },
        #[cfg(windows)]
        _parent_fence: parent_fence,
        _namespace_fence: namespace_fence,
    })
}

/// Retain an explicit no-follow handle to the exact private History parent for
/// the complete connection lifetime. The generic approved-root capability is
/// retained as the ancestor/reparse fence; this separate parent handle is the
/// concrete Windows namespace-delete fence used by the History connection.
#[cfg(windows)]
fn open_private_history_parent_delete_fence(
    path: &Path,
    approved_root: &crate::connectors::local_import::ApprovedImportRoot,
) -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_READ_ATTRIBUTES, READ_CONTROL,
    };

    let directory = OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .context("open private History parent delete fence")?;
    crate::connectors::local_import::verify_approved_import_root_handle(approved_root, &directory)
        .context("bind private History parent delete fence to approved namespace")?;
    crate::wal::win_native::verify_private_directory_handle_dacl(&directory)
        .context("verify private History parent delete fence owner and DACL")?;
    Ok(directory)
}

/// Anchor the caller-approved History namespace to one physical path before
/// handling the database leaf. On macOS this admits platform-owned aliases
/// above the namespace (for example `/var`) without carrying that mutable
/// spelling into later file operations. Other platforms retain their existing
/// no-link root policy, including Windows reparse-point defenses.
fn anchor_private_history_target(path: &Path) -> Result<PathBuf> {
    let parent = private_history_parent(path)?;
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("history database requires a file name"))?;
    if !parent.exists() {
        std::fs::create_dir_all(parent).context("create private history database directory")?;
        make_private_history_directory(parent)?;
    }
    #[cfg(target_os = "macos")]
    let physical_parent =
        std::fs::canonicalize(parent).context("canonicalize private history database namespace")?;
    #[cfg(not(target_os = "macos"))]
    let physical_parent = parent.to_path_buf();
    verify_private_history_directory(&physical_parent)?;
    Ok(physical_parent.join(file_name))
}

fn prepare_private_history_target(path: &Path) -> Result<PreparedHistoryTarget> {
    let parent = private_history_parent(path)?;
    if parent.exists() {
        verify_private_history_directory(parent)?;
    } else {
        std::fs::create_dir_all(parent).context("create private history database directory")?;
        make_private_history_directory(parent)?;
        verify_private_history_directory(parent)?;
    }
    if path.exists() {
        let file = prepare_existing_private_history_file(path)?;
        prepare_existing_private_history_sidecars(path)?;
        Ok(PreparedHistoryTarget::Existing(file))
    } else {
        Ok(PreparedHistoryTarget::Fresh(create_private_history_file(
            path,
        )?))
    }
}

/// Admit an existing review journal only after it satisfies the private-file
/// contract. Windows v37 journals predate that contract and can therefore be
/// TokenUser-owned while retaining inherited ACEs. A nonempty legacy database
/// is hardened through an identity-bound, no-reparse handle before SQLite sees
/// it; empty or foreign-owned database files remain rejected.
fn prepare_existing_private_history_file(path: &Path) -> Result<std::fs::File> {
    match open_private_history_file(path) {
        Ok(file) => Ok(file),
        Err(_strict_error) => {
            #[cfg(windows)]
            {
                let file = open_private_history_file_witness(path)?;
                anyhow::ensure!(
                    file.metadata()
                        .context("inspect legacy private History database witness")?
                        .len()
                        > 0,
                    "existing private History database is empty and does not qualify for legacy DACL migration"
                );
                crate::wal::win_native::set_private_current_user_file_dacl_bound(path, &file)
                    .context("harden owner-bound legacy private History database DACL")?;
                verify_private_history_file(path)?;
                Ok(file)
            }
            #[cfg(not(windows))]
            {
                Err(_strict_error)
            }
        }
    }
}

/// Sidecars are recovered independently from the main database because an
/// interrupted prior migration can leave a strict main file beside a legacy
/// `-wal`, `-shm`, or rollback-journal. The operation is idempotent: an already
/// private sidecar is only verified; any other Windows sidecar must prove the
/// current owner through its no-reparse handle before it is hardened.
fn prepare_existing_private_history_sidecars(path: &Path) -> Result<()> {
    for sidecar in sqlite_sidecar_paths(path) {
        if !sidecar.exists() {
            continue;
        }
        match verify_private_history_file(&sidecar) {
            Ok(()) => continue,
            Err(_strict_error) => {
                #[cfg(windows)]
                {
                    let file = open_private_history_file_witness(&sidecar)?;
                    crate::wal::win_native::set_private_current_user_file_dacl_bound(
                        &sidecar, &file,
                    )
                    .context("harden owner-bound legacy private History sidecar DACL")?;
                    verify_private_history_file(&sidecar)?;
                }
                #[cfg(not(windows))]
                {
                    return Err(_strict_error);
                }
            }
        }
    }
    Ok(())
}

fn verify_private_history_target(path: &Path, require_database: bool) -> Result<()> {
    verify_private_history_directory(private_history_parent(path)?)?;
    if require_database || path.exists() {
        verify_private_history_file(path)?;
    }
    for sidecar in sqlite_sidecar_paths(path) {
        if sidecar.exists() {
            verify_private_history_file(&sidecar)?;
        }
    }
    Ok(())
}

fn private_history_parent(path: &Path) -> Result<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("history database requires an explicit private parent"))
}

fn sqlite_sidecar_paths(path: &Path) -> [PathBuf; 3] {
    ["-wal", "-shm", "-journal"].map(|suffix| {
        let mut sidecar = OsString::from(path.as_os_str());
        sidecar.push(suffix);
        PathBuf::from(sidecar)
    })
}

fn create_private_history_file(path: &Path) -> Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = options
        .open(path)
        .context("create private history database file")?;
    #[cfg(windows)]
    crate::wal::win_native::set_private_current_user_file_dacl_bound(path, &file)
        .context("set private history database DACL")?;
    verify_private_history_file(path)?;
    Ok(file)
}

fn open_private_history_file(path: &Path) -> Result<std::fs::File> {
    let file = open_private_history_file_witness(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = file
            .metadata()
            .context("inspect private History database witness")?;
        let mode = metadata.permissions().mode();
        anyhow::ensure!(metadata.is_file(), "History database witness is not a file");
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "History database witness owner mismatch"
        );
        anyhow::ensure!(
            metadata.nlink() == 1,
            "History database witness is hard-linked"
        );
        anyhow::ensure!(
            mode & 0o077 == 0 && mode & 0o600 == 0o600,
            "History database witness is not owner-private"
        );
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_file_handle(&file)
        .context("verify private History database witness owner and DACL")?;
    Ok(file)
}

/// Open the exact existing History object without following a final link.
/// Windows legacy migration performs only its owner proof and DACL transition
/// through this handle; strict private verification stays in
/// [`open_private_history_file`].
fn open_private_history_file_witness(path: &Path) -> Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .context("open private History database witness")?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        anyhow::ensure!(
            file.metadata()
                .context("inspect private History database witness")?
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT
                == 0,
            "private History database witness cannot be a reparse point"
        );
    }
    Ok(file)
}

fn verify_fresh_history_path_identity(path: &Path, created: &std::fs::File) -> Result<()> {
    let rebound =
        open_private_history_file(path).context("rebind prepared private History database")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let created = created
            .metadata()
            .context("identify created History database")?;
        let rebound = rebound
            .metadata()
            .context("identify rebound History database")?;
        anyhow::ensure!(
            created.dev() == rebound.dev() && created.ino() == rebound.ino(),
            "freshly prepared private History database identity changed"
        );
    }
    #[cfg(windows)]
    anyhow::ensure!(
        crate::wal::win_native::same_file_object(created, &rebound)
            .context("compare fresh History database identities")?,
        "freshly prepared private History database identity changed"
    );
    Ok(())
}

fn make_private_history_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .context("set private history directory mode")?;
    }
    #[cfg(windows)]
    crate::wal::win_native::set_private_current_user_directory_dacl(path)
        .context("set private history directory DACL")?;
    Ok(())
}

fn verify_private_history_directory(path: &Path) -> Result<()> {
    let metadata =
        std::fs::symlink_metadata(path).context("inspect private history database directory")?;
    anyhow::ensure!(
        metadata.is_dir(),
        "history database parent is not a directory"
    );
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "history database parent cannot be a link"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "history database parent owner mismatch"
        );
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "history database parent is not owner-private"
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };

        let directory = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .context("open private history directory capability")?;
        crate::wal::win_native::verify_private_directory_handle_dacl(&directory)
            .context("verify private history directory owner and DACL")?;
    }
    Ok(())
}

fn verify_private_history_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).context("inspect private history file")?;
    anyhow::ensure!(
        metadata.is_file(),
        "history database object is not a regular file"
    );
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "history database cannot be a link"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode();
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "history database owner mismatch"
        );
        anyhow::ensure!(
            metadata.nlink() == 1,
            "history database hard links are forbidden"
        );
        anyhow::ensure!(
            mode & 0o077 == 0 && mode & 0o600 == 0o600,
            "history database is not owner-private"
        );
    }
    #[cfg(windows)]
    {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .context("open private history file capability")?;
        crate::wal::win_native::verify_private_file_handle(&file)
            .context("verify private history file owner and DACL")?;
    }
    Ok(())
}

fn harden_new_history_sidecars(path: &Path) -> Result<()> {
    for sidecar in sqlite_sidecar_paths(path) {
        if !sidecar.exists() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&sidecar)
                .context("open SQLite sidecar without following links")?;
            let metadata = file
                .metadata()
                .context("inspect handle-bound SQLite sidecar")?;
            anyhow::ensure!(metadata.is_file(), "SQLite sidecar is not a regular file");
            anyhow::ensure!(
                metadata.uid() == unsafe { libc::geteuid() },
                "SQLite sidecar owner mismatch"
            );
            anyhow::ensure!(
                metadata.nlink() == 1,
                "SQLite sidecar hard links are forbidden"
            );
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .context("set private SQLite sidecar mode")?;
        }
        #[cfg(windows)]
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&sidecar)
                .context("open SQLite sidecar for private DACL")?;
            crate::wal::win_native::set_private_current_user_file_dacl_bound(&sidecar, &file)
                .context("set private SQLite sidecar DACL")?;
        }
        verify_private_history_file(&sidecar)?;
    }
    Ok(())
}

/// Open or create the views database. Applies schema. Sets unix mode 0600
/// on the file. Windows DACL restriction follows the same pattern as WAL
/// segments (see `wal/win_acl.rs`).
pub fn open(path: &Path) -> Result<Connection> {
    open_with_prepared_history_target_and_hook(path, &PreparedHistoryTarget::Generic, || {})
}

fn open_with_prepared_history_target_and_hook(
    path: &Path,
    prepared: &PreparedHistoryTarget,
    after_identity_proof: impl FnOnce(),
) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir for {}", path.display()))?;
    }
    let witness = match prepared {
        PreparedHistoryTarget::Generic => None,
        PreparedHistoryTarget::Existing(file) | PreparedHistoryTarget::Fresh(file) => Some(file),
    };
    let is_fresh = matches!(prepared, PreparedHistoryTarget::Fresh(_));
    let is_new = !path.exists() || is_fresh;
    if let Some(file) = witness {
        let metadata = file
            .metadata()
            .context("inspect private History database witness")?;
        anyhow::ensure!(
            metadata.is_file(),
            "private History database witness is not a regular file"
        );
        if is_fresh {
            anyhow::ensure!(
                metadata.len() == 0,
                "fresh History database is no longer empty"
            );
        } else {
            anyhow::ensure!(metadata.len() > 0, "existing History database is empty");
        }
        if is_fresh {
            anyhow::ensure!(
                sqlite_sidecar_paths(path)
                    .iter()
                    .all(|sidecar| !sidecar.exists()),
                "fresh private History database already has SQLite sidecars"
            );
        }
    }
    let mut conn = if witness.is_some() {
        Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
    } else {
        Connection::open(path)
    }
    .with_context(|| format!("open SQLite db {}", path.display()))?;
    if let Some(file) = witness {
        verify_fresh_history_path_identity(path, file)?;
    }
    after_identity_proof();

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
            // Keep the already-open connection: prepared History targets have
            // passed NOFOLLOW and exact-file identity checks on this handle.
            crate::memory::migrations::migrate(&mut conn, current, SCHEMA_VERSION)?;
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

        -- v28: durable bulk-text import identity. `fingerprint` accelerates
        -- lookup but is deliberately not unique: only the full canonical
        -- statement plus scope proves equality. The row outlives revocation;
        -- ON DELETE SET NULL preserves a hard-delete tombstone as well.
        CREATE TABLE IF NOT EXISTS ground_truth_fingerprints (
            scope                  TEXT NOT NULL,
            fingerprint            BLOB NOT NULL
                                       CHECK (typeof(fingerprint) = 'blob' AND length(fingerprint) = 8),
            normalised_statement   TEXT NOT NULL,
            groundtruth_id         INTEGER,
            first_seen_at          INTEGER NOT NULL,
            PRIMARY KEY (scope, normalised_statement),
            FOREIGN KEY (groundtruth_id) REFERENCES idx_groundtruth(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ground_truth_fingerprints_hash
            ON ground_truth_fingerprints (scope, fingerprint);

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
            valid_to  TEXT,
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
            -- v22: refines-JV-MEM-08 — Ebbinghaus decay stability parameter.
            -- Conceptually in days. Default 1.0 → 1-day half-life at zero
            -- reinforcement. Grows via Cepeda spacing: +0.1 whenever the
            -- inter-access gap exceeds the current stability window, rewarding
            -- spaced practice with slower forgetting.
            stability REAL NOT NULL DEFAULT 1.0,
            UNIQUE(lo_id, hi_id),
            CHECK(lo_id < hi_id)
        );
        CREATE INDEX IF NOT EXISTS idx_memory_links_lo ON idx_memory_links (lo_id);
        CREATE INDEX IF NOT EXISTS idx_memory_links_hi ON idx_memory_links (hi_id);
        CREATE INDEX IF NOT EXISTS idx_memory_links_weight ON idx_memory_links (weight DESC);

        -- GOLD-ADAPT-GRAPH-03: idx_memory_communities — Louvain community
        -- assignments refreshed by decay_task after each link decay pass.
        -- PK on node_id: each episode belongs to at most one community.
        CREATE TABLE IF NOT EXISTS idx_memory_communities (
            node_id      INTEGER NOT NULL PRIMARY KEY,
            community_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_memory_communities_community
            ON idx_memory_communities (community_id);

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
            created_at_unix INTEGER NOT NULL,
            resolution_decision TEXT NOT NULL DEFAULT 'pending'
                CHECK (resolution_decision IN ('pending', 'approve', 'decline'))
        );
        CREATE INDEX IF NOT EXISTS idx_profile_pending_created
            ON idx_profile_pending (created_at_unix ASC);

        -- ── Schema v21: GOLD-ADAPT-ODY-26 — raw transcript FTS ───────────
        --
        -- `raw_turns` is an append-only table: one row per operator/agent
        -- turn. `raw_turns_fts` is a content-linked FTS5 virtual table
        -- (porter unicode61 tokeniser, same as `chunks`) kept in sync by
        -- the three triggers below (same pattern as idx_episode_fts v2).
        -- `session_id` is an opaque string (the turn-id from serve_pipeline
        -- or session_id_for from hindsight); `role` is 'operator'|'agent'.
        -- Indexed by (session_id, id) for context-row window queries.
        CREATE TABLE IF NOT EXISTS raw_turns (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT    NOT NULL,
            role       TEXT    NOT NULL CHECK (role IN ('operator', 'agent')),
            ts_unix    INTEGER NOT NULL,
            text       TEXT    NOT NULL,
            -- v36: defaults every pre-v36/ordinary turn to permanently
            -- legacy-unbound. Only a later authenticated ingress may set 1 at
            -- INSERT time; UPDATE is fenced below.
            transcript_mining_authority_epoch INTEGER NOT NULL DEFAULT 0
                CHECK(transcript_mining_authority_epoch IN (0, 1)),
            -- v37: separates the post-v37 raw-frame-plan birth boundary from
            -- the v36 witness epoch. Every row present before v37 is stamped
            -- 0 by the migration and can never gain a frame plan later.
            transcript_mining_raw_frame_plan_epoch INTEGER NOT NULL DEFAULT 0
                CHECK(transcript_mining_raw_frame_plan_epoch IN (0, 1)),
            CHECK(
                transcript_mining_raw_frame_plan_epoch = 0
                OR transcript_mining_authority_epoch = 1
            )
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
    .context("apply views schema")?;

    conn.execute_batch(TRANSCRIPT_MINING_V37_TABLES_SQL)
        .context("apply v37 transcript mining metadata tables")?;
    conn.execute_batch(TRANSCRIPT_MINING_V37_TRIGGERS_SQL)
        .context("apply v37 transcript mining metadata triggers")?;
    // SPEC-11 merge tombstone — idempotent column add for an `idx_human_identity`
    // created before the `merged_into` column existed. `CREATE TABLE IF NOT
    // EXISTS` never alters an existing table, so back-fill the column here;
    // `.ok()` swallows the "duplicate column" error on tables that already have it.
    let _ = conn.execute(
        "ALTER TABLE idx_human_identity ADD COLUMN merged_into TEXT",
        [],
    );

    // G-02 CLUSTER-01: foreign event ingest surface.
    // Accepted gossip frames from paired peers land here — never in idx_episode
    // (foreign ≠ operator truth). UNIQUE(origin_peer_pk, origin_seq) makes
    // INSERT OR IGNORE idempotent: a re-gossiped frame is a silent no-op.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS idx_foreign_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            origin_peer_pk  TEXT    NOT NULL,
            stable_node_id  TEXT    NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            auth_epoch      INTEGER NOT NULL DEFAULT 1 CHECK(auth_epoch > 0),
            membership_epoch INTEGER NOT NULL DEFAULT 1 CHECK(membership_epoch > 0),
            fence_state     TEXT NOT NULL DEFAULT 'legacy_unbound'
                                 CHECK(fence_state IN ('active','legacy_unbound')),
            origin_seq      INTEGER NOT NULL,
            event_type      INTEGER NOT NULL,
            payload         BLOB    NOT NULL,
            received_at     INTEGER NOT NULL,
            envelope_version INTEGER NOT NULL DEFAULT 0,
            content_sha256  BLOB CHECK (content_sha256 IS NULL OR (typeof(content_sha256) = 'blob' AND length(content_sha256) = 32)),
            content_kind    TEXT,
            content_payload BLOB,
            UNIQUE (stable_node_id, auth_epoch, origin_seq)
        );
        CREATE INDEX IF NOT EXISTS idx_foreign_events_peer
            ON idx_foreign_events (stable_node_id, auth_epoch, received_at DESC);

        CREATE TABLE IF NOT EXISTS mesh_sync_local_events (
            peer_pk         TEXT NOT NULL,
            stable_node_id   TEXT,
            auth_epoch       INTEGER,
            membership_epoch INTEGER,
            fence_state      TEXT NOT NULL DEFAULT 'legacy_unbound'
                                  CHECK (fence_state IN ('active', 'legacy_unbound')),
            origin_seq      INTEGER NOT NULL CHECK (origin_seq > 0),
            content_sha256  BLOB NOT NULL
                                  CHECK (typeof(content_sha256) = 'blob' AND length(content_sha256) = 32),
            envelope        BLOB NOT NULL,
            created_at      INTEGER NOT NULL,
            PRIMARY KEY (peer_pk, origin_seq),
            UNIQUE (peer_pk, content_sha256)
        );
        CREATE TABLE IF NOT EXISTS mesh_sync_outbound (
            peer_pk              TEXT PRIMARY KEY,
            stable_node_id        TEXT,
            auth_epoch            INTEGER,
            membership_epoch      INTEGER,
            fence_state           TEXT NOT NULL DEFAULT 'legacy_unbound'
                                      CHECK (fence_state IN ('active', 'legacy_unbound')),
            cursor_segment       TEXT,
            cursor_offset        INTEGER NOT NULL DEFAULT 0 CHECK (cursor_offset >= 0),
            acked_origin_seq     INTEGER NOT NULL DEFAULT 0 CHECK (acked_origin_seq >= 0),
            acked_content_sha256 BLOB,
            updated_at           INTEGER NOT NULL,
            CHECK ((acked_origin_seq = 0 AND acked_content_sha256 IS NULL) OR
                   (acked_origin_seq > 0 AND typeof(acked_content_sha256) = 'blob' AND length(acked_content_sha256) = 32))
        );
        CREATE TABLE IF NOT EXISTS mesh_sync_outbound_pending (
            peer_pk             TEXT PRIMARY KEY,
            stable_node_id       TEXT,
            auth_epoch           INTEGER,
            membership_epoch     INTEGER,
            fence_state          TEXT NOT NULL DEFAULT 'legacy_unbound'
                                    CHECK (fence_state IN ('active', 'legacy_unbound')),
            origin_seq         INTEGER NOT NULL CHECK (origin_seq > 0),
            content_sha256     BLOB NOT NULL CHECK (typeof(content_sha256) = 'blob' AND length(content_sha256) = 32),
            wire_frame         BLOB NOT NULL,
            next_cursor_segment TEXT,
            next_cursor_offset INTEGER NOT NULL CHECK (next_cursor_offset >= 0),
            attempts           INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            created_at         INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mesh_sync_requests (
            peer_pk       TEXT PRIMARY KEY
                               CHECK (length(peer_pk) = 64 AND peer_pk NOT GLOB '*[^0-9a-f]*'),
            stable_node_id TEXT,
            auth_epoch INTEGER,
            membership_epoch INTEGER,
            fence_state TEXT NOT NULL DEFAULT 'legacy_unbound'
                              CHECK (fence_state IN ('active', 'legacy_unbound')),
            requested_at  INTEGER NOT NULL CHECK (requested_at > 0),
            expires_at    INTEGER NOT NULL CHECK (expires_at > requested_at),
            state         TEXT NOT NULL
                               CHECK (state IN ('queued', 'active', 'waiting_peer', 'complete', 'expired')),
            updated_at    INTEGER NOT NULL CHECK (updated_at >= requested_at),
            last_attempt_at INTEGER CHECK (last_attempt_at IS NULL OR last_attempt_at >= requested_at),
            send_attempts INTEGER NOT NULL DEFAULT 0 CHECK (send_attempts >= 0),
            last_error    TEXT CHECK (last_error IS NULL OR length(last_error) <= 240)
        );
        CREATE TRIGGER IF NOT EXISTS mesh_sync_requests_cap
        BEFORE INSERT ON mesh_sync_requests
        WHEN NOT EXISTS (SELECT 1 FROM mesh_sync_requests WHERE peer_pk = NEW.peer_pk)
             AND (SELECT COUNT(*) FROM mesh_sync_requests) >= 256
        BEGIN
            SELECT RAISE(ABORT, 'mesh sync request queue exceeds 256 peers');
        END;
        CREATE TABLE IF NOT EXISTS mesh_sync_inbound (
            origin_peer_pk       TEXT PRIMARY KEY,
            stable_node_id        TEXT,
            auth_epoch            INTEGER,
            membership_epoch      INTEGER,
            fence_state           TEXT NOT NULL DEFAULT 'legacy_unbound'
                                      CHECK (fence_state IN ('active', 'legacy_unbound')),
            next_expected_seq    INTEGER NOT NULL DEFAULT 1 CHECK (next_expected_seq > 0),
            last_content_sha256  BLOB,
            updated_at           INTEGER NOT NULL,
            CHECK ((next_expected_seq = 1 AND last_content_sha256 IS NULL) OR
                   (next_expected_seq > 1 AND typeof(last_content_sha256) = 'blob' AND length(last_content_sha256) = 32))
        );
        CREATE TABLE IF NOT EXISTS mesh_sync_inbound_receipts (
            origin_peer_pk TEXT NOT NULL,
            stable_node_id  TEXT,
            auth_epoch      INTEGER,
            membership_epoch INTEGER,
            fence_state     TEXT NOT NULL DEFAULT 'legacy_unbound'
                                CHECK (fence_state IN ('active', 'legacy_unbound')),
            origin_seq     INTEGER NOT NULL CHECK (origin_seq > 0),
            content_sha256 BLOB NOT NULL CHECK (typeof(content_sha256) = 'blob' AND length(content_sha256) = 32),
            frame_sha256   BLOB CHECK (frame_sha256 IS NULL OR (typeof(frame_sha256) = 'blob' AND length(frame_sha256) = 32)),
            content_stored INTEGER NOT NULL CHECK (content_stored IN (0, 1)),
            committed_at   INTEGER NOT NULL,
            PRIMARY KEY (origin_peer_pk, origin_seq)
        );
        CREATE TABLE IF NOT EXISTS mesh_sync_vector_frontier (
            peer_pk TEXT NOT NULL CHECK (length(peer_pk) > 0),
            stable_node_id TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            auth_epoch INTEGER NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
            membership_epoch INTEGER NOT NULL DEFAULT 1 CHECK (membership_epoch > 0),
            fence_state TEXT NOT NULL DEFAULT 'legacy_unbound'
                              CHECK (fence_state IN ('active', 'legacy_unbound')),
            counter INTEGER NOT NULL CHECK (counter > 0),
            PRIMARY KEY (stable_node_id, auth_epoch, membership_epoch, peer_pk)
        );
        CREATE TRIGGER IF NOT EXISTS mesh_sync_vector_frontier_cap
        BEFORE INSERT ON mesh_sync_vector_frontier
        WHEN NOT EXISTS (
                SELECT 1 FROM mesh_sync_vector_frontier
                WHERE stable_node_id=NEW.stable_node_id
                  AND auth_epoch=NEW.auth_epoch
                  AND membership_epoch=NEW.membership_epoch
                  AND peer_pk=NEW.peer_pk
             )
             AND (SELECT COUNT(*) FROM mesh_sync_vector_frontier
                  WHERE stable_node_id=NEW.stable_node_id
                    AND auth_epoch=NEW.auth_epoch
                    AND membership_epoch=NEW.membership_epoch) >= 256
        BEGIN
            SELECT RAISE(ABORT, 'mesh vector frontier exceeds 256 peers');
        END;
        CREATE TABLE IF NOT EXISTS mesh_sync_materialized (
            origin_peer_pk  TEXT NOT NULL,
            stable_node_id  TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            auth_epoch      INTEGER NOT NULL DEFAULT 1 CHECK(auth_epoch > 0),
            membership_epoch INTEGER NOT NULL DEFAULT 1 CHECK(membership_epoch > 0),
            fence_state     TEXT NOT NULL DEFAULT 'legacy_unbound'
                                 CHECK(fence_state IN ('active','legacy_unbound')),
            content_id      TEXT NOT NULL,
            origin_seq      INTEGER NOT NULL CHECK (origin_seq > 0),
            content_sha256  BLOB NOT NULL CHECK (typeof(content_sha256) = 'blob' AND length(content_sha256) = 32),
            content_kind    TEXT NOT NULL CHECK (content_kind IN ('memory', 'ground_truth', 'metadata', 'raw_private')),
            content_payload BLOB NOT NULL,
            updated_at      INTEGER NOT NULL,
            PRIMARY KEY (stable_node_id, auth_epoch, content_id)
        );
        CREATE TABLE IF NOT EXISTS mesh_sync_conflicts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            content_id      TEXT NOT NULL,
            incumbent_origin TEXT NOT NULL,
            incumbent_auth_epoch INTEGER NOT NULL DEFAULT 1 CHECK(incumbent_auth_epoch > 0),
            incoming_origin TEXT NOT NULL,
            incoming_auth_epoch INTEGER NOT NULL DEFAULT 1 CHECK(incoming_auth_epoch > 0),
            incumbent_sha256 BLOB NOT NULL CHECK (length(incumbent_sha256) = 32),
            incoming_sha256 BLOB NOT NULL CHECK (length(incoming_sha256) = 32),
            policy          TEXT NOT NULL CHECK (policy IN ('ordered_origin_lww', 'cross_origin_typed_conflict')),
            observed_at     INTEGER NOT NULL,
            resolved_at     INTEGER CHECK (resolved_at IS NULL OR resolved_at > 0),
            preferred_origin TEXT,
            CHECK ((resolved_at IS NULL AND preferred_origin IS NULL) OR
                   (resolved_at IS NOT NULL AND preferred_origin IS NOT NULL AND
                    length(preferred_origin) > 0)),
            UNIQUE (content_id, incumbent_origin, incumbent_auth_epoch, incoming_origin,
                    incoming_auth_epoch, incumbent_sha256, incoming_sha256)
        );
        CREATE TABLE IF NOT EXISTS mesh_sync_restore_map (
            origin_peer_pk TEXT NOT NULL,
            stable_node_id TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            auth_epoch     INTEGER NOT NULL DEFAULT 1 CHECK(auth_epoch > 0),
            content_id     TEXT NOT NULL,
            local_kind     TEXT NOT NULL CHECK (local_kind IN ('memory', 'ground_truth')),
            local_row_id   INTEGER NOT NULL CHECK (local_row_id > 0),
            last_origin_seq INTEGER NOT NULL CHECK (last_origin_seq > 0),
            content_sha256 BLOB NOT NULL CHECK (typeof(content_sha256) = 'blob' AND length(content_sha256) = 32),
            restored_at    INTEGER NOT NULL,
            PRIMARY KEY (stable_node_id, auth_epoch, content_id),
            UNIQUE (local_kind, local_row_id)
        );
        CREATE TABLE IF NOT EXISTS mesh_sync_restore_evidence (
            origin_peer_pk         TEXT NOT NULL,
            stable_node_id         TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            auth_epoch             INTEGER NOT NULL DEFAULT 1 CHECK(auth_epoch > 0),
            ground_truth_content_id TEXT NOT NULL,
            evidence_position      INTEGER NOT NULL CHECK (evidence_position >= 0),
            evidence_content_id    TEXT NOT NULL,
            local_row_id           INTEGER CHECK (local_row_id IS NULL OR local_row_id > 0),
            PRIMARY KEY (stable_node_id, auth_epoch, ground_truth_content_id, evidence_position),
            UNIQUE (stable_node_id, auth_epoch, ground_truth_content_id, evidence_content_id)
        );
        CREATE INDEX IF NOT EXISTS mesh_sync_restore_evidence_content
            ON mesh_sync_restore_evidence (stable_node_id, auth_epoch, evidence_content_id);

        CREATE TRIGGER IF NOT EXISTS mesh_foreign_content_insert_guard
        BEFORE INSERT ON idx_foreign_events
        WHEN NOT (
            (NEW.envelope_version = 0 AND NEW.content_sha256 IS NULL AND
             NEW.content_kind IS NULL AND NEW.content_payload IS NULL) OR
            (NEW.envelope_version = 1 AND typeof(NEW.content_sha256) = 'blob' AND
             length(NEW.content_sha256) = 32 AND
             NEW.content_kind IN ('memory', 'ground_truth', 'metadata', 'raw_private') AND
             typeof(NEW.content_payload) = 'blob')
        )
        BEGIN
            SELECT RAISE(ABORT, 'incomplete canonical foreign content');
        END;
        CREATE TRIGGER IF NOT EXISTS mesh_foreign_content_update_guard
        BEFORE UPDATE OF envelope_version,content_sha256,content_kind,content_payload
        ON idx_foreign_events
        WHEN NOT (
            (NEW.envelope_version = 0 AND NEW.content_sha256 IS NULL AND
             NEW.content_kind IS NULL AND NEW.content_payload IS NULL) OR
            (NEW.envelope_version = 1 AND typeof(NEW.content_sha256) = 'blob' AND
             length(NEW.content_sha256) = 32 AND
             NEW.content_kind IN ('memory', 'ground_truth', 'metadata', 'raw_private') AND
             typeof(NEW.content_payload) = 'blob')
        )
        BEGIN
            SELECT RAISE(ABORT, 'incomplete canonical foreign content');
        END;
        "#,
    )
    .context("create idx_foreign_events")?;

    // L6-PRELOAD-RESTRICTED-INDEX-01 — physically separate restricted index.
    //
    // Exploit/payload corpora land here after `neoth obsidian preload --ingest`
    // when the manifest section has a restricted `risk_tier`. This table is
    // NEVER read by the normal recall path (`groundtruth::surface_for_recall` /
    // `groundtruth::list_for_scope` only query `idx_groundtruth`). Content
    // becomes available to recall ONLY via explicit operator promotion
    // (`neoth obsidian promote <id>`), which moves the row into `idx_groundtruth`
    // and writes an audit entry to `~/.neoth/promotion-audit.jsonl`.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS idx_restricted (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            statement    TEXT    NOT NULL,
            source_name  TEXT    NOT NULL,
            scope        TEXT    NOT NULL,
            risk_tier    TEXT    NOT NULL,
            asserted_at  INTEGER NOT NULL,
            promoted_at  INTEGER,          -- NULL until operator promotes
            promoted_by  TEXT              -- NULL until operator promotes
        );
        CREATE INDEX IF NOT EXISTS idx_restricted_scope
            ON idx_restricted (scope);
        CREATE INDEX IF NOT EXISTS idx_restricted_risk_tier
            ON idx_restricted (risk_tier);
        CREATE INDEX IF NOT EXISTS idx_restricted_promoted
            ON idx_restricted (promoted_at);
        "#,
    )
    .context("create idx_restricted")?;

    // OMI-MULTIMODAL-01 — durable, idempotent conversation reconciliation.
    // External ids stay separate from NEOTH ground-truth/kanban ids so REST
    // retries and live-stream reconciliation cannot mature or enqueue twice.
    // Transcript text is nullable (default retention is metadata+hash only);
    // raw media bytes never enter views.db.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS idx_omi_conversations (
            source_id              TEXT PRIMARY KEY,
            revision               TEXT NOT NULL,
            projection_hash        TEXT NOT NULL,
            status                 TEXT NOT NULL,
            source                 TEXT,
            language               TEXT,
            started_at_ms          INTEGER,
            finished_at_ms         INTEGER,
            call_id                TEXT,
            title                  TEXT,
            summary                TEXT,
            metadata_json          TEXT,
            transcript_hash        TEXT NOT NULL,
            segment_count          INTEGER NOT NULL DEFAULT 0,
            photo_count            INTEGER NOT NULL DEFAULT 0,
            audio_count            INTEGER NOT NULL DEFAULT 0,
            video_count            INTEGER NOT NULL DEFAULT 0,
            summary_groundtruth_id INTEGER,
            kanban_session_id      INTEGER,
            retain_transcript      INTEGER NOT NULL DEFAULT 0 CHECK (retain_transcript IN (0, 1)),
            audio_consent          INTEGER NOT NULL DEFAULT 0 CHECK (audio_consent IN (0, 1)),
            image_consent          INTEGER NOT NULL DEFAULT 0 CHECK (image_consent IN (0, 1)),
            video_consent          INTEGER NOT NULL DEFAULT 0 CHECK (video_consent IN (0, 1)),
            first_seen_ts          INTEGER NOT NULL,
            ingested_at_ts         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_omi_conversations_ingested
            ON idx_omi_conversations (ingested_at_ts DESC);
        CREATE INDEX IF NOT EXISTS idx_omi_conversations_call
            ON idx_omi_conversations (call_id) WHERE call_id IS NOT NULL;

        CREATE TABLE IF NOT EXISTS idx_omi_segments (
            conversation_id TEXT NOT NULL,
            segment_id      TEXT NOT NULL,
            ordinal         INTEGER NOT NULL,
            start_ms        INTEGER NOT NULL,
            end_ms          INTEGER NOT NULL,
            speaker         TEXT,
            speaker_id      INTEGER,
            is_user         INTEGER CHECK (is_user IN (0, 1)),
            person_id       TEXT,
            stt_provider    TEXT,
            text_hash       TEXT NOT NULL,
            text            TEXT,
            PRIMARY KEY (conversation_id, segment_id),
            FOREIGN KEY (conversation_id) REFERENCES idx_omi_conversations(source_id)
                ON DELETE CASCADE
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_omi_segments_ordinal
            ON idx_omi_segments (conversation_id, ordinal);
        CREATE INDEX IF NOT EXISTS idx_omi_segments_timeline
            ON idx_omi_segments (conversation_id, start_ms, end_ms);

        CREATE TABLE IF NOT EXISTS idx_omi_media (
            conversation_id   TEXT NOT NULL,
            media_id          TEXT NOT NULL,
            kind              TEXT NOT NULL CHECK (kind IN ('audio', 'image', 'video')),
            created_at_ms     INTEGER,
            duration_ms       INTEGER,
            content_hash      TEXT,
            processing_status TEXT NOT NULL,
            metadata_json     TEXT,
            processed_at_ts   INTEGER,
            PRIMARY KEY (conversation_id, media_id, kind),
            FOREIGN KEY (conversation_id) REFERENCES idx_omi_conversations(source_id)
                ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_omi_media_status
            ON idx_omi_media (processing_status, kind);

        CREATE TABLE IF NOT EXISTS idx_omi_actions (
            conversation_id TEXT NOT NULL,
            action_hash     TEXT NOT NULL,
            task_id         INTEGER NOT NULL,
            created_at_ts   INTEGER NOT NULL,
            PRIMARY KEY (conversation_id, action_hash),
            FOREIGN KEY (conversation_id) REFERENCES idx_omi_conversations(source_id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS idx_omi_state (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            updated_ts INTEGER NOT NULL
        );
        "#,
    )
    .context("create OMI reconciliation ledger")?;

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
    pub fn open(
        path: &std::path::Path,
        reader_count: usize,
    ) -> anyhow::Result<std::sync::Arc<Self>> {
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

// Pin the intended auto-traits without overriding Rust's structural checks.
// Adding a future !Send/!Sync field now fails compilation at this boundary.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ViewsExecutor>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_views_path_honors_neoth_home() {
        let _env = crate::test_env::lock();
        let home = tempdir().unwrap();
        let previous = std::env::var_os("NEOTH_HOME");
        unsafe { std::env::set_var("NEOTH_HOME", home.path()) };

        let actual = default_path();

        match previous {
            Some(value) => unsafe { std::env::set_var("NEOTH_HOME", value) },
            None => unsafe { std::env::remove_var("NEOTH_HOME") },
        }

        assert_eq!(actual, home.path().join("views.db"));
    }

    #[test]
    fn default_history_journal_is_private_and_isolated_from_views_database() {
        let _env = crate::test_env::lock();
        let home = tempdir().unwrap();
        let views = home.path().join("views.db");
        std::fs::write(&views, b"ordinary views sentinel").unwrap();
        let previous = std::env::var_os("NEOTH_HOME");
        unsafe { std::env::set_var("NEOTH_HOME", home.path()) };

        let history = default_history_path();
        let connection = open_private_history(&history).unwrap();
        drop(connection);

        match previous {
            Some(value) => unsafe { std::env::set_var("NEOTH_HOME", value) },
            None => unsafe { std::env::remove_var("NEOTH_HOME") },
        }

        assert_eq!(history, home.path().join("history").join("history.db"));
        assert_eq!(std::fs::read(&views).unwrap(), b"ordinary views sentinel");
        verify_private_history_target(&history, true).unwrap();
    }

    #[test]
    fn fresh_views_database_contains_no_history_journal_tables() {
        let dir = tempdir().unwrap();
        let connection = open(&dir.path().join("views.db")).unwrap();
        let history_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name LIKE 'history_onboarding_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let version: i64 = connection
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history_tables, 0);
        assert_eq!(version, 37);
    }

    #[test]
    fn on_disk_v37_open_migrates_only_the_empty_history_journal() {
        let dir = tempdir().unwrap();
        let parent = dir.path().join("history");
        std::fs::create_dir(&parent).unwrap();
        make_private_history_directory(&parent).unwrap();
        let path = parent.join("v37.db");
        let conn = open(&path).unwrap();
        conn.execute_batch(
            "UPDATE meta SET value='37' WHERE key='schema_version';
             INSERT INTO meta(key,value) VALUES('history_migration_sentinel','preserve-me');",
        )
        .unwrap();
        drop(conn);

        #[cfg(windows)]
        {
            assert!(verify_private_history_file(&path).is_err());
        }

        let migrated = open_private_history(&path).unwrap();
        let foreign_keys: i64 = migrated
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        let version: String = migrated
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let history_version: String = migrated
            .query_row(
                "SELECT value FROM meta WHERE key='history_schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let sentinel: String = migrated
            .query_row(
                "SELECT value FROM meta WHERE key='history_migration_sentinel'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let history_rows: i64 = migrated
            .query_row(
                "SELECT COUNT(*) FROM history_onboarding_batches",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let episode_rows: i64 = migrated
            .query_row("SELECT COUNT(*) FROM idx_episode", [], |row| row.get(0))
            .unwrap();
        let path_index: i64 = migrated
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='index' AND name='history_onboarding_batches_path'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(foreign_keys, 1);
        assert_eq!(version, SCHEMA_VERSION.to_string());
        assert_eq!(history_version, "1");
        assert_eq!(sentinel, "preserve-me");
        assert_eq!((history_rows, episode_rows), (0, 0));
        assert_eq!(path_index, 1);
        verify_private_history_target(&path, true).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_history_open_rejects_existing_weak_database_before_sqlite_open() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let dir = tempdir().unwrap();
        let path = dir.path().join("weak.db");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(open_private_history(&path).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn private_history_open_rejects_unprotected_inherited_database_dacl() {
        let root = tempdir().unwrap();
        let parent = root.path().join("private-parent");
        std::fs::create_dir(&parent).unwrap();
        make_private_history_directory(&parent).unwrap();
        let path = parent.join("weak.db");
        std::fs::write(&path, b"").unwrap();
        assert!(open_private_history(&path).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        assert!(verify_private_history_file(&path).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn strict_main_hardens_owner_bound_legacy_sidecars_and_retry_is_idempotent() {
        let root = tempdir().unwrap();
        let parent = root.path().join("private-history");
        std::fs::create_dir(&parent).unwrap();
        make_private_history_directory(&parent).unwrap();
        let database = parent.join("history.db");
        drop(create_private_history_file(&database).unwrap());

        let sidecars = sqlite_sidecar_paths(&database);
        for sidecar in &sidecars[..2] {
            std::fs::write(sidecar, b"legacy-sidecar").unwrap();
            crate::wal::win_native::set_unprotected_current_user_file_dacl_for_test(sidecar)
                .unwrap();
            assert!(verify_private_history_file(sidecar).is_err());
        }

        let first = prepare_private_history_target(&database).unwrap();
        drop(first);
        for sidecar in &sidecars[..2] {
            verify_private_history_file(sidecar).unwrap();
        }

        let retry = prepare_private_history_target(&database).unwrap();
        drop(retry);
        for sidecar in &sidecars[..2] {
            verify_private_history_file(sidecar).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn owner_bound_legacy_main_and_existing_sidecars_harden_before_sqlite_open() {
        let root = tempdir().unwrap();
        let parent = root.path().join("private-history");
        std::fs::create_dir(&parent).unwrap();
        make_private_history_directory(&parent).unwrap();
        let database = parent.join("history.db");
        std::fs::write(&database, b"legacy-history-database").unwrap();
        crate::wal::win_native::set_unprotected_current_user_file_dacl_for_test(&database)
            .unwrap();

        let sidecars = sqlite_sidecar_paths(&database);
        for sidecar in &sidecars[..2] {
            std::fs::write(sidecar, b"legacy-sidecar").unwrap();
            crate::wal::win_native::set_unprotected_current_user_file_dacl_for_test(sidecar)
                .unwrap();
        }

        assert!(verify_private_history_file(&database).is_err());
        assert!(verify_private_history_file(&sidecars[0]).is_err());
        let prepared = prepare_private_history_target(&database).unwrap();
        drop(prepared);
        verify_private_history_file(&database).unwrap();
        for sidecar in &sidecars[..2] {
            verify_private_history_file(sidecar).unwrap();
        }
    }

    #[test]
    fn private_history_open_creates_and_reverifies_private_target() {
        let root = tempdir().unwrap();
        let path = root.path().join("private-history").join("views.db");
        let connection = open_private_history(&path).unwrap();
        let foreign_keys: i64 = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        let versions: (String, String) = connection
            .query_row(
                "SELECT
                    (SELECT value FROM meta WHERE key='schema_version'),
                    (SELECT value FROM meta WHERE key='history_schema_version')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let journal_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name LIKE 'history_onboarding_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let history_indexes: Vec<String> = {
            let mut statement = connection
                .prepare(
                    "SELECT name FROM sqlite_master
                     WHERE type='index' AND name LIKE 'history_onboarding_batches_%'
                     ORDER BY name",
                )
                .unwrap();
            statement
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(foreign_keys, 1);
        assert_eq!(versions, ("37".to_string(), "1".to_string()));
        assert_eq!(journal_tables, 2);
        assert_eq!(
            history_indexes,
            [
                "history_onboarding_batches_object",
                "history_onboarding_batches_path",
                "history_onboarding_batches_subject_state",
            ]
            .map(str::to_string)
        );
        connection
            .execute(
                "INSERT INTO history_onboarding_batches
                 (batch_id,operator_subject,source_family,source_sha256,
                  source_object_sha256,source_path_sha256,parser_schema_version,
                  scanned_at_unix,candidate_count,excluded_privacy_mode_count,
                  skipped_structural_count)
                 VALUES (?1,'owner','chatgpt_export',zeroblob(32),zeroblob(32),
                         zeroblob(32),1,1,0,0,0)",
                ["a".repeat(64)],
            )
            .unwrap();
        assert!(
            connection
                .execute(
                    "INSERT INTO history_onboarding_candidates
                 (candidate_id,batch_id,operator_subject,conversation_id,turn_id,
                  position,content_sha256,excerpt,kind,created_at_unix)
                 VALUES (?1,?2,'intruder','c','t',0,zeroblob(32),'safe',
                         'operator_turn',1)",
                    ["b".repeat(64), "a".repeat(64)],
                )
                .is_err()
        );
        verify_private_history_target(&path, true).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_history_anchors_an_approved_namespace_alias_before_descendant_io() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let physical_parent = root.path().join("physical-history");
        std::fs::create_dir(&physical_parent).unwrap();
        make_private_history_directory(&physical_parent).unwrap();
        let alias = root.path().join("namespace-alias");
        symlink(&physical_parent, &alias).unwrap();
        let database = alias.join("history.db");
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        make_private_history_directory(&outside).unwrap();

        let connection = open_private_history_with_hook(&database, || {
            std::fs::remove_file(&alias).unwrap();
            symlink(&outside, &alias).unwrap();
        })
        .unwrap();

        assert!(physical_parent.join("history.db").exists());
        assert!(!outside.join("history.db").exists());
        let version: String = connection
            .query_row(
                "SELECT value FROM meta WHERE key='history_schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
    }

    #[test]
    fn history_marker_abort_rolls_back_the_complete_ddl_prefix_atomically() {
        let root = tempdir().unwrap();
        let parent = root.path().join("private-history");
        std::fs::create_dir(&parent).unwrap();
        make_private_history_directory(&parent).unwrap();
        let path = parent.join("history.db");
        let connection = open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_history_schema_version
                 BEFORE INSERT ON meta
                 WHEN NEW.key='history_schema_version'
                 BEGIN
                     SELECT RAISE(ABORT, 'reject history schema marker');
                 END;",
            )
            .unwrap();
        drop(connection);

        assert!(open_private_history(&path).is_err());
        let connection = open(&path).unwrap();
        let leaked: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE (type='table' OR type='index')
                   AND name LIKE 'history_onboarding_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let marker: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM meta WHERE key='history_schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((leaked, marker), (0, 0));
    }

    #[cfg(unix)]
    #[test]
    fn fresh_history_symlink_swap_cannot_create_external_target() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let database = root.path().join("history").join("history.db");
        let external = root.path().join("must-not-exist.db");
        let result = open_private_history_with_hook(&database, || {
            std::fs::remove_file(&database).unwrap();
            symlink(&external, &database).unwrap();
        });
        assert!(result.is_err());
        assert!(!external.exists());
    }

    #[cfg(unix)]
    #[test]
    fn existing_history_swap_to_views_database_cannot_mutate_views() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let history = root.path().join("history").join("history.db");
        drop(open_private_history(&history).unwrap());
        let views = root.path().join("views.db");
        drop(open(&views).unwrap());
        let before = std::fs::read(&views).unwrap();
        let result = open_private_history_with_hook(&history, || {
            std::fs::remove_file(&history).unwrap();
            symlink(&views, &history).unwrap();
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&views).unwrap(), before);
        let views = open(&views).unwrap();
        let version: String = views
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let history_tables: i64 = views
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name LIKE 'history_onboarding_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((version.as_str(), history_tables), ("37", 0));
    }

    #[cfg(unix)]
    #[test]
    fn existing_history_regular_replacement_fails_identity_rebind() {
        let root = tempdir().unwrap();
        let history = root.path().join("history").join("history.db");
        drop(open_private_history(&history).unwrap());
        let replacement = root.path().join("replacement.db");
        std::fs::copy(&history, &replacement).unwrap();
        let moved = root.path().join("original.db");
        let result = open_private_history_with_hook(&history, || {
            std::fs::rename(&history, &moved).unwrap();
            std::fs::rename(&replacement, &history).unwrap();
        });
        let error = result.err().expect("replacement must fail");
        assert!(
            format!("{error:#}").contains("private History database identity changed"),
            "replacement must reach the exact identity boundary: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_history_migration_never_reopens_a_swapped_views_path() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let parent = root.path().join("history");
        std::fs::create_dir(&parent).unwrap();
        make_private_history_directory(&parent).unwrap();
        let history = parent.join("history.db");
        let legacy = open(&history).unwrap();
        legacy
            .execute("UPDATE meta SET value='36' WHERE key='schema_version'", [])
            .unwrap();
        drop(legacy);
        let views = root.path().join("views.db");
        drop(open(&views).unwrap());
        let views_before = std::fs::read(&views).unwrap();
        let moved = root.path().join("legacy-original.db");

        let result = open_private_history_with_hooks(
            &history,
            || {},
            || {
                std::fs::rename(&history, &moved).unwrap();
                symlink(&views, &history).unwrap();
            },
        );
        let error = result.err().expect("swapped migration must fail");
        assert!(
            format!("{error:#}").contains("rebind prepared private History database"),
            "migration must fail at the final no-follow rebind: {error:#}"
        );
        assert_eq!(std::fs::read(&views).unwrap(), views_before);
        let views = open(&views).unwrap();
        let version: String = views
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let history_tables: i64 = views
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name LIKE 'history_onboarding_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((version.as_str(), history_tables), ("37", 0));
    }

    #[test]
    fn preexisting_private_empty_database_is_not_mistaken_for_fresh_prepare() {
        let root = tempdir().unwrap();
        let parent = root.path().join("private-history");
        std::fs::create_dir(&parent).unwrap();
        make_private_history_directory(&parent).unwrap();
        let path = parent.join("history.db");
        create_private_history_file(&path).unwrap();

        assert!(open_private_history(&path).is_err());
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn adversarial_preexisting_history_sidecars_fail_before_database_creation() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

        for attack in ["weak", "hardlink", "symlink"] {
            let root = tempdir().unwrap();
            let parent = root.path().join("private-history");
            std::fs::create_dir(&parent).unwrap();
            make_private_history_directory(&parent).unwrap();
            let database = parent.join("history.db");
            let sidecar = sqlite_sidecar_paths(&database)[0].clone();
            match attack {
                "weak" => {
                    std::fs::write(&sidecar, b"weak-sidecar").unwrap();
                    std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                "hardlink" => {
                    let anchor = parent.join("anchor");
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&anchor)
                        .unwrap();
                    std::fs::hard_link(anchor, &sidecar).unwrap();
                }
                "symlink" => {
                    let target = parent.join("target");
                    std::fs::write(&target, b"symlink-target").unwrap();
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    symlink(target, &sidecar).unwrap();
                }
                _ => unreachable!(),
            }
            let before = std::fs::read(&sidecar).unwrap();
            assert!(open_private_history(&database).is_err(), "attack={attack}");
            assert!(!database.exists(), "attack={attack}");
            assert_eq!(std::fs::read(&sidecar).unwrap(), before, "attack={attack}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn fresh_private_history_sidecars_are_handle_hardened_to_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempdir().unwrap();
        let database = root.path().join("history").join("history.db");
        let connection = open_private_history(&database).unwrap();
        let sidecars = sqlite_sidecar_paths(&database);
        let present: Vec<_> = sidecars.iter().filter(|path| path.exists()).collect();
        assert!(
            !present.is_empty(),
            "fresh WAL history must create a sidecar"
        );
        for sidecar in present {
            let mode = std::fs::metadata(sidecar).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        drop(connection);
    }

    #[cfg(windows)]
    #[test]
    fn private_history_normal_drop_releases_file_before_namespace() {
        let fixture = tempdir().unwrap();
        let parent = fixture.path().join("history");
        let database = parent.join("history.db");
        let moved = fixture.path().join("history-after-normal-drop");
        let connection = open_private_history(&database).unwrap();

        drop(connection);
        std::fs::rename(&parent, &moved).unwrap();
        assert!(moved.join("history.db").exists());
    }

    #[cfg(windows)]
    #[test]
    fn private_history_connection_holds_namespace_delete_fences_until_drop() {
        let fixture = tempdir().unwrap();
        let parent = fixture.path().join("history");
        let database = parent.join("history.db");
        let moved_parent = fixture
            .path()
            .join(format!("history-moved-{}", std::process::id()));
        let PrivateHistoryConnection {
            connection: sqlite,
            _file_fence: file_fence,
            _parent_fence: parent_fence,
            _namespace_fence: fence,
        } = open_private_history(&database).unwrap();
        drop(sqlite);
        drop(file_fence);

        // The opaque import-root capability is intentionally no longer relied
        // on for this connection-level promise. The explicit minimal-access
        // parent fence alone must reject namespace mutation until it drops.
        drop(fence);
        assert!(std::fs::rename(&parent, &moved_parent).is_err());
        assert!(database.exists());

        for entry in std::iter::once(database.clone()).chain(sqlite_sidecar_paths(&database)) {
            if entry.exists() {
                std::fs::remove_file(entry).unwrap();
            }
        }
        assert!(std::fs::remove_dir(&parent).is_err());

        drop(parent_fence);
        std::fs::remove_dir(&parent).unwrap();
        assert!(!parent.exists());
        assert!(!moved_parent.exists());
    }

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
        for table in &[
            "idx_episode",
            "idx_provider",
            "wal_cursor",
            "meta",
            "idx_omi_conversations",
            "idx_omi_segments",
            "idx_omi_media",
            "idx_omi_actions",
            "idx_omi_state",
        ] {
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
                conn.query_row("SELECT value FROM meta WHERE key='multi_key'", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap()
            }),
            exec2.with_reader(|conn| {
                conn.query_row("SELECT value FROM meta WHERE key='multi_key'", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap()
            }),
            exec3.with_reader(|conn| {
                conn.query_row("SELECT value FROM meta WHERE key='multi_key'", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap()
            }),
        );
        assert_eq!(a, "99");
        assert_eq!(b, "99");
        assert_eq!(c, "99");
    }

    /// TRAIL-04 P1 regression: parallel FIRST-SIGHT identity resolves through the
    /// executor must converge on ONE uuid with no duplicate aliases, no orphan
    /// identities, and no busy/locked errors — proving the fast-read(reader) /
    /// slow-create(WRITER) split keeps every INSERT on the single writer (the
    /// old code ran the writing `resolve_or_create` on the reader pool).
    #[tokio::test]
    async fn trail04_parallel_first_sight_identity_single_writer_no_dup() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let exec = ViewsExecutor::open(&path, 4).expect("open executor");

        // 12 concurrent first-sight resolves for the SAME triple, each using the
        // production path: read-only lookup on the pool, then create under the
        // single writer when absent.
        let mut handles = Vec::new();
        for _ in 0..12 {
            let e = exec.clone();
            handles.push(tokio::spawn(async move {
                if let Some(uuid) = e
                    .with_reader(|c| {
                        crate::channels::identity::lookup_human_uuid(
                            c, "telegram", "user-1", "chat-1",
                        )
                    })
                    .await
                    .expect("reader lookup must not error (busy/locked)")
                {
                    return uuid;
                }
                e.with_writer(|c| {
                    crate::channels::identity::resolve_or_create_human_uuid(
                        c, "telegram", "user-1", "chat-1",
                    )
                })
                .await
                .expect("writer create must not error (busy/locked)")
            }));
        }
        let mut uuids = std::collections::HashSet::new();
        for h in handles {
            uuids.insert(h.await.unwrap());
        }
        let distinct_count = uuids.len();
        assert!(
            distinct_count == 1,
            "concurrent first-sight must converge on exactly one UUID"
        );

        let alias_count: i64 = exec
            .with_reader(|c| {
                c.query_row("SELECT count(*) FROM idx_human_identity_aliases", [], |r| {
                    r.get(0)
                })
                .unwrap()
            })
            .await;
        let identity_count: i64 = exec
            .with_reader(|c| {
                c.query_row("SELECT count(*) FROM idx_human_identity", [], |r| r.get(0))
                    .unwrap()
            })
            .await;
        assert_eq!(alias_count, 1, "exactly one alias row (no duplicates)");
        assert_eq!(identity_count, 1, "exactly one identity row (no orphans)");
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
