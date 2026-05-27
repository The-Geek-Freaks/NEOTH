//! Stage 6 — `profile.apply` Effect Adapter. Schicht-1 boundary.
//!
//! Takes a guarded `ProfileDelta` (already passed validate + claim_guard),
//! emits one `PROFILE_DELTA` WAL frame per accepted claim, and writes a
//! mirror row into `idx_profile` so the recall surface sees the new
//! profile state without re-parsing the WAL.
//!
//! Idempotency: the `extraction_id` field on the delta serves as the
//! idempotency key. `apply_once` checks `idx_profile` for prior rows
//! with the same `extraction_id` + skips re-application — the same
//! delta replayed twice produces one set of rows. The spec calls this
//! out in §profile_apply.
//!
//! What this stage does (current state, ratified by the contradiction-
//! resolver session 2026-05-15):
//!   - **Supersede contradicted claims** — when a new claim contradicts
//!     an active row for the same `field`, emits `PROFILE_SUPERSEDED`
//!     + marks the prior row's `superseded_at`. See `supersede_profile_row`.
//!   - **Reinforce same-value claims** — when a new claim matches an
//!     existing row's value with higher (or equal) confidence, emits
//!     `PROFILE_REINFORCED` + bumps `confidence_pct` saturatingly.
//!     See `reinforce_profile_row`.
//!   - **Insert genuinely new claims** — emits `PROFILE_DELTA` + writes
//!     a fresh `idx_profile` row.
//!
//! What this stage still does NOT do (real Phase-2 / v0.3-alpha follow-ups):
//!   - **region_tag wire-header cryptographic enforcement** — waits on
//!     the wire-format extension tracked in `SPEC_wire_header_v2_slim.md`.
//!   - **TOMBSTONE-anchored physical WAL rewrite** for
//!     `neoth memory --forget <topic>` — current path SQLite-wipes the
//!     row; rewriting the WAL bytes is Phase-2.
//!   - **Codex-flagged consistency hole** at the post-commit / pre-WAL
//!     emit boundary (Pick #11 — Option B WAL-first materialisation,
//!     ratified by ADR-002 / 2026-05-18 architecture review).
//!
//! ## CDX-02 rollback substrate
//!
//! profile/apply.rs does NOT emit `PRE_MUTATION_SNAPSHOT` (0xF2) frames
//! for its idx_profile inserts/updates, and that's intentional. The
//! existing audit frames (`PROFILE_DELTA` 0xB0 / `PROFILE_REINFORCED`
//! 0xB1 / `PROFILE_SUPERSEDED` 0xB2) — Hypothalamus band 0xB0..=0xBF,
//! compile-time enforced in `wal/events.rs` — already carry every byte
//! the `neoth rollback` apply path would need to invert:
//!   - **DELTA** insert → inverse is DELETE by `event_id` (audit
//!     frame carries the inserted row's `event_id`).
//!   - **REINFORCED** confidence bump → inverse is UPDATE `confidence`
//!     back to the prior value (audit frame carries `old_confidence`).
//!   - **SUPERSEDED** mark → inverse is UPDATE `superseded_at = NULL`
//!     on the prior row + DELETE the new row (audit frame carries
//!     both `prior_event_id` and `new_event_id`).
//!
//! Stacking SqlMutation snapshots on top would double-write the same
//! information into the WAL (~2× growth for a write-heavy profile
//! extraction pipeline) for zero new operator capability. The future
//! `neoth profile rollback --to <event_id>` operator surface reads the
//! audit frames directly to produce the inverse plan.
//!
//! If the operator NEEDS coarse-grained "wipe everything since this
//! point" semantics (which the per-claim audit can't reconstruct
//! cheaply), `neoth memory --forget <topic>` is the existing path —
//! today it SQLite-wipes the affected rows; WAL TOMBSTONE-anchored
//! physical rewrite of the underlying bytes is Phase-2.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

use crate::profile::delta::{ProfileDelta, RawClaim};
use crate::wal::events::{
    EVENT_TYPE_PROFILE_DELTA, EVENT_TYPE_PROFILE_DELTA_BLOCKED, EVENT_TYPE_PROFILE_REDACT_BLOCKED,
    EVENT_TYPE_PROFILE_REINFORCED, EVENT_TYPE_PROFILE_SUPERSEDED,
};
use crate::wal::writer::WalWriterHandle;

/// Outcome of one apply pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// Number of new `idx_profile` rows written. 0 when the delta was
    /// already applied (idempotency hit).
    pub claims_applied: usize,
    /// Number of existing rows reinforced (same value, equal-or-higher
    /// confidence). Reinforce bumps the existing row's confidence
    /// without creating a new row.
    pub claims_reinforced: usize,
    /// Number of existing rows superseded (different value on the
    /// same field). The old row gets `superseded_at = now`; the new
    /// row is inserted alongside as a fresh `PROFILE_DELTA`.
    pub claims_superseded: usize,
    /// ADV-04 (Session 28) — number of per-claim inserts skipped
    /// because the field has an active `never_recreate=1` redaction.
    /// Defence-in-depth complement to the Stage-5 guard: a delta can
    /// pass the guard then sit in `idx_profile_pending` while the
    /// operator adds a redaction; this counter proves the apply step
    /// honoured the fresh redaction. Each skipped claim emits one
    /// `EVENT_TYPE_PROFILE_REDACT_BLOCKED` frame for the audit trail.
    pub claims_redact_blocked: usize,
    /// True if this delta had been seen before — skipped via the
    /// extraction_id check.
    pub idempotent_skip: bool,
}

/// Apply a guarded delta to the profile state. Writes one
/// `PROFILE_DELTA` WAL event per claim + one row in `idx_profile`,
/// inside a single SQLite transaction so partial application is
/// impossible.
///
/// Returns `ApplyOutcome` describing what was actually written —
/// repeat calls with the same delta return `idempotent_skip: true`.
pub async fn apply_delta(
    conn: &mut Connection,
    writer: &WalWriterHandle,
    delta: &ProfileDelta,
    now_unix: i64,
) -> Result<ApplyOutcome> {
    if delta.extraction_id.trim().is_empty() {
        anyhow::bail!("profile.apply: refusing to apply delta with empty extraction_id");
    }
    if claims_already_applied(conn, &delta.extraction_id)? {
        // Idempotency-skip path. A prior `apply_delta` already committed
        // the idx_profile rows for this `extraction_id`. The outbox
        // drain runs AFTER the SQLite commit (line ~222 below), so a
        // crash between "tx.commit" and "drain finished" leaves outbox
        // rows whose owning rows already exist — without this best-
        // effort drain, those orphans only get cleared when some OTHER
        // extraction_id arrives (and `drain_outbox_for_extraction`
        // never touches them) or when `drain_outbox_all` runs on
        // daemon startup. Drain them here so a retry of the same
        // extraction always converges, even if startup-drain didn't
        // run yet.
        if let Err(e) = drain_outbox_for_extraction(conn, writer, &delta.extraction_id).await {
            tracing::warn!(
                error = %e,
                extraction_id = %delta.extraction_id,
                "profile.apply: idempotent-skip outbox drain failed; rows will replay later"
            );
        }
        return Ok(ApplyOutcome {
            claims_applied: 0,
            claims_reinforced: 0,
            claims_superseded: 0,
            claims_redact_blocked: 0,
            idempotent_skip: true,
        });
    }

    // Per-claim contradiction resolution: for each new claim, look up
    // the most-recent active idx_profile row for the same field. Three
    // branches:
    //
    //   1. No prior row → INSERT fresh + PROFILE_DELTA frame.
    //   2. Prior row, identical value:
    //      - new confidence > prior → REINFORCE (bump prior confidence
    //        + last_access, PROFILE_REINFORCED frame, no new row).
    //      - new confidence <= prior → drop redundant claim, no frame.
    //   3. Prior row, different value → SUPERSEDE (mark prior
    //      `superseded_at = now`, PROFILE_SUPERSEDED frame, insert
    //      new row, PROFILE_DELTA frame).
    //
    // All branches commit atomically in one SQLite transaction so the
    // post-state is consistent — partial application is impossible.
    let mut applied = 0usize;
    let mut reinforced = 0usize;
    let mut superseded = 0usize;
    let mut redact_blocked = 0usize;
    // We collect per-claim decisions inside the tx, then emit WAL
    // frames AFTER the commit. That ordering means a tx-failure leaves
    // the WAL untouched (no audit row for a write that never landed).
    let mut to_emit: Vec<ClaimEvent> = Vec::with_capacity(delta.claims.len());

    let tx = conn.transaction().context("begin apply tx")?;
    for claim in &delta.claims {
        // ADV-04 (Session 28) — redaction recheck. The Stage-5 guard
        // already filtered redacted fields, BUT a delta can sit in
        // `idx_profile_pending` between approval-gate parking and
        // operator-driven `neoth profile approve`; an operator who
        // adds a redaction in that window expects the apply step to
        // honour it. We re-lookup the active redaction per claim,
        // drop the insert + emit a `PROFILE_REDACT_BLOCKED` audit
        // frame post-commit when one is present. Cheap (single
        // indexed row lookup) + idempotent (no row written so retry
        // is a no-op).
        if let Some(redaction) = crate::profile::redaction::lookup_active(&tx, &claim.field)?
            && redaction.never_recreate
        {
            redact_blocked += 1;
            to_emit.push(ClaimEvent::RedactBlocked {
                field: claim.field.clone(),
                redaction_id: redaction.id,
                asserted_by: redaction.asserted_by.clone(),
            });
            continue;
        }
        let prior = lookup_active_for_field(&tx, &claim.field)?;
        let value_json = serde_json::to_string(&claim.value_json).unwrap_or_else(|_| "null".into());
        match prior {
            None => {
                let event_id = insert_profile_row(
                    &tx,
                    &delta.extraction_id,
                    claim,
                    &delta.guard_version,
                    now_unix,
                )?;
                applied += 1;
                to_emit.push(ClaimEvent::Delta {
                    claim: claim.clone(),
                    event_id,
                });
            }
            Some(p) if p.value_json == value_json => {
                if claim.confidence > p.confidence as f32 {
                    reinforce_profile_row(&tx, p.id, claim.confidence as f64, now_unix)?;
                    reinforced += 1;
                    to_emit.push(ClaimEvent::Reinforced {
                        prior_event_id: p.event_id,
                        field: claim.field.clone(),
                        old_confidence: p.confidence as f32,
                        new_confidence: claim.confidence,
                    });
                }
                // Equal-or-lower confidence repeat: silently drop.
            }
            Some(p) => {
                supersede_profile_row(&tx, p.id, now_unix)?;
                let event_id = insert_profile_row(
                    &tx,
                    &delta.extraction_id,
                    claim,
                    &delta.guard_version,
                    now_unix,
                )?;
                applied += 1;
                superseded += 1;
                to_emit.push(ClaimEvent::Superseded {
                    prior_event_id: p.event_id,
                    field: claim.field.clone(),
                    old_value_hash: xxhash_rust::xxh3::xxh3_64(p.value_json.as_bytes()),
                    new_value_hash: xxhash_rust::xxh3::xxh3_64(value_json.as_bytes()),
                });
                to_emit.push(ClaimEvent::Delta {
                    claim: claim.clone(),
                    event_id,
                });
            }
        }
    }

    // Pick #12 (Session 14, ADR-002 ratified) — Outbox pattern closes
    // the post-commit / pre-WAL-emit consistency hole. Each pending
    // ClaimEvent is serialised + inserted into `idx_profile_outbox`
    // inside the SAME transaction as the idx_profile rows. After the
    // tx commits, the drain loop emits WAL frames + deletes outbox
    // rows on each successful ack. A crash between commit + drain
    // leaves rows in the outbox; the next `apply_delta` invocation
    // OR daemon startup replays them via `drain_outbox_all`.
    for event in &to_emit {
        let (event_type, payload) =
            serialise_claim_event(&delta.extraction_id, &delta.guard_version, event, now_unix)?;
        tx.execute(
            "INSERT INTO idx_profile_outbox \
             (extraction_id, event_type, payload, enqueued_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![&delta.extraction_id, event_type as i64, payload, now_unix],
        )
        .context("insert idx_profile_outbox row")?;
    }
    tx.commit().context("commit apply tx")?;

    // Drain the rows we just inserted (and any leftover rows from a
    // prior-run crash for this extraction). Best-effort — failure to
    // drain leaves the rows for the next replay attempt.
    if let Err(e) = drain_outbox_for_extraction(conn, writer, &delta.extraction_id).await {
        tracing::warn!(
            error = %e,
            extraction_id = %delta.extraction_id,
            "profile.apply: outbox drain failed; rows will replay on next attempt"
        );
    }

    Ok(ApplyOutcome {
        claims_applied: applied,
        claims_reinforced: reinforced,
        claims_superseded: superseded,
        claims_redact_blocked: redact_blocked,
        idempotent_skip: false,
    })
}

/// Pick #12 (Session 14) — drain pending WAL emits for one extraction.
/// Reads outbox rows ordered by id, emits each via `writer.append`,
/// deletes the row on ack success. Failures abort the loop early; any
/// remaining rows survive for the next replay.
pub async fn drain_outbox_for_extraction(
    conn: &mut Connection,
    writer: &WalWriterHandle,
    extraction_id: &str,
) -> Result<usize> {
    // Snapshot rows before iterating so a long-running drain doesn't
    // hold a read transaction while await-ing the WAL writer.
    let rows: Vec<(i64, i64, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT id, event_type, payload FROM idx_profile_outbox \
             WHERE extraction_id = ?1 ORDER BY id ASC",
        )?;
        let mapped = stmt.query_map(rusqlite::params![extraction_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut drained = 0usize;
    for (row_id, event_type, payload) in rows {
        let event_type_u8 = u8::try_from(event_type)
            .with_context(|| format!("outbox row {row_id}: event_type out of u8 range"))?;
        let header = crate::wal::HeaderBuilder::new(event_type_u8, &payload).build();
        writer
            .append(header, payload)
            .await
            .with_context(|| format!("drain outbox row {row_id}: WAL append"))?;
        conn.execute(
            "DELETE FROM idx_profile_outbox WHERE id = ?1",
            rusqlite::params![row_id],
        )
        .with_context(|| format!("drain outbox row {row_id}: DELETE"))?;
        drained += 1;
    }
    Ok(drained)
}

/// Pick #12 (Session 14) — sweep ALL outbox rows on daemon startup +
/// before the first `apply_delta` call. Returns the count drained.
/// Failures during the sweep do NOT block the caller; they leave the
/// surviving rows for the next attempt.
pub async fn drain_outbox_all(conn: &mut Connection, writer: &WalWriterHandle) -> Result<usize> {
    let extractions: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT extraction_id FROM idx_profile_outbox ORDER BY enqueued_at ASC",
        )?;
        let mapped = stmt.query_map([], |row| row.get::<_, String>(0))?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut total = 0usize;
    for extraction_id in extractions {
        match drain_outbox_for_extraction(conn, writer, &extraction_id).await {
            Ok(n) => total += n,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    extraction_id = %extraction_id,
                    "drain_outbox_all: extraction failed, continuing with next"
                );
            }
        }
    }
    Ok(total)
}

/// Sync helper — builds the (event_type, payload_bytes) tuple a
/// `ClaimEvent` lowers to. Pure serialisation, no I/O. Lets us insert
/// into the outbox INSIDE the SQLite transaction (no async) and drain
/// outside (async).
fn serialise_claim_event(
    extraction_id: &str,
    guard_version: &str,
    event: &ClaimEvent,
    now_unix: i64,
) -> Result<(u8, Vec<u8>)> {
    match event {
        ClaimEvent::Delta { claim, event_id } => {
            let payload = serde_json::to_vec(&serde_json::json!({
                "extraction_id": extraction_id,
                "event_id": event_id,
                "field": claim.field,
                "value_json": claim.value_json,
                "confidence": claim.confidence,
                "evidence_event_ids": claim.evidence_event_ids,
                "guard_version": guard_version,
                "ts_unix": now_unix,
            }))
            .context("serialise PROFILE_DELTA payload")?;
            Ok((EVENT_TYPE_PROFILE_DELTA, payload))
        }
        ClaimEvent::Reinforced {
            prior_event_id,
            field,
            old_confidence,
            new_confidence,
        } => {
            let payload = serde_json::to_vec(&serde_json::json!({
                "prior_event_id": prior_event_id,
                "field": field,
                "old_confidence": old_confidence,
                "new_confidence": new_confidence,
                "extraction_id": extraction_id,
                "ts_unix": now_unix,
            }))
            .context("serialise PROFILE_REINFORCED payload")?;
            Ok((EVENT_TYPE_PROFILE_REINFORCED, payload))
        }
        ClaimEvent::Superseded {
            prior_event_id,
            field,
            old_value_hash,
            new_value_hash,
        } => {
            let payload = serde_json::to_vec(&serde_json::json!({
                "prior_event_id": prior_event_id,
                "field": field,
                "old_value_hash": old_value_hash,
                "new_value_hash": new_value_hash,
                "extraction_id": extraction_id,
                "ts_unix": now_unix,
            }))
            .context("serialise PROFILE_SUPERSEDED payload")?;
            Ok((EVENT_TYPE_PROFILE_SUPERSEDED, payload))
        }
        ClaimEvent::RedactBlocked {
            field,
            redaction_id,
            asserted_by,
        } => {
            // NB: no `value_json` in this payload — operator redacted
            // the field because they don't want any value preserved.
            let payload = serde_json::to_vec(&serde_json::json!({
                "extraction_id": extraction_id,
                "field": field,
                "redaction_id": redaction_id,
                "asserted_by": asserted_by,
                "guard_version": guard_version,
                "ts_unix": now_unix,
            }))
            .context("serialise PROFILE_REDACT_BLOCKED payload")?;
            Ok((EVENT_TYPE_PROFILE_REDACT_BLOCKED, payload))
        }
    }
}

/// Snapshot of an active idx_profile row used by the supersede/reinforce
/// lookup. The fields are the subset the resolver compares.
struct ActiveRow {
    id: i64,
    event_id: i64,
    value_json: String,
    confidence: f64,
}

fn lookup_active_for_field(
    tx: &rusqlite::Transaction<'_>,
    field: &str,
) -> Result<Option<ActiveRow>> {
    // Pick #32 (Session 14, audit-fix): prior `.ok()` collapsed EVERY
    // DB error to `None`, which the caller interprets as "no active
    // row for this field" + inserts a fresh row — silently bypassing
    // the supersede/reinforce contract on transient lock / corrupt /
    // permission errors. `optional()` is the canonical rusqlite
    // pattern: `QueryReturnedNoRows → Ok(None)`, every other error
    // propagates so apply_delta aborts with audit context instead of
    // silently corrupting the profile state.
    use rusqlite::OptionalExtension;
    let row = tx
        .query_row(
            "SELECT id, event_id, value_json, confidence FROM idx_profile \
             WHERE field = ?1 AND superseded_at IS NULL \
             ORDER BY applied_at DESC LIMIT 1",
            rusqlite::params![field],
            |r| {
                Ok(ActiveRow {
                    id: r.get(0)?,
                    event_id: r.get(1)?,
                    value_json: r.get(2)?,
                    confidence: r.get(3)?,
                })
            },
        )
        .optional()
        .with_context(|| format!("lookup active idx_profile row for field `{field}`"))?;
    Ok(row)
}

fn reinforce_profile_row(
    tx: &rusqlite::Transaction<'_>,
    id: i64,
    new_confidence: f64,
    now_unix: i64,
) -> Result<()> {
    tx.execute(
        "UPDATE idx_profile SET confidence = ?1, applied_at = ?2 WHERE id = ?3",
        rusqlite::params![new_confidence, now_unix, id],
    )
    .context("reinforce idx_profile row")?;
    Ok(())
}

fn supersede_profile_row(tx: &rusqlite::Transaction<'_>, id: i64, now_unix: i64) -> Result<()> {
    tx.execute(
        "UPDATE idx_profile SET superseded_at = ?1 WHERE id = ?2",
        rusqlite::params![now_unix, id],
    )
    .context("supersede idx_profile row")?;
    Ok(())
}

/// Per-claim outcome of the contradiction resolver. Drives WAL emission
/// after the SQLite tx commits.
enum ClaimEvent {
    Delta {
        claim: RawClaim,
        event_id: i64,
    },
    Reinforced {
        prior_event_id: i64,
        field: String,
        old_confidence: f32,
        new_confidence: f32,
    },
    Superseded {
        prior_event_id: i64,
        field: String,
        old_value_hash: u64,
        new_value_hash: u64,
    },
    /// ADV-04 (Session 28) — claim was dropped because the field has
    /// an active `never_recreate=1` redaction at apply time. Audit-
    /// only — no row is written in `idx_profile`.
    RedactBlocked {
        field: String,
        redaction_id: i64,
        asserted_by: String,
    },
}

async fn emit_claim_event(
    writer: &WalWriterHandle,
    extraction_id: &str,
    guard_version: &str,
    event: &ClaimEvent,
    now_unix: i64,
) -> Result<()> {
    match event {
        ClaimEvent::Delta { claim, event_id } => {
            emit_profile_delta_frame(
                writer,
                extraction_id,
                claim,
                *event_id,
                guard_version,
                now_unix,
            )
            .await
        }
        ClaimEvent::Reinforced {
            prior_event_id,
            field,
            old_confidence,
            new_confidence,
        } => {
            let payload = serde_json::to_vec(&serde_json::json!({
                "prior_event_id": prior_event_id,
                "field": field,
                "old_confidence": old_confidence,
                "new_confidence": new_confidence,
                "extraction_id": extraction_id,
                "ts_unix": now_unix,
            }))
            .context("serialise PROFILE_REINFORCED payload")?;
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_PROFILE_REINFORCED, &payload).build();
            writer
                .append(header, payload)
                .await
                .context("append PROFILE_REINFORCED frame")?;
            Ok(())
        }
        ClaimEvent::Superseded {
            prior_event_id,
            field,
            old_value_hash,
            new_value_hash,
        } => {
            let payload = serde_json::to_vec(&serde_json::json!({
                "prior_event_id": prior_event_id,
                "field": field,
                "old_value_hash": old_value_hash,
                "new_value_hash": new_value_hash,
                "extraction_id": extraction_id,
                "ts_unix": now_unix,
            }))
            .context("serialise PROFILE_SUPERSEDED payload")?;
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_PROFILE_SUPERSEDED, &payload).build();
            writer
                .append(header, payload)
                .await
                .context("append PROFILE_SUPERSEDED frame")?;
            Ok(())
        }
        ClaimEvent::RedactBlocked {
            field,
            redaction_id,
            asserted_by,
        } => {
            let payload = serde_json::to_vec(&serde_json::json!({
                "extraction_id": extraction_id,
                "field": field,
                "redaction_id": redaction_id,
                "asserted_by": asserted_by,
                "guard_version": guard_version,
                "ts_unix": now_unix,
            }))
            .context("serialise PROFILE_REDACT_BLOCKED payload")?;
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_PROFILE_REDACT_BLOCKED, &payload).build();
            writer
                .append(header, payload)
                .await
                .context("append PROFILE_REDACT_BLOCKED frame")?;
            Ok(())
        }
    }
}

/// Audit-only: emit a `PROFILE_DELTA_BLOCKED` WAL frame for a rejected
/// delta. The caller (typically the dispatcher invoking stage 5) passes
/// the `GuardReason` string + a stable hash so audit rows dedupe.
pub async fn record_blocked(
    writer: &WalWriterHandle,
    extraction_id: &str,
    reason: &str,
    blocked_hash_hex: &str,
    guard_version: &str,
    now_unix: i64,
) -> Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "extraction_id": extraction_id,
        "reason": reason,
        "blocked_delta_hash": blocked_hash_hex,
        "guard_version": guard_version,
        "ts_unix": now_unix,
    }))
    .context("serialise PROFILE_DELTA_BLOCKED payload")?;
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PROFILE_DELTA_BLOCKED, &payload).build();
    writer
        .append(header, payload)
        .await
        .context("append PROFILE_DELTA_BLOCKED frame")?;
    Ok(())
}

fn claims_already_applied(conn: &Connection, extraction_id: &str) -> Result<bool> {
    let n: i64 = conn
        .query_row(
            "SELECT count(*) FROM idx_profile WHERE extraction_id = ?1",
            params![extraction_id],
            |r| r.get(0),
        )
        .context("idempotency check")?;
    Ok(n > 0)
}

fn insert_profile_row(
    tx: &rusqlite::Transaction<'_>,
    extraction_id: &str,
    claim: &RawClaim,
    guard_version: &str,
    now_unix: i64,
) -> Result<i64> {
    let value_json = serde_json::to_string(&claim.value_json).unwrap_or_else(|_| "null".into());
    let evidence_json =
        serde_json::to_string(&claim.evidence_event_ids).unwrap_or_else(|_| "[]".into());
    tx.execute(
        "INSERT INTO idx_profile \
         (extraction_id, event_id, field, value_json, confidence, \
          evidence_event_ids, guard_version, applied_at, superseded_at) \
         VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
        params![
            extraction_id,
            claim.field,
            value_json,
            claim.confidence as f64,
            evidence_json,
            guard_version,
            now_unix,
        ],
    )
    .context("insert idx_profile row")?;
    let row_id = tx.last_insert_rowid();
    // `event_id` mirrors the autoincrement id for v0.1. When the WAL
    // ingress gate lands and assigns real event_ids upstream, this
    // becomes the WAL-side id; today the mirror id is sufficient for
    // recall queries.
    tx.execute(
        "UPDATE idx_profile SET event_id = ?1 WHERE id = ?1",
        params![row_id],
    )
    .context("backfill event_id on idx_profile row")?;
    Ok(row_id)
}

async fn emit_profile_delta_frame(
    writer: &WalWriterHandle,
    extraction_id: &str,
    claim: &RawClaim,
    event_id: i64,
    guard_version: &str,
    now_unix: i64,
) -> Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "extraction_id": extraction_id,
        "event_id": event_id,
        "field": claim.field,
        "value_json": claim.value_json,
        "confidence": claim.confidence,
        "evidence_event_ids": claim.evidence_event_ids,
        "guard_version": guard_version,
        "ts_unix": now_unix,
    }))
    .context("serialise PROFILE_DELTA payload")?;
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PROFILE_DELTA, &payload).build();
    writer
        .append(header, payload)
        .await
        .context("append PROFILE_DELTA frame")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use crate::wal::writer::spawn;
    use tempfile::tempdir;

    fn claim(field: &str, confidence: f32) -> RawClaim {
        RawClaim {
            field: field.into(),
            value_json: serde_json::json!("v"),
            confidence,
            reasoning: "".into(),
            evidence_event_ids: vec![10, 20],
        }
    }

    fn delta() -> ProfileDelta {
        ProfileDelta {
            extraction_id: "ext-abc".into(),
            conversation_hash: "hash".into(),
            claims: vec![claim("identity.location", 0.85), claim("skills.rust", 0.95)],
            guard_version: "0.1.0".into(),
            ..Default::default()
        }
    }

    async fn setup() -> (
        tempfile::TempDir,
        Connection,
        WalWriterHandle,
        tokio::task::JoinHandle<()>,
    ) {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        let (writer, join) = spawn(dir.path().join("seg.wal")).unwrap();
        (dir, conn, writer, join)
    }

    #[tokio::test]
    async fn apply_writes_one_row_per_claim() {
        let (_dir, mut conn, writer, join) = setup().await;
        let out = apply_delta(&mut conn, &writer, &delta(), 1).await.unwrap();
        assert_eq!(out.claims_applied, 2);
        assert!(!out.idempotent_skip);

        let n: i64 = conn
            .query_row("SELECT count(*) FROM idx_profile", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn apply_is_idempotent_on_same_extraction_id() {
        let (_dir, mut conn, writer, join) = setup().await;
        let _ = apply_delta(&mut conn, &writer, &delta(), 1).await.unwrap();
        let out = apply_delta(&mut conn, &writer, &delta(), 2).await.unwrap();
        assert_eq!(out.claims_applied, 0);
        assert!(out.idempotent_skip);

        // Still only 2 rows total.
        let n: i64 = conn
            .query_row("SELECT count(*) FROM idx_profile", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);

        drop(writer);
        let _ = join.await;
    }

    // ── ADV-04 (Session 28) — apply-step redaction recheck ─────────────

    #[tokio::test]
    async fn apply_drops_claim_when_field_is_redacted_at_apply_time() {
        // Operator-asserted redaction for `identity.location` is added
        // AFTER the delta was queued (mirrors the
        // approval-gate-parking-then-redaction race window). The
        // apply step MUST honour the fresh redaction + skip the
        // insert + emit a PROFILE_REDACT_BLOCKED audit frame.
        let (_dir, mut conn, writer, join) = setup().await;

        // Seed an active redaction for one of the two delta fields.
        let redaction_id = crate::profile::redaction::add(
            &conn,
            "identity.location",
            true, // never_recreate
            Some("operator wiped"),
            "alex",
            1,
        )
        .unwrap();
        assert!(redaction_id > 0);

        // Apply the standard 2-claim delta (one field is redacted,
        // the other is not).
        let out = apply_delta(&mut conn, &writer, &delta(), 2).await.unwrap();

        // identity.location → blocked; skills.rust → applied.
        assert_eq!(out.claims_applied, 1);
        assert_eq!(out.claims_redact_blocked, 1);
        assert!(!out.idempotent_skip);

        // Exactly one row landed — the non-redacted one.
        let n: i64 = conn
            .query_row("SELECT count(*) FROM idx_profile", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        let surviving_field: String = conn
            .query_row("SELECT field FROM idx_profile", [], |r| r.get(0))
            .unwrap();
        assert_eq!(surviving_field, "skills.rust");

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn apply_skips_all_when_every_field_is_redacted() {
        // Both delta fields redacted at apply time → zero rows
        // written + two skip counters + zero idempotency hit (this is
        // a first-attempt apply that just happens to skip every
        // claim, not a re-apply).
        let (_dir, mut conn, writer, join) = setup().await;
        crate::profile::redaction::add(&conn, "identity.location", true, None, "alex", 1).unwrap();
        crate::profile::redaction::add(&conn, "skills.rust", true, None, "alex", 1).unwrap();

        let out = apply_delta(&mut conn, &writer, &delta(), 2).await.unwrap();
        assert_eq!(out.claims_applied, 0);
        assert_eq!(out.claims_redact_blocked, 2);
        assert!(!out.idempotent_skip);

        let n: i64 = conn
            .query_row("SELECT count(*) FROM idx_profile", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn apply_honours_only_active_never_recreate_redactions() {
        // A revoked redaction (or one with never_recreate=false) must
        // NOT block the apply — the recheck pairs both flags so a
        // soft "I redacted this once, then changed my mind" cannot
        // accidentally pin the field forever.
        let (_dir, mut conn, writer, join) = setup().await;
        // never_recreate=false → must not block.
        crate::profile::redaction::add(&conn, "identity.location", false, None, "alex", 1).unwrap();

        let out = apply_delta(&mut conn, &writer, &delta(), 2).await.unwrap();
        // Both claims land — the redaction was advisory-only.
        assert_eq!(out.claims_applied, 2);
        assert_eq!(out.claims_redact_blocked, 0);

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn same_field_same_value_higher_confidence_reinforces() {
        let (_dir, mut conn, writer, join) = setup().await;
        // First extraction: confidence 0.7
        let d1 = ProfileDelta {
            extraction_id: "ext-1".into(),
            conversation_hash: "h1".into(),
            claims: vec![RawClaim {
                field: "identity.location".into(),
                value_json: serde_json::json!("Berlin"),
                confidence: 0.7,
                reasoning: "".into(),
                evidence_event_ids: vec![],
            }],
            guard_version: "0.1.0".into(),
            ..Default::default()
        };
        let o1 = apply_delta(&mut conn, &writer, &d1, 100).await.unwrap();
        assert_eq!(o1.claims_applied, 1);

        // Second extraction: same value, higher confidence
        let d2 = ProfileDelta {
            extraction_id: "ext-2".into(),
            conversation_hash: "h2".into(),
            claims: vec![RawClaim {
                field: "identity.location".into(),
                value_json: serde_json::json!("Berlin"),
                confidence: 0.9,
                reasoning: "".into(),
                evidence_event_ids: vec![],
            }],
            guard_version: "0.1.0".into(),
            ..Default::default()
        };
        let o2 = apply_delta(&mut conn, &writer, &d2, 200).await.unwrap();
        assert_eq!(o2.claims_applied, 0);
        assert_eq!(o2.claims_reinforced, 1);
        assert_eq!(o2.claims_superseded, 0);

        // Still only one idx_profile row, with confidence bumped to 0.9.
        let (n, conf): (i64, f64) = conn
            .query_row(
                "SELECT count(*), MAX(confidence) FROM idx_profile WHERE field = 'identity.location'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(n, 1);
        assert!((conf - 0.9).abs() < 1e-6);

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn same_field_same_value_lower_confidence_silently_drops() {
        let (_dir, mut conn, writer, join) = setup().await;
        let d1 = ProfileDelta {
            extraction_id: "ext-1".into(),
            conversation_hash: "h1".into(),
            claims: vec![RawClaim {
                field: "skills.rust".into(),
                value_json: serde_json::json!(true),
                confidence: 0.9,
                reasoning: "".into(),
                evidence_event_ids: vec![],
            }],
            guard_version: "0.1.0".into(),
            ..Default::default()
        };
        apply_delta(&mut conn, &writer, &d1, 100).await.unwrap();

        let d2 = ProfileDelta {
            extraction_id: "ext-2".into(),
            conversation_hash: "h2".into(),
            claims: vec![RawClaim {
                field: "skills.rust".into(),
                value_json: serde_json::json!(true),
                confidence: 0.5,
                reasoning: "".into(),
                evidence_event_ids: vec![],
            }],
            guard_version: "0.1.0".into(),
            ..Default::default()
        };
        let o2 = apply_delta(&mut conn, &writer, &d2, 200).await.unwrap();
        // Lower-confidence repeat: no change to the row, no reinforce.
        assert_eq!(o2.claims_applied, 0);
        assert_eq!(o2.claims_reinforced, 0);

        let conf: f64 = conn
            .query_row(
                "SELECT confidence FROM idx_profile WHERE field = 'skills.rust'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!((conf - 0.9).abs() < 1e-6);

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn same_field_different_value_supersedes() {
        let (_dir, mut conn, writer, join) = setup().await;
        let d1 = ProfileDelta {
            extraction_id: "ext-1".into(),
            conversation_hash: "h1".into(),
            claims: vec![RawClaim {
                field: "identity.location".into(),
                value_json: serde_json::json!("Hamburg"),
                confidence: 0.8,
                reasoning: "".into(),
                evidence_event_ids: vec![],
            }],
            guard_version: "0.1.0".into(),
            ..Default::default()
        };
        apply_delta(&mut conn, &writer, &d1, 100).await.unwrap();

        let d2 = ProfileDelta {
            extraction_id: "ext-2".into(),
            conversation_hash: "h2".into(),
            claims: vec![RawClaim {
                field: "identity.location".into(),
                value_json: serde_json::json!("Berlin"),
                confidence: 0.85,
                reasoning: "".into(),
                evidence_event_ids: vec![],
            }],
            guard_version: "0.1.0".into(),
            ..Default::default()
        };
        let o2 = apply_delta(&mut conn, &writer, &d2, 200).await.unwrap();
        assert_eq!(o2.claims_applied, 1);
        assert_eq!(o2.claims_superseded, 1);
        assert_eq!(o2.claims_reinforced, 0);

        // Two rows: old one superseded, new one active.
        let active: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_profile \
                 WHERE field = 'identity.location' AND superseded_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active, 1);
        let total: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_profile WHERE field = 'identity.location'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, 2);

        // Live value is now "Berlin".
        let value_json: String = conn
            .query_row(
                "SELECT value_json FROM idx_profile \
                 WHERE field = 'identity.location' AND superseded_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(value_json, "\"Berlin\"");

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn empty_extraction_id_rejected() {
        let (_dir, mut conn, writer, join) = setup().await;
        let mut d = delta();
        d.extraction_id = "".into();
        let err = apply_delta(&mut conn, &writer, &d, 1).await.unwrap_err();
        assert!(err.to_string().contains("empty extraction_id"));
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn record_blocked_writes_audit_frame() {
        let (_dir, _conn, writer, join) = setup().await;
        record_blocked(&writer, "ext-x", "no_first_person", "deadbeef", "0.1.0", 42)
            .await
            .unwrap();
        drop(writer);
        let _ = join.await;
        // The frame existence is implicitly verified by the no-panic path
        // — the WAL writer returns Err when the append fails. A deeper
        // assertion would re-read the WAL bytes; that's covered by
        // wal::writer's own tests.
    }

    #[tokio::test]
    async fn empty_claims_apply_records_zero_but_marks_extraction_seen() {
        let (_dir, mut conn, writer, join) = setup().await;
        let d = ProfileDelta {
            extraction_id: "ext-empty".into(),
            conversation_hash: "h".into(),
            claims: vec![],
            ..Default::default()
        };
        let out = apply_delta(&mut conn, &writer, &d, 1).await.unwrap();
        assert_eq!(out.claims_applied, 0);
        assert!(!out.idempotent_skip);

        // Second apply of the empty delta — extraction_id is registered
        // via the zero rows on the FIRST pass? No — empty claims means
        // no rows, which means the idempotency check finds nothing and
        // re-runs. For v0.1 that's the correct behaviour: empty deltas
        // are cheap to re-process.
        let out2 = apply_delta(&mut conn, &writer, &d, 2).await.unwrap();
        assert_eq!(out2.claims_applied, 0);
        // idempotent_skip stays false because no prior rows exist.
        assert!(!out2.idempotent_skip);

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn applied_row_carries_field_value_and_confidence() {
        let (_dir, mut conn, writer, join) = setup().await;
        let _ = apply_delta(&mut conn, &writer, &delta(), 100)
            .await
            .unwrap();
        let (field, value_json, confidence, applied_at): (String, String, f64, i64) = conn
            .query_row(
                "SELECT field, value_json, confidence, applied_at FROM idx_profile \
                 WHERE field = 'skills.rust' AND extraction_id = 'ext-abc'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(field, "skills.rust");
        assert_eq!(value_json, "\"v\"");
        assert!((confidence - 0.95_f64).abs() < 1e-6);
        assert_eq!(applied_at, 100);
        drop(writer);
        let _ = join.await;
    }

    // ── Pick #12 (Session 14) — outbox consistency invariants ──────────────

    #[tokio::test]
    async fn outbox_is_empty_after_successful_apply_plus_drain() {
        // Happy path: apply_delta enqueues outbox rows INSIDE the
        // SQLite tx, then drains them after commit. End state must
        // be an empty outbox — no leftover audit-debt rows.
        let (_dir, mut conn, writer, join) = setup().await;
        let _ = apply_delta(&mut conn, &writer, &delta(), 1).await.unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM idx_profile_outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n, 0,
            "outbox must be empty after successful drain; got {n} leftover rows"
        );
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn outbox_replays_leftover_rows_via_drain_all() {
        // Simulate a crash: insert outbox rows by hand WITHOUT
        // emitting them. `drain_outbox_all` should sweep them.
        let (_dir, mut conn, writer, join) = setup().await;
        // Manually seed an outbox row (simulates a prior-run crash
        // between tx commit + WAL emit).
        let now: i64 = 1_700_000_000;
        let payload = b"{\"extraction_id\":\"leftover-ext\",\"field\":\"x\",\"event_id\":1,\"value_json\":\"v\",\"confidence\":0.5,\"evidence_event_ids\":[],\"guard_version\":\"0.1.0\",\"ts_unix\":1700000000}".to_vec();
        conn.execute(
            "INSERT INTO idx_profile_outbox \
             (extraction_id, event_type, payload, enqueued_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "leftover-ext",
                EVENT_TYPE_PROFILE_DELTA as i64,
                payload,
                now,
            ],
        )
        .unwrap();
        let drained = drain_outbox_all(&mut conn, &writer).await.unwrap();
        assert_eq!(drained, 1, "drain_outbox_all must replay the leftover");
        let remaining: i64 = conn
            .query_row("SELECT count(*) FROM idx_profile_outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 0, "drained row must be deleted");
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn drain_outbox_empty_is_noop() {
        let (_dir, mut conn, writer, join) = setup().await;
        let drained = drain_outbox_all(&mut conn, &writer).await.unwrap();
        assert_eq!(drained, 0);
        let drained2 = drain_outbox_for_extraction(&mut conn, &writer, "never-existed")
            .await
            .unwrap();
        assert_eq!(drained2, 0);
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn idempotent_skip_path_drains_own_extraction_outbox_rows() {
        // Pick #12 follow-up: a crash between `tx.commit()` and the
        // post-commit drain can leave outbox rows whose owning
        // idx_profile rows ALREADY exist. A retry with the same
        // extraction_id hits the idempotency-skip branch. Without
        // a drain there, the orphaned rows survive until SOMETHING
        // ELSE triggers `drain_outbox_all` (daemon restart) — the
        // retry path itself never resolves them.
        //
        // After the fix, the idempotency-skip branch best-effort
        // drains its own extraction_id before returning, so a retry
        // converges immediately.
        let (_dir, mut conn, writer, join) = setup().await;

        // First successful apply — fully drains its own rows.
        let outcome = apply_delta(&mut conn, &writer, &delta(), 1).await.unwrap();
        assert!(!outcome.idempotent_skip);

        // Simulate a crash that left an outbox row for THIS extraction:
        // insert a fake row carrying the same extraction_id used by
        // `delta()`.
        let payload = b"{\"extraction_id\":\"ext-abc\",\"field\":\"x\",\"event_id\":99,\"value_json\":\"v\",\"confidence\":0.5,\"evidence_event_ids\":[],\"guard_version\":\"0.1.0\",\"ts_unix\":1}".to_vec();
        conn.execute(
            "INSERT INTO idx_profile_outbox \
             (extraction_id, event_type, payload, enqueued_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["ext-abc", EVENT_TYPE_PROFILE_DELTA as i64, payload, 1_i64,],
        )
        .unwrap();
        let stranded_before: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_profile_outbox WHERE extraction_id = 'ext-abc'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stranded_before, 1, "stranded row must be in outbox");

        // Retry — must hit idempotency-skip AND drain the stranded row.
        let outcome = apply_delta(&mut conn, &writer, &delta(), 1).await.unwrap();
        assert!(
            outcome.idempotent_skip,
            "second apply with same extraction_id must idempotency-skip"
        );
        let stranded_after: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_profile_outbox WHERE extraction_id = 'ext-abc'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            stranded_after, 0,
            "idempotency-skip must best-effort drain the same extraction_id"
        );

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn apply_with_existing_outbox_leftover_drains_old_then_new() {
        // Prior crash left an outbox row for a different extraction.
        // The next `apply_delta` call drains its OWN rows (the
        // extraction it just inserted); the leftover from the
        // unrelated prior extraction survives that call but gets
        // swept by `drain_outbox_all` on next daemon startup.
        let (_dir, mut conn, writer, join) = setup().await;
        let prior_payload = b"{\"extraction_id\":\"prior-ext\",\"field\":\"y\",\"event_id\":1,\"value_json\":\"v\",\"confidence\":0.5,\"evidence_event_ids\":[],\"guard_version\":\"0.1.0\",\"ts_unix\":1}".to_vec();
        conn.execute(
            "INSERT INTO idx_profile_outbox \
             (extraction_id, event_type, payload, enqueued_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "prior-ext",
                EVENT_TYPE_PROFILE_DELTA as i64,
                prior_payload,
                1_i64,
            ],
        )
        .unwrap();
        // Apply a NEW delta — its rows enqueue + drain, prior row stays.
        let _ = apply_delta(&mut conn, &writer, &delta(), 1).await.unwrap();
        let remaining: i64 = conn
            .query_row("SELECT count(*) FROM idx_profile_outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            remaining, 1,
            "prior-ext row should survive (different extraction_id)"
        );
        // Now `drain_outbox_all` sweeps it.
        let n = drain_outbox_all(&mut conn, &writer).await.unwrap();
        assert_eq!(n, 1);
        let zero: i64 = conn
            .query_row("SELECT count(*) FROM idx_profile_outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(zero, 0);
        drop(writer);
        let _ = join.await;
    }
}
