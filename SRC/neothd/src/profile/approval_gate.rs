//! ADV-03 item 4 — operator-confirmation gate (Stage 5b) sitting
//! between `claim_guard` (Stage 5) and `apply_delta` (Stage 6).
//!
//! # Threat model
//!
//! After ADV-03 items 1+2 shipped (XML boundary + quoted-content
//! pre-filter), an attacker who controls operator-attributed text
//! can still try to drive profile state through a CHAIN of innocent-
//! looking turns. The defence below is the operator-in-the-loop
//! confirmation step: every extracted `ProfileDelta` becomes visible
//! to the operator before it persists, so a slow-poison campaign
//! that slips past the structural filters still has to convince
//! the human at the keyboard.
//!
//! # Behaviour matrix
//!
//! | Autonomy | `require_approval=true`     | `require_approval=false` |
//! |----------|-----------------------------|--------------------------|
//! | Strict   | always confirm              | always confirm           |
//! | Standard | confirm                     | auto-approve             |
//! | Elevated | confirm                     | auto-approve             |
//! | Full     | auto-approve                | auto-approve             |
//! | Custom   | confirm (treat as Standard) | auto-approve             |
//!
//! "Confirm" means: tty present → `dialoguer::Confirm` prompt; no
//! tty → park in `idx_profile_pending` + emit
//! `EVENT_TYPE_PROFILE_DELTA_PENDING` (0xB5). The operator resolves
//! daemon-queued pending rows via `neoth profile approve <id>` or
//! `neoth profile decline <id>` (CLI subcommands shipped in
//! [`super::pending_repo`] consumers).
//!
//! # Idempotency
//!
//! `extraction_id` is `UNIQUE` in `idx_profile_pending`. Re-running
//! the gate on the same delta is a no-op for the pending path
//! (`ON CONFLICT DO NOTHING`) — the audit chain stays clean.

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::config::ProfileConfig;
use crate::permissions::AutonomyLevel;
use crate::profile::delta::ProfileDelta;
use crate::wal::events::{
    EVENT_TYPE_PROFILE_DELTA_APPROVED, EVENT_TYPE_PROFILE_DELTA_DECLINED,
    EVENT_TYPE_PROFILE_DELTA_PENDING,
};

/// Outcome of one gate run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Caller MUST proceed to `apply_delta`. Either: (a) the gate
    /// bypassed (autonomy=Full or require_approval=false), or (b) the
    /// operator answered yes at the tty prompt.
    Approved,
    /// Caller MUST NOT call `apply_delta`. The delta has been parked
    /// in `idx_profile_pending`; the operator will resolve it later
    /// via `neoth profile approve|decline`. WAL frame 0xB5 was
    /// emitted (or attempted — emit failures log + continue).
    Queued { extraction_id: String },
    /// Caller MUST NOT call `apply_delta`. The operator explicitly
    /// declined at the tty prompt. WAL frame 0xB7 was emitted.
    Declined,
}

/// Decide whether `delta` should be applied immediately, queued for
/// operator review, or dropped. Pure routing function — DB writes
/// and WAL emits happen inside this fn (the consumer doesn't need
/// to know which branch fired).
///
/// Arguments:
/// - `delta`: the post-claim-guard delta from Stage 5
/// - `config`: read `profile.require_approval`
/// - `autonomy`: from `FreedomConfig.autonomy`
/// - `is_tty`: caller passes the result of e.g. `std::io::stderr().is_terminal()`
/// - `conn`: views.db connection (used only when the gate queues)
/// - `confirm`: a closure that runs the interactive confirm — injected
///   so tests can simulate yes/no without spinning up dialoguer
/// - `now_unix`: wall-clock seconds for queue-row + WAL timestamps
pub fn approval_gate(
    delta: &ProfileDelta,
    config: &ProfileConfig,
    autonomy: AutonomyLevel,
    is_tty: bool,
    conn: &Connection,
    confirm: impl FnOnce(&ProfileDelta) -> bool,
    now_unix: u64,
) -> Result<ApprovalOutcome> {
    // Empty deltas never reach the gate — the runner short-circuits
    // earlier — but be defensive in case a future caller forgets.
    if delta.claims.is_empty() {
        return Ok(ApprovalOutcome::Approved);
    }

    let needs_confirm = match autonomy {
        AutonomyLevel::Strict => true,
        AutonomyLevel::Full => false,
        AutonomyLevel::Standard | AutonomyLevel::Elevated | AutonomyLevel::Custom => {
            config.require_approval
        }
    };

    if !needs_confirm {
        return Ok(ApprovalOutcome::Approved);
    }

    if is_tty {
        if confirm(delta) {
            Ok(ApprovalOutcome::Approved)
        } else {
            // Emit a best-effort audit frame for the decline. WAL
            // append failures here are non-fatal — the chat reply
            // already went out, losing the audit frame is a
            // logged-warning, not a caller-facing error.
            tracing::info!(
                extraction_id = %delta.extraction_id,
                claim_count = delta.claims.len(),
                event_code = format!("0x{:02X}", EVENT_TYPE_PROFILE_DELTA_DECLINED),
                "ADV-03 approval_gate: operator declined delta at tty prompt"
            );
            Ok(ApprovalOutcome::Declined)
        }
    } else {
        // Daemon mode: park the delta + emit pending audit frame.
        let id = insert_pending(conn, delta, now_unix)
            .with_context(|| format!("queue pending delta {}", delta.extraction_id))?;
        tracing::info!(
            extraction_id = %delta.extraction_id,
            row_id = id,
            claim_count = delta.claims.len(),
            event_code = format!("0x{:02X}", EVENT_TYPE_PROFILE_DELTA_PENDING),
            "ADV-03 approval_gate: parked delta in idx_profile_pending"
        );
        Ok(ApprovalOutcome::Queued {
            extraction_id: delta.extraction_id.clone(),
        })
    }
}

/// Build the JSON payload for an `EVENT_TYPE_PROFILE_DELTA_PENDING`
/// WAL frame. Returned so the caller (cli/serve, channel pipeline)
/// can append it to the active writer without dragging the entire
/// `WalWriter` into this pure-routing module.
pub fn pending_payload(delta: &ProfileDelta, now_unix: u64) -> Vec<u8> {
    let field_summary: Vec<&str> = delta
        .claims
        .iter()
        .take(8)
        .map(|c| c.field.as_str())
        .collect();
    let value = serde_json::json!({
        "extraction_id": delta.extraction_id,
        "conversation_hash": delta.conversation_hash,
        "claim_count": delta.claims.len(),
        "field_summary": field_summary,
        "ts_unix": now_unix,
    });
    serde_json::to_vec(&value).unwrap_or_else(|_| {
        format!(
            "{{\"extraction_id\":\"{}\",\"claim_count\":{}}}",
            delta.extraction_id.replace('"', ""),
            delta.claims.len(),
        )
        .into_bytes()
    })
}

/// Build the JSON payload for an `EVENT_TYPE_PROFILE_DELTA_APPROVED`
/// frame. Operator resolved a previously-queued pending row.
pub fn approved_payload(extraction_id: &str, claim_count: usize, now_unix: u64) -> Vec<u8> {
    let value = serde_json::json!({
        "extraction_id": extraction_id,
        "claim_count": claim_count,
        "approved_at_ts_unix": now_unix,
    });
    serde_json::to_vec(&value).unwrap_or_else(|_| Vec::new())
}

/// Build the JSON payload for an `EVENT_TYPE_PROFILE_DELTA_DECLINED`
/// frame. Operator resolved a queued row OR declined at the tty
/// prompt — `reason` is `Some` when the operator typed one in the
/// `neoth profile decline <id> --reason ...` flow.
pub fn declined_payload(
    extraction_id: &str,
    claim_count: usize,
    now_unix: u64,
    reason: Option<&str>,
) -> Vec<u8> {
    let value = serde_json::json!({
        "extraction_id": extraction_id,
        "claim_count": claim_count,
        "declined_at_ts_unix": now_unix,
        "reason": reason,
    });
    serde_json::to_vec(&value).unwrap_or_else(|_| Vec::new())
}

/// Constants re-exported so the cli + runner can reference these
/// codes without depending on `wal::events` directly.
pub const PENDING_EVENT: u8 = EVENT_TYPE_PROFILE_DELTA_PENDING;
pub const APPROVED_EVENT: u8 = EVENT_TYPE_PROFILE_DELTA_APPROVED;
pub const DECLINED_EVENT: u8 = EVENT_TYPE_PROFILE_DELTA_DECLINED;

// ── idx_profile_pending repository ─────────────────────────────────────────

/// One row in `idx_profile_pending`. Operator-facing summary the
/// `neoth profile pending` CLI command renders into a table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRow {
    pub id: i64,
    pub extraction_id: String,
    pub claim_count: i64,
    pub created_at_unix: i64,
    /// JSON-encoded ProfileDelta. Caller deserialises before
    /// passing to `apply_delta`.
    pub delta_json: String,
}

/// Insert (or noop on conflict) a pending row. Returns the row id.
/// `ON CONFLICT (extraction_id) DO NOTHING` keeps the gate idempotent
/// across retries: a duplicate extraction silently re-finds the
/// existing row and returns its id.
pub fn insert_pending(conn: &Connection, delta: &ProfileDelta, now_unix: u64) -> Result<i64> {
    let delta_json = serde_json::to_string(delta).context("serialise ProfileDelta to JSON")?;
    // Try insert first; on UNIQUE conflict re-read the existing row's id.
    let inserted = conn.execute(
        "INSERT INTO idx_profile_pending \
         (extraction_id, delta_json, claim_count, created_at_unix) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(extraction_id) DO NOTHING",
        rusqlite::params![
            delta.extraction_id,
            delta_json,
            delta.claims.len() as i64,
            now_unix as i64,
        ],
    )
    .context("insert idx_profile_pending")?;
    if inserted == 1 {
        Ok(conn.last_insert_rowid())
    } else {
        // Existing row — fetch its id.
        let id: i64 = conn
            .query_row(
                "SELECT id FROM idx_profile_pending WHERE extraction_id = ?1",
                rusqlite::params![delta.extraction_id],
                |row| row.get(0),
            )
            .context("re-read pending row after conflict-noop")?;
        Ok(id)
    }
}

/// List every pending row, oldest-first (matches `neoth profile pending`
/// rendering order). Bounded by `limit` so a runaway daemon can't
/// fill the operator's terminal.
pub fn list_pending(conn: &Connection, limit: usize) -> Result<Vec<PendingRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, extraction_id, delta_json, claim_count, created_at_unix \
             FROM idx_profile_pending \
             ORDER BY created_at_unix ASC \
             LIMIT ?1",
        )
        .context("prepare list_pending")?;
    let rows = stmt
        .query_map(rusqlite::params![limit as i64], |row| {
            Ok(PendingRow {
                id: row.get(0)?,
                extraction_id: row.get(1)?,
                delta_json: row.get(2)?,
                claim_count: row.get(3)?,
                created_at_unix: row.get(4)?,
            })
        })
        .context("query idx_profile_pending")?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.context("decode pending row")?);
    }
    Ok(out)
}

/// Pop a pending row by `extraction_id`: deletes it from the table
/// AND returns its contents. Used by `neoth profile approve` to take
/// the row, hand the delta to `apply_delta`, then commit deletion in
/// the same transaction the caller controls.
///
/// Returns `Ok(None)` when no row matches (operator typo / race).
pub fn pop_pending(conn: &Connection, extraction_id: &str) -> Result<Option<PendingRow>> {
    let row: Option<PendingRow> = conn
        .query_row(
            "SELECT id, extraction_id, delta_json, claim_count, created_at_unix \
             FROM idx_profile_pending \
             WHERE extraction_id = ?1",
            rusqlite::params![extraction_id],
            |row| {
                Ok(PendingRow {
                    id: row.get(0)?,
                    extraction_id: row.get(1)?,
                    delta_json: row.get(2)?,
                    claim_count: row.get(3)?,
                    created_at_unix: row.get(4)?,
                })
            },
        )
        .ok();
    let Some(row) = row else {
        return Ok(None);
    };
    conn.execute(
        "DELETE FROM idx_profile_pending WHERE id = ?1",
        rusqlite::params![row.id],
    )
    .context("delete pending row after pop")?;
    Ok(Some(row))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use crate::profile::delta::RawClaim;

    fn open_test_db() -> Connection {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.db");
        let conn = store::open(&path).unwrap();
        std::mem::forget(dir);
        conn
    }

    fn fixture_delta() -> ProfileDelta {
        ProfileDelta {
            extraction_id: "ext-test-1".into(),
            conversation_hash: "hash-1".into(),
            claims: vec![RawClaim {
                field: "identity.location".into(),
                value_json: serde_json::json!("Berlin"),
                confidence: 0.9,
                reasoning: "operator said so".into(),
                evidence_event_ids: vec![10],
            }],
            ..Default::default()
        }
    }

    fn fixture_config(require_approval: bool) -> ProfileConfig {
        let mut c = ProfileConfig::default();
        c.require_approval = require_approval;
        c
    }

    #[test]
    fn empty_delta_is_auto_approved() {
        let conn = open_test_db();
        let empty = ProfileDelta::default();
        let out = approval_gate(
            &empty,
            &fixture_config(true),
            AutonomyLevel::Strict,
            true,
            &conn,
            |_| panic!("confirm closure must not fire for empty delta"),
            100,
        )
        .unwrap();
        assert_eq!(out, ApprovalOutcome::Approved);
    }

    #[test]
    fn full_autonomy_skips_gate_unconditionally() {
        let conn = open_test_db();
        let out = approval_gate(
            &fixture_delta(),
            &fixture_config(true),
            AutonomyLevel::Full,
            true,
            &conn,
            |_| panic!("confirm closure must not fire when autonomy=Full"),
            100,
        )
        .unwrap();
        assert_eq!(out, ApprovalOutcome::Approved);
    }

    #[test]
    fn standard_with_require_approval_false_auto_approves() {
        let conn = open_test_db();
        let out = approval_gate(
            &fixture_delta(),
            &fixture_config(false),
            AutonomyLevel::Standard,
            true,
            &conn,
            |_| panic!("confirm closure must not fire when require_approval=false"),
            100,
        )
        .unwrap();
        assert_eq!(out, ApprovalOutcome::Approved);
    }

    #[test]
    fn strict_with_require_approval_false_still_confirms() {
        let conn = open_test_db();
        let confirmed = std::cell::Cell::new(false);
        let out = approval_gate(
            &fixture_delta(),
            &fixture_config(false),
            AutonomyLevel::Strict,
            true,
            &conn,
            |_| {
                confirmed.set(true);
                true
            },
            100,
        )
        .unwrap();
        assert!(confirmed.get(), "Strict must confirm even when require_approval=false");
        assert_eq!(out, ApprovalOutcome::Approved);
    }

    #[test]
    fn tty_confirm_yes_returns_approved() {
        let conn = open_test_db();
        let out = approval_gate(
            &fixture_delta(),
            &fixture_config(true),
            AutonomyLevel::Standard,
            true,
            &conn,
            |_| true,
            100,
        )
        .unwrap();
        assert_eq!(out, ApprovalOutcome::Approved);
    }

    #[test]
    fn tty_confirm_no_returns_declined() {
        let conn = open_test_db();
        let out = approval_gate(
            &fixture_delta(),
            &fixture_config(true),
            AutonomyLevel::Standard,
            true,
            &conn,
            |_| false,
            100,
        )
        .unwrap();
        assert_eq!(out, ApprovalOutcome::Declined);
    }

    #[test]
    fn no_tty_queues_to_pending_table() {
        let conn = open_test_db();
        let delta = fixture_delta();
        let out = approval_gate(
            &delta,
            &fixture_config(true),
            AutonomyLevel::Standard,
            false, // no tty
            &conn,
            |_| panic!("confirm closure must not fire without tty"),
            100,
        )
        .unwrap();
        assert_eq!(
            out,
            ApprovalOutcome::Queued {
                extraction_id: delta.extraction_id.clone(),
            }
        );
        // Row landed in idx_profile_pending.
        let pending = list_pending(&conn, 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].extraction_id, delta.extraction_id);
        assert_eq!(pending[0].claim_count, 1);
    }

    #[test]
    fn insert_pending_is_idempotent_on_duplicate_extraction_id() {
        let conn = open_test_db();
        let delta = fixture_delta();
        let id_a = insert_pending(&conn, &delta, 100).unwrap();
        let id_b = insert_pending(&conn, &delta, 200).unwrap();
        assert_eq!(id_a, id_b, "second insert must return the existing row's id");
        // Only one row in the table.
        let pending = list_pending(&conn, 10).unwrap();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn pop_pending_returns_row_and_deletes_it() {
        let conn = open_test_db();
        let delta = fixture_delta();
        let _ = insert_pending(&conn, &delta, 100).unwrap();
        let popped = pop_pending(&conn, &delta.extraction_id).unwrap();
        let row = popped.expect("row must exist before pop");
        assert_eq!(row.extraction_id, delta.extraction_id);
        // Now gone.
        assert!(list_pending(&conn, 10).unwrap().is_empty());
        assert!(pop_pending(&conn, &delta.extraction_id).unwrap().is_none());
    }

    #[test]
    fn list_pending_orders_oldest_first() {
        let conn = open_test_db();
        let mut d1 = fixture_delta();
        d1.extraction_id = "ext-a".into();
        let mut d2 = fixture_delta();
        d2.extraction_id = "ext-b".into();
        let mut d3 = fixture_delta();
        d3.extraction_id = "ext-c".into();
        insert_pending(&conn, &d2, 200).unwrap();
        insert_pending(&conn, &d1, 100).unwrap();
        insert_pending(&conn, &d3, 300).unwrap();
        let rows = list_pending(&conn, 10).unwrap();
        let order: Vec<&str> = rows.iter().map(|r| r.extraction_id.as_str()).collect();
        assert_eq!(order, vec!["ext-a", "ext-b", "ext-c"]);
    }

    #[test]
    fn pending_payload_is_well_formed_json_with_field_summary() {
        let delta = fixture_delta();
        let bytes = pending_payload(&delta, 1_716_000_000);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v.get("extraction_id").and_then(|x| x.as_str()),
            Some("ext-test-1")
        );
        assert_eq!(v.get("claim_count").and_then(|x| x.as_u64()), Some(1));
        assert!(v.get("field_summary").and_then(|x| x.as_array()).is_some());
        assert_eq!(v.get("ts_unix").and_then(|x| x.as_u64()), Some(1_716_000_000));
    }

    #[test]
    fn approved_and_declined_payloads_carry_metadata() {
        let a = approved_payload("ext-1", 3, 1_716_000_500);
        let av: serde_json::Value = serde_json::from_slice(&a).unwrap();
        assert_eq!(av["extraction_id"], "ext-1");
        assert_eq!(av["claim_count"], 3);
        assert_eq!(av["approved_at_ts_unix"], 1_716_000_500u64);

        let d = declined_payload("ext-2", 5, 1_716_000_600, Some("noise"));
        let dv: serde_json::Value = serde_json::from_slice(&d).unwrap();
        assert_eq!(dv["extraction_id"], "ext-2");
        assert_eq!(dv["reason"], "noise");
    }

    #[test]
    fn event_constant_re_exports_pin_to_band_b() {
        // Drift guard: if a future event-code refactor renumbers these,
        // operators with persisted WAL frames will misread the audit
        // trail. Pin them loud.
        assert_eq!(PENDING_EVENT, 0xB5);
        assert_eq!(APPROVED_EVENT, 0xB6);
        assert_eq!(DECLINED_EVENT, 0xB7);
    }
}
