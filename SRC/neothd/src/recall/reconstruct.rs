//! Round-3 v0.4 QU-11 / ARS-6 — multi-session pipeline recovery via
//! `MODE_CHECKPOINT` (WAL `0x9A`).
//!
//! When the operator runs a long pipeline (council deliberation, code
//! workflow, multi-step task decomposition) and the session ends
//! before the pipeline finishes — daemon restart, laptop sleep, OS
//! reboot, kernel panic — the next session needs to pick up where the
//! previous one left off. The `MODE_CHECKPOINT` WAL frame snapshots
//! the resumable state (provider target, council mode, hemisphere
//! routing, MCP scope) at well-known pipeline boundaries; this module
//! ships the read-side that finds + hydrates one of those snapshots.
//!
//! ## Operator surface
//!
//! ```text
//! neoth chat resume from <checkpoint_hash>
//! ```
//!
//! `<checkpoint_hash>` is the short SHA-256 prefix (12 chars) printed
//! at checkpoint-emission time. The CLI wraps
//! [`reconstruct_from_checkpoint`] to fetch the snapshot, rebuild
//! the chat context, and resume the pipeline.
//!
//! ## Why MODE not just the chat log
//!
//! A chat-log replay would re-execute every prior tool call, council
//! deliberation, and provider request — wasting cost + producing
//! non-deterministic re-runs. The checkpoint snapshots the *state*
//! the pipeline needs (which provider was chosen, which council
//! hemisphere is up next, which MCP servers are scoped in) so the
//! resumed session continues forward, not re-derives from scratch.

use serde::{Deserialize, Serialize};

use crate::wal::events::{
    EVENT_TYPE_CONTEXT_COMPACTION_DONE, EVENT_TYPE_MCP_TOOL_CALLED, EVENT_TYPE_MODE_CHECKPOINT,
    EVENT_TYPE_PROVIDER_REQUEST,
};

/// Payload format for the `MODE_CHECKPOINT` WAL frame. The writer
/// emits this JSON; the reader parses it via
/// [`reconstruct_from_checkpoint`].
///
/// The shape is intentionally narrow: only state the resumed pipeline
/// can't re-derive from idempotent inputs. Operator-controlled inputs
/// (the prompt text) live in the prior `RAW_TEXT` frames and are
/// replayed by reading the WAL window before the checkpoint, not
/// stored in the snapshot itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeCheckpoint {
    /// 12-char hex prefix of SHA-256(serialized-checkpoint). Stable
    /// identifier the operator pastes into `neoth chat resume from
    /// <hash>`.
    pub checkpoint_hash: String,
    /// Stable session identifier — UUID v7 string so the resume can
    /// link the new session to the original's WAL prefix.
    pub session_id: String,
    /// Which conversational mode was active when the checkpoint was
    /// emitted (chat / code / council / etc.).
    pub mode: String,
    /// Which provider routing was active (claude-cli / openai-compat /
    /// local-qwen / etc.).
    pub provider_target: String,
    /// Council mode active at checkpoint time (off / consensus / 3-
    /// hemisphere / etc.). Empty string when council was disabled.
    pub council_mode: String,
    /// MCP servers explicitly scoped into this session — operator may
    /// have toggled them via `/mcp` slash commands during the prior
    /// turns. Empty Vec is an exact empty scope when
    /// `mcp_scope_recorded=true`.
    pub scoped_mcp_servers: Vec<String>,
    /// True when `scoped_mcp_servers` is an exact, complete snapshot. Older
    /// checkpoints did not carry this discriminator; keeping false omitted
    /// during serialization preserves their original checkpoint hash, while
    /// resume rejects them because exact tool re-scoping is impossible.
    #[serde(default, skip_serializing_if = "is_false")]
    pub mcp_scope_recorded: bool,
    /// Pipeline phase the checkpoint represents (e.g.
    /// "council:awaiting-synthesis", "code:tests-failing",
    /// "decompose:step-3-of-7"). Free-form string the resume code
    /// uses to dispatch the next action.
    pub phase: String,
    /// Unix-seconds timestamp at emit time.
    pub ts_unix: i64,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl ModeCheckpoint {
    /// Compute the canonical 12-char checkpoint hash from the
    /// snapshot's stable fields. The same input always produces the
    /// same hash so the operator can re-derive it from a fresh
    /// snapshot. The `checkpoint_hash` field is set to the empty
    /// string before hashing so the hash doesn't depend on itself
    /// (would be a chicken-and-egg).
    pub fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut tmp = self.clone();
        tmp.checkpoint_hash.clear();
        let json = serde_json::to_string(&tmp).expect("ModeCheckpoint serialises cleanly");
        let digest = Sha256::digest(json.as_bytes());
        hex_encode_12(&digest)
    }

    /// Re-stamp the checkpoint with the canonical hash. The writer
    /// calls this immediately before emitting the WAL frame so the
    /// stored hash is always self-consistent.
    pub fn stamp_hash(&mut self) {
        self.checkpoint_hash = self.compute_hash();
    }
}

fn hex_encode_12(bytes: &[u8]) -> String {
    // First 6 bytes → 12 hex chars. Lowercase per the rest of the
    // codebase's hex convention (e.g. webhook_verify::sign_meta).
    let mut s = String::with_capacity(12);
    for b in &bytes[..6] {
        s.push(hex_nibble(b >> 4));
        s.push(hex_nibble(b & 0x0F));
    }
    s
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!("nibble fits in u4"),
    }
}

/// Summary of activity that occurred SINCE a prior `MODE_CHECKPOINT` was
/// written. Returned by [`catchup_summary`] so a resumed session can
/// print "N provider turns, M tool calls since checkpoint" without having
/// to scan the entire WAL.
///
/// The three counters cover the three most operator-visible activities:
/// - `provider_turns` — how many outbound LLM calls were made (0x20
///   `PROVIDER_REQUEST`).
/// - `tool_calls` — how many MCP tool invocations were dispatched (0xC0
///   `MCP_TOOL_CALLED`).
/// - `compactions` — how many context-compaction passes completed (0x5C
///   `CONTEXT_COMPACTION_DONE`).
///
/// All three are counted from `since_ts_unix` (inclusive, seconds) to
/// "now". A zero-value summary means "nothing interesting happened since
/// the checkpoint" — the caller should suppress the catchup line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchupSummary {
    /// Number of `PROVIDER_REQUEST` (0x20) frames after the checkpoint.
    pub provider_turns: u32,
    /// Number of `MCP_TOOL_CALLED` (0xC0) frames after the checkpoint.
    pub tool_calls: u32,
    /// Number of `CONTEXT_COMPACTION_DONE` (0x5C) frames after the checkpoint.
    pub compactions: u32,
}

impl CatchupSummary {
    /// True when all three counters are zero — the caller skips the
    /// catchup print line in this case.
    pub fn is_empty(&self) -> bool {
        self.provider_turns == 0 && self.tool_calls == 0 && self.compactions == 0
    }
}

/// Count the three activity types in `idx_episode` that occurred AFTER the
/// given checkpoint timestamp (exclusive lower bound, nanoseconds
/// converted from seconds internally).
///
/// Called immediately after a successful [`reconstruct_from_checkpoint`]
/// to give the resumed session a "what you missed" signal:
///
/// ```text
/// [neoth] catchup: 3 provider turns, 2 tool calls since checkpoint
/// ```
///
/// The function is read-only and best-effort — a query failure returns
/// a zero [`CatchupSummary`] rather than propagating an error. The
/// caller uses `CatchupSummary::is_empty()` to decide whether to print.
pub fn catchup_summary(conn: &rusqlite::Connection, since_ts_unix: i64) -> CatchupSummary {
    // Convert seconds → nanoseconds for the idx_episode.ts_ns column.
    let since_ts_ns = since_ts_unix.saturating_mul(1_000_000_000i64);
    let count_for = |event_type: u8| -> u32 {
        conn.query_row(
            "SELECT COUNT(*) FROM idx_episode \
             WHERE event_type = ?1 AND ts_ns > ?2",
            rusqlite::params![event_type as i64, since_ts_ns],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n.min(u32::MAX as i64) as u32)
        .unwrap_or(0)
    };
    CatchupSummary {
        provider_turns: count_for(EVENT_TYPE_PROVIDER_REQUEST),
        tool_calls: count_for(EVENT_TYPE_MCP_TOOL_CALLED),
        compactions: count_for(EVENT_TYPE_CONTEXT_COMPACTION_DONE),
    }
}

/// Errors surfaced by [`reconstruct_from_checkpoint`]. Importer
/// callers fold these into operator-visible wizard / CLI warnings.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ReconstructError {
    #[error("SQLite read failed: {0}")]
    Sqlite(String),
    #[error("no MODE_CHECKPOINT frame found with hash prefix {0}")]
    CheckpointNotFound(String),
    #[error("MODE_CHECKPOINT payload parse failed: {0}")]
    PayloadParse(String),
    #[error("checkpoint hash mismatch — stored hash {stored} does not match computed {computed}")]
    HashMismatch { stored: String, computed: String },
}

/// Hydrate a `ModeCheckpoint` snapshot from the WAL indexer by hash
/// prefix. The operator pastes the 12-char prefix; this function
/// scans `idx_episode` for `event_type = 0x9A` rows whose payload
/// JSON's `checkpoint_hash` starts with the prefix, returns the
/// matching snapshot (newest first if multiple match).
///
/// The hash is recomputed from the payload + compared with the
/// stored value to catch tampering / WAL corruption — a mismatch
/// surfaces as [`ReconstructError::HashMismatch`] rather than
/// silently returning a payload that doesn't match its own hash.
pub fn reconstruct_from_checkpoint<S: AsRef<str>>(
    conn: &rusqlite::Connection,
    hash_prefix: S,
) -> Result<ModeCheckpoint, ReconstructError> {
    let prefix = hash_prefix.as_ref();
    // The indexer materialises MODE_CHECKPOINT payloads into
    // idx_episode.text (raw JSON). We scan latest-first and return
    // the first parse-succeeding + hash-matching entry.
    let mut stmt = conn
        .prepare(
            "SELECT text FROM idx_episode \
             WHERE event_type = ?1 \
             ORDER BY ts_ns DESC",
        )
        .map_err(|e| ReconstructError::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([EVENT_TYPE_MODE_CHECKPOINT as i64], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|e| ReconstructError::Sqlite(e.to_string()))?;
    for row in rows {
        let payload = row.map_err(|e| ReconstructError::Sqlite(e.to_string()))?;
        let cp: ModeCheckpoint = match serde_json::from_str(&payload) {
            Ok(c) => c,
            Err(_) => continue, // skip unparseable rows — could be a future-format frame
        };
        if !cp.checkpoint_hash.starts_with(prefix) {
            continue;
        }
        let recomputed = cp.compute_hash();
        if cp.checkpoint_hash != recomputed {
            return Err(ReconstructError::HashMismatch {
                stored: cp.checkpoint_hash,
                computed: recomputed,
            });
        }
        return Ok(cp);
    }
    Err(ReconstructError::CheckpointNotFound(prefix.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_checkpoint() -> ModeCheckpoint {
        let mut cp = ModeCheckpoint {
            checkpoint_hash: String::new(),
            session_id: "01892bda-1234-7890-abcd-ef1234567890".into(),
            mode: "chat".into(),
            provider_target: "claude_cli".into(),
            council_mode: "off".into(),
            scoped_mcp_servers: vec!["paperless".into(), "fs".into()],
            mcp_scope_recorded: true,
            phase: "chat:awaiting-user".into(),
            ts_unix: 1_700_000_000,
        };
        cp.stamp_hash();
        cp
    }

    #[test]
    fn legacy_checkpoint_hash_stays_stable_without_scope_discriminator() {
        let mut legacy = sample_checkpoint();
        legacy.mcp_scope_recorded = false;
        legacy.stamp_hash();
        let encoded = serde_json::to_string(&legacy).unwrap();
        assert!(
            !encoded.contains("mcp_scope_recorded"),
            "false discriminator must stay absent so historical hashes still verify"
        );
        let decoded: ModeCheckpoint = serde_json::from_str(&encoded).unwrap();
        assert!(!decoded.mcp_scope_recorded);
        assert_eq!(decoded.compute_hash(), decoded.checkpoint_hash);
    }

    fn build_in_memory_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
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
        conn
    }

    fn insert_checkpoint_row(
        conn: &rusqlite::Connection,
        event_id: i64,
        ts_ns: i64,
        cp: &ModeCheckpoint,
    ) {
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                event_id,
                EVENT_TYPE_MODE_CHECKPOINT as i64,
                ts_ns,
                serde_json::to_string(cp).unwrap(),
                "h"
            ],
        )
        .unwrap();
    }

    // ── compute_hash + stamp_hash ─────────────────────────────────

    #[test]
    fn compute_hash_is_12_hex_chars() {
        let cp = sample_checkpoint();
        assert_eq!(cp.checkpoint_hash.len(), 12);
        assert!(cp.checkpoint_hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(cp.checkpoint_hash.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn compute_hash_is_deterministic() {
        let a = sample_checkpoint();
        let b = sample_checkpoint();
        assert_eq!(a.checkpoint_hash, b.checkpoint_hash);
    }

    #[test]
    fn compute_hash_changes_with_distinct_state() {
        let mut a = sample_checkpoint();
        let mut b = sample_checkpoint();
        b.phase = "chat:processing".to_string();
        b.stamp_hash();
        assert_ne!(a.checkpoint_hash, b.checkpoint_hash);
        // And original a is unchanged.
        assert_eq!(a.compute_hash(), a.checkpoint_hash);
        a.stamp_hash(); // no-op since already stamped
    }

    #[test]
    fn compute_hash_independent_of_stored_field() {
        // The hash field itself is excluded from the hashed bytes,
        // so re-stamping never changes the hash for the same state.
        let mut cp = sample_checkpoint();
        let original = cp.checkpoint_hash.clone();
        cp.stamp_hash();
        assert_eq!(cp.checkpoint_hash, original);
        cp.stamp_hash();
        assert_eq!(cp.checkpoint_hash, original);
    }

    // ── reconstruct_from_checkpoint integration ───────────────────

    #[test]
    fn reconstruct_round_trip() {
        let conn = build_in_memory_db();
        let cp = sample_checkpoint();
        insert_checkpoint_row(&conn, 1, 1, &cp);
        let recovered = reconstruct_from_checkpoint(&conn, &cp.checkpoint_hash).unwrap();
        assert_eq!(recovered, cp);
    }

    #[test]
    fn reconstruct_via_short_prefix() {
        // Operator pastes the first 6 chars rather than the full 12 —
        // still finds the unique match.
        let conn = build_in_memory_db();
        let cp = sample_checkpoint();
        insert_checkpoint_row(&conn, 1, 1, &cp);
        let prefix = &cp.checkpoint_hash[..6];
        let recovered = reconstruct_from_checkpoint(&conn, prefix).unwrap();
        assert_eq!(recovered.checkpoint_hash, cp.checkpoint_hash);
    }

    #[test]
    fn reconstruct_missing_hash_surfaces_not_found() {
        let conn = build_in_memory_db();
        let err = reconstruct_from_checkpoint(&conn, "deadbeef0000").unwrap_err();
        match err {
            ReconstructError::CheckpointNotFound(p) => assert_eq!(p, "deadbeef0000"),
            other => panic!("expected CheckpointNotFound, got {other:?}"),
        }
    }

    #[test]
    fn reconstruct_tampered_payload_surfaces_hash_mismatch() {
        let conn = build_in_memory_db();
        let mut cp = sample_checkpoint();
        let original_hash = cp.checkpoint_hash.clone();
        // Tamper: change the phase but keep the original hash.
        cp.phase = "tampered".to_string();
        // cp.checkpoint_hash still holds the pre-tamper value.
        insert_checkpoint_row(&conn, 1, 1, &cp);
        let err = reconstruct_from_checkpoint(&conn, &original_hash).unwrap_err();
        match err {
            ReconstructError::HashMismatch { stored, computed } => {
                assert_eq!(stored, original_hash);
                assert_ne!(computed, original_hash);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn reconstruct_returns_newest_when_prefix_matches_multiple() {
        let conn = build_in_memory_db();
        // Two distinct checkpoints with different phases. If their
        // hashes happen to share a prefix, newest-by-ts wins.
        let cp_old = sample_checkpoint();
        let mut cp_new = sample_checkpoint();
        cp_new.phase = "council:awaiting-synthesis".to_string();
        cp_new.stamp_hash();
        insert_checkpoint_row(&conn, 1, 100, &cp_old);
        insert_checkpoint_row(&conn, 2, 200, &cp_new); // higher ts_ns
        // Use a prefix that uniquely identifies cp_new.
        let recovered = reconstruct_from_checkpoint(&conn, &cp_new.checkpoint_hash).unwrap();
        assert_eq!(recovered.phase, "council:awaiting-synthesis");
    }

    #[test]
    fn reconstruct_skips_unparseable_rows() {
        let conn = build_in_memory_db();
        // Insert a junk-payload row at higher ts first, then the
        // real checkpoint. The scanner must skip the junk + find
        // the real one.
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                1,
                EVENT_TYPE_MODE_CHECKPOINT as i64,
                200,
                "{not valid json",
                "h"
            ],
        )
        .unwrap();
        let cp = sample_checkpoint();
        insert_checkpoint_row(&conn, 2, 100, &cp);
        let recovered = reconstruct_from_checkpoint(&conn, &cp.checkpoint_hash).unwrap();
        assert_eq!(recovered, cp);
    }

    #[test]
    fn reconstruct_empty_db_surfaces_not_found() {
        let conn = build_in_memory_db();
        let err = reconstruct_from_checkpoint(&conn, "anyhash12345").unwrap_err();
        assert!(matches!(err, ReconstructError::CheckpointNotFound(_)));
    }

    // ── catchup_summary ───────────────────────────────────────────────

    fn insert_episode_row(conn: &rusqlite::Connection, event_id: i64, event_type: u8, ts_ns: i64) {
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, '', 'h')",
            rusqlite::params![event_id, event_type as i64, ts_ns],
        )
        .unwrap();
    }

    /// 3 PROVIDER_REQUEST + 2 MCP_TOOL_CALLED rows AFTER the cutoff must be
    /// counted correctly; CONTEXT_COMPACTION_DONE rows absent → 0.
    #[test]
    fn catchup_summary_counts_relevant_frame_types() {
        let conn = build_in_memory_db();
        let since_ts_unix: i64 = 1_700_000_000;
        let after_ns = (since_ts_unix + 1) * 1_000_000_000;
        // 3 provider requests.
        for i in 0..3i64 {
            insert_episode_row(&conn, 10 + i, EVENT_TYPE_PROVIDER_REQUEST, after_ns + i);
        }
        // 2 MCP tool calls.
        for i in 0..2i64 {
            insert_episode_row(&conn, 20 + i, EVENT_TYPE_MCP_TOOL_CALLED, after_ns + i);
        }
        let summary = catchup_summary(&conn, since_ts_unix);
        assert_eq!(summary.provider_turns, 3);
        assert_eq!(summary.tool_calls, 2);
        assert_eq!(summary.compactions, 0);
        assert!(!summary.is_empty());
    }

    /// Rows AT OR BEFORE the cutoff timestamp must be excluded.
    #[test]
    fn catchup_summary_ignores_frames_before_checkpoint() {
        let conn = build_in_memory_db();
        let since_ts_unix: i64 = 1_700_000_000;
        let cutoff_ns = since_ts_unix * 1_000_000_000;
        // Insert rows at exactly the cutoff (not after) — must be excluded.
        insert_episode_row(&conn, 1, EVENT_TYPE_PROVIDER_REQUEST, cutoff_ns);
        insert_episode_row(&conn, 2, EVENT_TYPE_MCP_TOOL_CALLED, cutoff_ns - 1);
        insert_episode_row(&conn, 3, EVENT_TYPE_CONTEXT_COMPACTION_DONE, cutoff_ns);
        let summary = catchup_summary(&conn, since_ts_unix);
        assert_eq!(summary.provider_turns, 0);
        assert_eq!(summary.tool_calls, 0);
        assert_eq!(summary.compactions, 0);
        assert!(summary.is_empty());
    }

    /// All three counters populated simultaneously.
    #[test]
    fn catchup_summary_counts_all_three_types() {
        let conn = build_in_memory_db();
        let since_ts_unix: i64 = 1_000_000;
        let after_ns = (since_ts_unix + 1) * 1_000_000_000;
        insert_episode_row(&conn, 1, EVENT_TYPE_PROVIDER_REQUEST, after_ns);
        insert_episode_row(&conn, 2, EVENT_TYPE_PROVIDER_REQUEST, after_ns + 1);
        insert_episode_row(&conn, 3, EVENT_TYPE_MCP_TOOL_CALLED, after_ns + 2);
        insert_episode_row(&conn, 4, EVENT_TYPE_CONTEXT_COMPACTION_DONE, after_ns + 3);
        insert_episode_row(&conn, 5, EVENT_TYPE_CONTEXT_COMPACTION_DONE, after_ns + 4);
        let summary = catchup_summary(&conn, since_ts_unix);
        assert_eq!(summary.provider_turns, 2);
        assert_eq!(summary.tool_calls, 1);
        assert_eq!(summary.compactions, 2);
    }

    #[test]
    fn mode_checkpoint_event_type_constant_is_0x9a() {
        // Drift guard: a future band-rebase that moves the event code
        // would silently break operator's `chat resume from <hash>`
        // workflow. Pin so the rebase forces a deliberate update.
        assert_eq!(EVENT_TYPE_MODE_CHECKPOINT, 0x9A);
    }

    #[test]
    fn hex_encode_12_known_answer_test() {
        // Test the hex helper directly so a future swap to a third-
        // party hex crate doesn't silently change the case / length.
        let bytes = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        assert_eq!(hex_encode_12(&bytes), "001122334455");
    }
}
