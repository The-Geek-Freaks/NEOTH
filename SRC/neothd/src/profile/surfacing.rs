//! Round-3 v0.4 G-02 — "Knows things about you you don't know" —
//! proactive surfacing of novel high-confidence profile claims.
//!
//! Builds on top of the G-01 consumer half (proactive_dispatcher
//! drain loop into JSONL sidecar): when a profile-extraction pass
//! lands a new claim above the high-confidence threshold, this
//! module turns it into a `ProactiveItem` the operator sees in
//! `~/.neoth/proactive_delivered.jsonl` next time the drain ticks.
//!
//! ## Why this surface
//!
//! NEOTH's profile extractor (`profile::extract`) writes
//! `idx_profile` rows continuously as the operator talks. Most
//! claims land at low/medium confidence (0.3-0.7) — useful for
//! recall biasing but not surface-worthy. Claims at >= 0.85 are
//! the "NEOTH learned something concrete about you" moments. G-02
//! surfaces those: "I noticed you said X about Y (confidence Z%).
//! Want to confirm or revise?"
//!
//! ## Dedup design
//!
//! Dedup key: `g02:<field>:<value_hash>`. Same (field, value)
//! pair never re-surfaces — even if a fresh extraction re-lands
//! the same claim (re-affirming what NEOTH already knows). The
//! operator either confirms once or revises; either way the
//! surface fires once per distinct claim.
//!
//! ## Threshold tuning
//!
//! Default `DEFAULT_HIGH_CONFIDENCE_THRESHOLD = 0.85` covers the
//! "NEOTH is pretty sure" band. Operators on noisy-extraction
//! models (small local LLM) raise this; operators on clean
//! flagship-model extraction lower it for more proactive surfacing.
//! Operator-tunable via `freedom.yaml::profile.surfacing_threshold`
//! in the follow-on slice.

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Default high-confidence threshold for G-02 surfacing. Claims
/// at or above this level are eligible for proactive surfacing.
pub const DEFAULT_HIGH_CONFIDENCE_THRESHOLD: f64 = 0.85;

/// Default "novel within this window" cutoff — claims with
/// `applied_at` younger than this many seconds qualify. 24h
/// default matches the daily G-02 cron cadence.
pub const DEFAULT_NOVELTY_WINDOW_SECS: u64 = 24 * 3600;

/// One candidate the G-02 surfacing pass picked. Carries the
/// fields the ProactiveItem template needs without bringing the
/// full `idx_profile` row shape downstream.
#[derive(Debug, Clone, PartialEq)]
pub struct NovelClaim {
    pub field: String,
    pub value_json: String,
    pub confidence: f64,
    pub applied_at_unix: i64,
}

/// Find active high-confidence claims newer than `since_unix`.
/// Pure-fn (no enqueue side effect) so tests assert on candidate
/// shape without touching ProactiveQueue.
///
/// Filters: `superseded_at IS NULL` (claim still live) AND
/// `confidence >= threshold` AND `applied_at >= since_unix`.
/// Anti-joins `idx_profile_redactions` so operator-marked
/// `never_recreate` fields stay silent.
///
/// `limit` caps the result set (avoid a flood when an extraction
/// pass lands 50 claims at once).
pub fn find_novel_high_confidence_claims(
    conn: &Connection,
    since_unix: i64,
    threshold: f64,
    limit: usize,
) -> Result<Vec<NovelClaim>> {
    let mut stmt = conn
        .prepare(
            "SELECT p.field, p.value_json, p.confidence, p.applied_at \
             FROM idx_profile p \
             WHERE p.superseded_at IS NULL \
               AND p.confidence >= ?1 \
               AND p.applied_at >= ?2 \
               AND NOT EXISTS ( \
                 SELECT 1 FROM idx_profile_redactions r \
                 WHERE r.field = p.field AND r.revoked_at IS NULL \
               ) \
             ORDER BY p.confidence DESC, p.applied_at DESC \
             LIMIT ?3",
        )
        .context("prepare find_novel_high_confidence_claims query")?;
    let rows = stmt.query_map(
        rusqlite::params![threshold, since_unix, limit as i64],
        |row| {
            Ok(NovelClaim {
                field: row.get(0)?,
                value_json: row.get(1)?,
                confidence: row.get(2)?,
                applied_at_unix: row.get(3)?,
            })
        },
    )?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Render a `NovelClaim` as a `ProactiveItem` ready for
/// `ProactiveQueue::enqueue`. Bilingual EN+DE one-liner template —
/// matches the rest of the operator-facing strings in NEOTH for
/// the operator's mixed-language profile.
///
/// dedup_key uses the (field, value) pair so a re-extracted
/// identical claim doesn't re-surface. confidence is rounded to
/// two decimals for operator readability.
pub fn build_g02_proactive_item(
    claim: &NovelClaim,
    channel: &str,
    now_unix: i64,
) -> crate::proactive::ProactiveItem {
    let confidence_pct = (claim.confidence * 100.0).round() as u32;
    // Strip JSON quoting for the visible body (most value_json values
    // are short strings; the operator-facing line shouldn't show the
    // surrounding quotes).
    let display_value = claim.value_json.trim_matches('"').replace("\\\"", "\"");
    let body = format!(
        "Ich habe gelernt: {field} = {value} ({pct}%). Stimmt das? \
         (`neoth profile show {field}` / `neoth profile correct \"{field}\" \"<value>\"`)\n\
         I learned: {field} = {value} ({pct}% confidence). Is this right?",
        field = claim.field,
        value = display_value,
        pct = confidence_pct,
    );
    let dedup_key = format!("g02:{}:{}", claim.field, short_hash(&claim.value_json),);
    crate::proactive::ProactiveItem {
        priority: 60, // higher than 50 reflection (operator-relevance > weekly-summary)
        dedup_key,
        channel: channel.to_string(),
        source: "g02_surfacing".to_string(),
        body,
        scheduled_for_unix: now_unix,
    }
}

/// 12-char hex prefix of SHA-256(value_json). Stable per value so
/// the dedup key collides exactly when the value repeats.
fn short_hash(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(12);
    for b in &digest[..6] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_in_memory_profile_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE idx_profile (
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
            CREATE TABLE idx_profile_redactions (
                field      TEXT NOT NULL,
                revoked_at INTEGER
            );",
        )
        .unwrap();
        conn
    }

    fn insert_claim(
        conn: &Connection,
        field: &str,
        value_json: &str,
        confidence: f64,
        applied_at: i64,
        superseded_at: Option<i64>,
    ) {
        conn.execute(
            "INSERT INTO idx_profile (extraction_id, event_id, field, value_json, confidence, \
             applied_at, superseded_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "e1",
                1i64,
                field,
                value_json,
                confidence,
                applied_at,
                superseded_at
            ],
        )
        .unwrap();
    }

    // ── find_novel_high_confidence_claims ─────────────────────────

    #[test]
    fn finds_high_confidence_recent_claim() {
        let conn = build_in_memory_profile_db();
        insert_claim(&conn, "city", "\"Berlin\"", 0.95, 1_700_000_000, None);
        let claims = find_novel_high_confidence_claims(&conn, 1_699_000_000, 0.85, 10).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].field, "city");
        assert_eq!(claims[0].value_json, "\"Berlin\"");
        assert!((claims[0].confidence - 0.95).abs() < 1e-9);
    }

    #[test]
    fn excludes_below_threshold() {
        let conn = build_in_memory_profile_db();
        insert_claim(&conn, "city", "\"Berlin\"", 0.70, 1_700_000_000, None);
        let claims = find_novel_high_confidence_claims(&conn, 1_699_000_000, 0.85, 10).unwrap();
        assert!(
            claims.is_empty(),
            "0.70 < 0.85 threshold → must be excluded"
        );
    }

    #[test]
    fn excludes_too_old_claims() {
        let conn = build_in_memory_profile_db();
        insert_claim(&conn, "city", "\"Berlin\"", 0.95, 1_000_000, None);
        let claims = find_novel_high_confidence_claims(&conn, 1_699_000_000, 0.85, 10).unwrap();
        assert!(claims.is_empty(), "applied_at before since_unix → excluded");
    }

    #[test]
    fn excludes_superseded_claims() {
        let conn = build_in_memory_profile_db();
        insert_claim(
            &conn,
            "city",
            "\"Berlin\"",
            0.95,
            1_700_000_000,
            Some(1_700_001_000),
        );
        let claims = find_novel_high_confidence_claims(&conn, 1_699_000_000, 0.85, 10).unwrap();
        assert!(claims.is_empty(), "superseded claim must not surface");
    }

    #[test]
    fn excludes_redacted_fields() {
        let conn = build_in_memory_profile_db();
        insert_claim(&conn, "city", "\"Berlin\"", 0.95, 1_700_000_000, None);
        conn.execute(
            "INSERT INTO idx_profile_redactions (field, revoked_at) VALUES (?1, NULL)",
            rusqlite::params!["city"],
        )
        .unwrap();
        let claims = find_novel_high_confidence_claims(&conn, 1_699_000_000, 0.85, 10).unwrap();
        assert!(
            claims.is_empty(),
            "operator-redacted field (never_recreate) must stay silent",
        );
    }

    #[test]
    fn redaction_revoked_lets_claim_surface_again() {
        let conn = build_in_memory_profile_db();
        insert_claim(&conn, "city", "\"Berlin\"", 0.95, 1_700_000_000, None);
        conn.execute(
            "INSERT INTO idx_profile_redactions (field, revoked_at) VALUES (?1, ?2)",
            rusqlite::params!["city", 1_700_000_500i64],
        )
        .unwrap();
        let claims = find_novel_high_confidence_claims(&conn, 1_699_000_000, 0.85, 10).unwrap();
        assert_eq!(
            claims.len(),
            1,
            "revoked redaction (revoked_at NOT NULL) lets the claim surface",
        );
    }

    #[test]
    fn orders_by_confidence_desc() {
        let conn = build_in_memory_profile_db();
        insert_claim(&conn, "city", "\"Berlin\"", 0.88, 1_700_000_000, None);
        insert_claim(&conn, "birthday", "\"March\"", 0.97, 1_700_000_500, None);
        insert_claim(&conn, "language", "\"German\"", 0.92, 1_700_000_300, None);
        let claims = find_novel_high_confidence_claims(&conn, 1_699_000_000, 0.85, 10).unwrap();
        assert_eq!(claims.len(), 3);
        assert_eq!(claims[0].field, "birthday"); // 0.97 first
        assert_eq!(claims[1].field, "language"); // 0.92 second
        assert_eq!(claims[2].field, "city"); // 0.88 third
    }

    #[test]
    fn respects_limit() {
        let conn = build_in_memory_profile_db();
        for i in 0..10 {
            insert_claim(
                &conn,
                &format!("field{i}"),
                "\"v\"",
                0.90,
                1_700_000_000 + i,
                None,
            );
        }
        let claims = find_novel_high_confidence_claims(&conn, 1_699_000_000, 0.85, 3).unwrap();
        assert_eq!(claims.len(), 3);
    }

    // ── build_g02_proactive_item ──────────────────────────────────

    #[test]
    fn build_item_carries_field_and_confidence_in_body() {
        let claim = NovelClaim {
            field: "city".to_string(),
            value_json: "\"Berlin\"".to_string(),
            confidence: 0.92,
            applied_at_unix: 1_700_000_000,
        };
        let item = build_g02_proactive_item(&claim, "cli", 1_700_000_100);
        assert!(item.body.contains("city"));
        assert!(item.body.contains("Berlin"), "value should appear unquoted");
        assert!(item.body.contains("92%"));
        assert!(item.body.contains("Ich habe gelernt"));
        assert!(item.body.contains("I learned"));
        assert_eq!(item.channel, "cli");
        assert_eq!(item.source, "g02_surfacing");
        assert_eq!(item.priority, 60);
    }

    #[test]
    fn build_item_dedup_key_stable_per_field_and_value() {
        let claim_a = NovelClaim {
            field: "city".to_string(),
            value_json: "\"Berlin\"".to_string(),
            confidence: 0.92,
            applied_at_unix: 1_700_000_000,
        };
        let claim_b = NovelClaim {
            field: "city".to_string(),
            value_json: "\"Berlin\"".to_string(),
            confidence: 0.95, // different confidence, same (field, value)
            applied_at_unix: 1_700_000_500,
        };
        let item_a = build_g02_proactive_item(&claim_a, "cli", 0);
        let item_b = build_g02_proactive_item(&claim_b, "cli", 100);
        assert_eq!(
            item_a.dedup_key, item_b.dedup_key,
            "same (field, value) → same dedup_key"
        );
    }

    #[test]
    fn build_item_dedup_key_diverges_on_distinct_value() {
        let claim_a = NovelClaim {
            field: "city".to_string(),
            value_json: "\"Berlin\"".to_string(),
            confidence: 0.92,
            applied_at_unix: 1_700_000_000,
        };
        let claim_b = NovelClaim {
            field: "city".to_string(),
            value_json: "\"Munich\"".to_string(),
            confidence: 0.92,
            applied_at_unix: 1_700_000_000,
        };
        let item_a = build_g02_proactive_item(&claim_a, "cli", 0);
        let item_b = build_g02_proactive_item(&claim_b, "cli", 0);
        assert_ne!(item_a.dedup_key, item_b.dedup_key);
    }

    #[test]
    fn build_item_strips_json_quotes_on_simple_string_value() {
        let claim = NovelClaim {
            field: "name".to_string(),
            value_json: "\"Sam\"".to_string(),
            confidence: 0.99,
            applied_at_unix: 0,
        };
        let item = build_g02_proactive_item(&claim, "cli", 0);
        assert!(item.body.contains("Sam"));
        assert!(
            !item.body.contains("\\\"Sam\\\""),
            "JSON quote escaping must be removed from operator-facing body",
        );
    }

    // ── short_hash ────────────────────────────────────────────────

    #[test]
    fn short_hash_is_12_char_hex() {
        let h = short_hash("test");
        assert_eq!(h.len(), 12);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn short_hash_deterministic_and_distinct() {
        assert_eq!(short_hash("abc"), short_hash("abc"));
        assert_ne!(short_hash("abc"), short_hash("def"));
    }

    // ── Constants pin ─────────────────────────────────────────────

    #[test]
    fn constants_canonical() {
        assert!((DEFAULT_HIGH_CONFIDENCE_THRESHOLD - 0.85).abs() < 1e-9);
        assert_eq!(DEFAULT_NOVELTY_WINDOW_SECS, 24 * 3600);
    }
}
