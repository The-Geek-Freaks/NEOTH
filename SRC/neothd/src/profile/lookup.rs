//! Profile lookup helpers — CH-11 Block-B injection support.
//!
//! Reads the operator's high-confidence profile claims from
//! `idx_profile` (joined against `idx_profile_redactions` so redacted
//! fields stay invisible) and renders them as a context block for the
//! callosum synthesis prompt. The chat dispatch wires this in before
//! firing `callosum::resolve_with_profile` on a Split verdict.
//!
//! Why ≥ 0.6 confidence gate: SPEC_proactive_learning §5.1 pins this
//! as the "high-confidence" threshold across all profile-consuming
//! pipelines. Lower-confidence claims may be wrong with non-trivial
//! probability — feeding them into a synthesis would bias the answer
//! on noisy data. Operator can adjust via the chat-dispatch caller.

use anyhow::{Context, Result};
use rusqlite::Connection;

/// One live profile claim ready for prompt injection. Live = not
/// superseded by a later contradicting claim + not redacted by the
/// operator's `never_recreate` registry.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileClaim {
    pub field: String,
    /// JSON-encoded value as stored in `idx_profile.value_json`.
    /// Rendered through `render_value_for_prompt` before display.
    pub value_json: String,
    pub confidence: f64,
}

/// Pull up to `limit` live, non-redacted profile claims with confidence
/// ≥ `min_confidence`, ordered confidence descending then field
/// ascending (stable across equal-confidence ties). Returns an empty
/// vec when the table is empty or every row is redacted/superseded.
pub fn top_claims_for_chat(
    conn: &Connection,
    min_confidence: f64,
    limit: usize,
) -> Result<Vec<ProfileClaim>> {
    // `(field, applied_at DESC)` composite index serves the WHERE on
    // `superseded_at IS NULL`. Anti-join against `idx_profile_redactions`
    // filters fields the operator marked `never_recreate`.
    let mut stmt = conn
        .prepare(
            "SELECT p.field, p.value_json, p.confidence \
             FROM idx_profile p \
             WHERE p.superseded_at IS NULL \
               AND p.confidence >= ?1 \
               AND NOT EXISTS ( \
                 SELECT 1 FROM idx_profile_redactions r \
                 WHERE r.field = p.field AND r.revoked_at IS NULL \
               ) \
             ORDER BY p.confidence DESC, p.field ASC \
             LIMIT ?2",
        )
        .context("prepare top_claims_for_chat query")?;
    let rows = stmt
        .query_map(rusqlite::params![min_confidence, limit as i64], |row| {
            Ok(ProfileClaim {
                field: row.get(0)?,
                value_json: row.get(1)?,
                confidence: row.get(2)?,
            })
        })
        .context("query idx_profile")?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.context("decode idx_profile row")?);
    }
    Ok(out)
}

/// Render a slice of claims into a multi-line context block ready to
/// drop into the callosum synthesis prompt. Each line is
/// `- field: value (conf 0.NN)`. Empty input → empty string (caller
/// uses `is_empty` to decide whether to add the section).
pub fn render_for_synthesis_prompt(claims: &[ProfileClaim]) -> String {
    let mut out = String::new();
    for c in claims {
        let value = render_value_for_prompt(&c.value_json);
        out.push_str(&format!(
            "- {field}: {value} (conf {conf:.2})\n",
            field = c.field,
            value = value,
            conf = c.confidence,
        ));
    }
    out
}

/// Decode `value_json` to a human-friendly inline string. JSON strings
/// drop their surrounding quotes; primitives render as-is; objects /
/// arrays fall back to the raw JSON for safety.
fn render_value_for_prompt(json: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::String(s)) => s,
        Ok(serde_json::Value::Number(n)) => n.to_string(),
        Ok(serde_json::Value::Bool(b)) => b.to_string(),
        Ok(serde_json::Value::Null) => "null".to_string(),
        Ok(other) => other.to_string(),
        Err(_) => json.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;

    fn open_test_db() -> Connection {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.db");
        let conn = store::open(&path).unwrap();
        // Tempdir drops at function end but the connection holds the
        // path open — that's fine for the duration of the test.
        std::mem::forget(dir);
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
             evidence_event_ids, guard_version, applied_at, superseded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, '[]', NULL, ?6, ?7)",
            rusqlite::params![
                "ext-test",
                42i64,
                field,
                value_json,
                confidence,
                applied_at,
                superseded_at
            ],
        )
        .unwrap();
    }

    fn redact_field(conn: &Connection, field: &str) {
        conn.execute(
            "INSERT INTO idx_profile_redactions (field, never_recreate, asserted_by, asserted_at) \
             VALUES (?1, 1, 'test', ?2)",
            rusqlite::params![field, 1_700_000_000i64],
        )
        .unwrap();
    }

    #[test]
    fn empty_table_returns_empty_vec() {
        let conn = open_test_db();
        let claims = top_claims_for_chat(&conn, 0.6, 10).unwrap();
        assert!(claims.is_empty());
    }

    #[test]
    fn confidence_gate_filters_below_threshold() {
        let conn = open_test_db();
        insert_claim(&conn, "role", "\"developer\"", 0.9, 1, None);
        insert_claim(&conn, "tone", "\"direct\"", 0.5, 2, None); // below 0.6
        insert_claim(&conn, "lang", "\"de\"", 0.7, 3, None);
        let claims = top_claims_for_chat(&conn, 0.6, 10).unwrap();
        let fields: Vec<&str> = claims.iter().map(|c| c.field.as_str()).collect();
        assert_eq!(fields, vec!["role", "lang"]);
    }

    #[test]
    fn confidence_desc_ordering_is_stable() {
        let conn = open_test_db();
        insert_claim(&conn, "alpha", "\"a\"", 0.7, 1, None);
        insert_claim(&conn, "zeta", "\"z\"", 0.7, 2, None);
        insert_claim(&conn, "mid", "\"m\"", 0.8, 3, None);
        let claims = top_claims_for_chat(&conn, 0.6, 10).unwrap();
        // 0.8 first, then 0.7s sorted by field ASC for stable tie-break.
        let fields: Vec<&str> = claims.iter().map(|c| c.field.as_str()).collect();
        assert_eq!(fields, vec!["mid", "alpha", "zeta"]);
    }

    #[test]
    fn superseded_rows_invisible() {
        let conn = open_test_db();
        insert_claim(&conn, "role", "\"old\"", 0.9, 1, Some(2));
        insert_claim(&conn, "role", "\"new\"", 0.9, 3, None);
        let claims = top_claims_for_chat(&conn, 0.6, 10).unwrap();
        assert_eq!(claims.len(), 1);
        assert!(claims[0].value_json.contains("new"));
    }

    #[test]
    fn redacted_fields_excluded() {
        let conn = open_test_db();
        insert_claim(&conn, "private_thing", "\"hush\"", 0.95, 1, None);
        insert_claim(&conn, "public_thing", "\"ok\"", 0.95, 2, None);
        redact_field(&conn, "private_thing");
        let claims = top_claims_for_chat(&conn, 0.6, 10).unwrap();
        let fields: Vec<&str> = claims.iter().map(|c| c.field.as_str()).collect();
        assert_eq!(fields, vec!["public_thing"]);
    }

    #[test]
    fn limit_caps_returned_rows() {
        let conn = open_test_db();
        for i in 0..10 {
            insert_claim(
                &conn,
                &format!("field{i}"),
                "\"x\"",
                0.9,
                1_700_000_000 + i,
                None,
            );
        }
        let claims = top_claims_for_chat(&conn, 0.6, 3).unwrap();
        assert_eq!(claims.len(), 3);
    }

    #[test]
    fn render_for_synthesis_prompt_formats_known_value_shapes() {
        let claims = vec![
            ProfileClaim {
                field: "role".into(),
                value_json: "\"developer\"".into(),
                confidence: 0.92,
            },
            ProfileClaim {
                field: "lang_count".into(),
                value_json: "3".into(),
                confidence: 0.8,
            },
            ProfileClaim {
                field: "is_active".into(),
                value_json: "true".into(),
                confidence: 0.75,
            },
        ];
        let rendered = render_for_synthesis_prompt(&claims);
        assert!(rendered.contains("- role: developer (conf 0.92)"));
        assert!(rendered.contains("- lang_count: 3 (conf 0.80)"));
        assert!(rendered.contains("- is_active: true (conf 0.75)"));
    }

    #[test]
    fn render_empty_input_is_empty_string() {
        assert!(render_for_synthesis_prompt(&[]).is_empty());
    }

    #[test]
    fn render_value_for_prompt_falls_back_on_malformed_json() {
        // Malformed JSON should NOT panic — surface verbatim.
        assert_eq!(render_value_for_prompt("not json {{{"), "not json {{{");
    }
}
