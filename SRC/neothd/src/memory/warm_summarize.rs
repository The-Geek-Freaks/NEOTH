//! GOLD-FEAT-12 (b) — warm-tier local summarization.
//!
//! When the consolidation pass migrates a day's hot episodes into the warm tier
//! (`idx_consolidated` `kind='retained'`), a LOCAL provider can roll that day up
//! into one dense `kind='summary'` row. Recall (`recall_warm_like`) already
//! surfaces both kinds, so a summarised day costs far fewer prompt tokens to
//! inject than its individual events — without any cloud billing, because the
//! summarize call is gated to local providers only.
//!
//! ## Why summarize in the consolidation pass, not at recall time
//!
//! The recall path runs its SQLite query inside `spawn_blocking` (sync
//! rusqlite). `local_qwen::complete` ALSO uses `spawn_blocking` internally, so a
//! `block_on(provider.complete(..))` nested inside the recall `spawn_blocking`
//! would deadlock a single-threaded runtime. The consolidation cron
//! (`decay_task::run_once`) is async and runs every 2h — it does the sync
//! consolidation in `spawn_blocking`, then runs THIS async summarize pass AFTER
//! that closure returns (never nested), writing the summary rows for next
//! recall to find.

use std::collections::HashMap;

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

use crate::config::policy::MeetingSummaryConfig;
use crate::memory::summarize_prompt::SummarizePromptLayers;
use crate::providers::{Provider, Request};

/// Max chars of concatenated event text fed to the summarizer — keeps the
/// prompt cheap on local weights even for a busy day.
const MAX_SUMMARY_INPUT_CHARS: usize = 2000;

/// GOLD-ADAPT-SPEAKR-01 — the hardcoded baseline summarizer layers. The
/// system framing lands in the `admin` (context) slot, the instruction in the
/// `append` (lowest-priority instruction) slot, so an operator's
/// `skills.meeting_summary.*` layers override either independently.
pub const DEFAULT_SUMMARY_SYSTEM: &str = "You are a terse memory summarizer.";
pub const DEFAULT_SUMMARY_INSTRUCTION: &str =
    "Summarize the following memory events from a single day in 2-3 sentences. \
     Preserve names, dates, and decisions; drop filler.";

/// Build the bounded event body (truncated, UTF-8-safe). Pure (no I/O).
pub fn build_summary_body(events: &[(i64, String)]) -> String {
    let mut body = String::new();
    for (_id, text) in events {
        let t = text.trim();
        if t.is_empty() {
            continue;
        }
        // Stop once we already have content AND the next event would overflow —
        // but ALWAYS admit the first non-empty event (char-truncated if it alone
        // exceeds the cap) so a single very long retained row never yields an
        // empty prompt → a vacuous/hallucinated summary.
        if !body.is_empty() && body.len() + t.len() + 1 > MAX_SUMMARY_INPUT_CHARS {
            break;
        }
        if t.chars().count() > MAX_SUMMARY_INPUT_CHARS {
            // char boundary safe (never splits a UTF-8 sequence).
            body.extend(t.chars().take(MAX_SUMMARY_INPUT_CHARS));
        } else {
            body.push_str(t);
        }
        body.push('\n');
        if body.len() >= MAX_SUMMARY_INPUT_CHARS {
            break;
        }
    }
    body.trim().to_string()
}

/// Build the default summarize prompt (instruction + body). Pure; retained for
/// the back-compat / unit-test surface.
pub fn build_summary_prompt(events: &[(i64, String)]) -> String {
    format!(
        "{DEFAULT_SUMMARY_INSTRUCTION}\n\n{}",
        build_summary_body(events)
    )
}

/// GOLD-ADAPT-SPEAKR-01 — map the operator's `skills.meeting_summary` config
/// onto [`SummarizePromptLayers`], seeded with the hardcoded defaults so a
/// fully-empty config reproduces the legacy prompt exactly. Any set layer
/// overrides its default.
pub fn summary_layers(cfg: Option<&MeetingSummaryConfig>) -> SummarizePromptLayers {
    let mut layers = SummarizePromptLayers {
        admin: Some(DEFAULT_SUMMARY_SYSTEM.to_string()),
        append: Some(DEFAULT_SUMMARY_INSTRUCTION.to_string()),
        ..Default::default()
    };
    if let Some(c) = cfg {
        if c.admin.is_some() {
            layers.admin = c.admin.clone();
        }
        if c.user.is_some() {
            layers.user = c.user.clone();
        }
        if c.folder.is_some() {
            layers.folder = c.folder.clone();
        }
        if c.tag.is_some() {
            layers.tag = c.tag.clone();
        }
        if c.append.is_some() {
            layers.append = c.append.clone();
        }
        layers.append_mode = c.append_mode;
    }
    layers
}

/// Summarize one day's retained events via the (local) provider. Async — call
/// it from the async consolidation pass, NEVER from inside a `spawn_blocking`
/// closure (see the module note on the nested-`block_on` deadlock).
///
/// GOLD-ADAPT-SPEAKR-01: the (system, instruction) prompt is composed from
/// `layers` ([`summary_layers`]) so an operator can override the summarizer
/// prompt via `freedom.yaml::skills.meeting_summary`. The event body is appended
/// to the composed instruction. Empty composed sides fall back to the hardcoded
/// defaults (defence-in-depth — `summary_layers` always seeds them).
pub async fn summarize_day_batch(
    provider: &dyn Provider,
    events: &[(i64, String)],
    layers: &SummarizePromptLayers,
) -> Result<String> {
    let body = build_summary_body(events);
    let (mut system, mut instruction) = layers.compose_with_roles(&HashMap::new());
    if system.trim().is_empty() {
        system = DEFAULT_SUMMARY_SYSTEM.to_string();
    }
    if instruction.trim().is_empty() {
        instruction = DEFAULT_SUMMARY_INSTRUCTION.to_string();
    }
    let req = Request {
        prompt: format!("{instruction}\n\n{body}"),
        system: Some(system),
        ..Default::default()
    };
    let completion = provider
        .complete(req)
        .await
        .context("warm-tier summarize provider call")?;
    Ok(completion.text.trim().to_string())
}

/// True when `day` has at least two `kind='retained'` rows and no `kind='summary'`
/// row yet — so we never burn inference on a single-event day or re-summarize a
/// day that already has its rollup.
pub fn needs_summary(conn: &Connection, day: &str) -> Result<bool> {
    let has_summary: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM idx_consolidated WHERE day = ?1 AND kind = 'summary')",
        params![day],
        |r| r.get(0),
    )?;
    if has_summary {
        return Ok(false);
    }
    let retained: i64 = conn.query_row(
        "SELECT COUNT(*) FROM idx_consolidated WHERE day = ?1 AND kind = 'retained'",
        params![day],
        |r| r.get(0),
    )?;
    Ok(retained >= 2)
}

/// Load ALL `kind='retained'` rows for `day` if a summary is still needed
/// (≥ 2 retained rows, no existing summary). Returns `None` when the day
/// should be skipped; `Some(events)` is the complete retained list — not just
/// the rows migrated this pass, but every retained row for that day across all
/// prior passes. This is the source that `summarize_day_batch` must receive so
/// that multi-pass days get a summary covering their full warm-tier history.
pub fn load_day_for_summary(conn: &Connection, day: &str) -> Result<Option<Vec<(i64, String)>>> {
    if !needs_summary(conn, day)? {
        return Ok(None);
    }
    let mut stmt = conn.prepare(
        "SELECT COALESCE(event_id, -id), text \
         FROM idx_consolidated \
         WHERE day = ?1 AND kind = 'retained' \
         ORDER BY id ASC",
    )?;
    let rows = stmt
        .query_map(params![day], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("load retained rows for day summary")?;
    Ok(Some(rows))
}

/// Insert a synthesised `kind='summary'` row for `day`. `event_id` is NULL (the
/// summary is not one source event — `recall::touch_access`'s
/// `COALESCE(event_id, -id)` handles that), `importance` is a neutral 0.5 so it
/// surfaces in recall without dominating the operator's pinned facts.
pub fn insert_summary_row(conn: &Connection, day: &str, summary: &str, now_ns: i64) -> Result<()> {
    let text_hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(summary.as_bytes()));
    conn.execute(
        "INSERT INTO idx_consolidated \
         (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts, access_count) \
         VALUES ('summary', ?1, NULL, ?2, ?3, ?4, ?5, ?5, 0)",
        params![day, summary, text_hash, 0.5_f64, now_ns],
    )?;
    Ok(())
}

/// Insert a `kind='summary'` row for `day` ONLY if one is still needed, ATOMICALLY.
/// Closes a check-then-insert TOCTOU: the `needs_summary` re-check and the INSERT
/// run inside one `IMMEDIATE` write transaction, so two decay passes racing on the
/// same day (the 2h cron + a `neoth memory --decay` CLI, or two daemon instances
/// sharing the SQLite WAL) can never both write a summary — the loser's re-check
/// sees the winner's row and skips. (`idx_consolidated` has no `UNIQUE(day)` for
/// summaries, so the txn re-check is the dedup, not a constraint — no schema bump.)
/// Returns `true` when a row was inserted, `false` when a concurrent pass already
/// wrote it.
pub fn insert_summary_if_absent(
    conn: &mut Connection,
    day: &str,
    summary: &str,
    now_ns: i64,
) -> Result<bool> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if !needs_summary(&tx, day)? {
        return Ok(false); // lost the race / no longer qualifies — tx rolls back on drop
    }
    insert_summary_row(&tx, day, summary, now_ns)?;
    tx.commit()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Completion;
    use async_trait::async_trait;
    use std::time::Duration;

    /// Echo provider — returns a canned summary so the async path is testable
    /// without real weights.
    struct StubSummarizer;

    #[async_trait]
    impl Provider for StubSummarizer {
        fn name(&self) -> &'static str {
            "local_qwen"
        }
        async fn complete(&self, req: Request) -> Result<Completion> {
            // Prove the prompt reached us, then return a fixed summary.
            assert!(req.prompt.contains("Summarize"));
            Ok(Completion {
                text: "  Alex shipped Nostr and OP-01.  ".to_string(),
                model: "stub".to_string(),
                latency: Duration::from_millis(1),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    fn mem_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE idx_consolidated (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, day TEXT, \
                event_id INTEGER, text TEXT, text_hash TEXT, importance REAL, \
                consolidated_ts INTEGER, last_access_ts INTEGER, access_count INTEGER)",
            [],
        )
        .unwrap();
        conn
    }

    fn insert_retained(conn: &Connection, day: &str, id: i64, text: &str) {
        conn.execute(
            "INSERT INTO idx_consolidated (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts, access_count) \
             VALUES ('retained', ?1, ?2, ?3, 'h', 0.5, 1, 1, 0)",
            params![day, id, text],
        )
        .unwrap();
    }

    #[test]
    fn prompt_caps_input_and_skips_empty_events() {
        let events = vec![
            (1, "first".to_string()),
            (2, "   ".to_string()),
            (3, "second".to_string()),
        ];
        let p = build_summary_prompt(&events);
        assert!(p.contains("first"));
        assert!(p.contains("second"));
        assert!(p.starts_with("Summarize the following"));
    }

    #[test]
    fn needs_summary_requires_two_retained_and_no_existing_summary() {
        let conn = mem_conn();
        assert!(
            !needs_summary(&conn, "2026-06-15").unwrap(),
            "no rows → no summary"
        );
        insert_retained(&conn, "2026-06-15", 1, "a");
        assert!(
            !needs_summary(&conn, "2026-06-15").unwrap(),
            "one row → not worth it"
        );
        insert_retained(&conn, "2026-06-15", 2, "b");
        assert!(
            needs_summary(&conn, "2026-06-15").unwrap(),
            "two rows → summarize"
        );
        insert_summary_row(&conn, "2026-06-15", "rollup", 9).unwrap();
        assert!(
            !needs_summary(&conn, "2026-06-15").unwrap(),
            "already summarised → skip"
        );
    }

    #[test]
    fn insert_summary_row_is_readable_with_null_event_id() {
        let conn = mem_conn();
        insert_summary_row(&conn, "2026-06-15", "the day's rollup", 42).unwrap();
        let (text, importance, event_id): (String, f64, Option<i64>) = conn
            .query_row(
                "SELECT text, importance, event_id FROM idx_consolidated WHERE kind='summary'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(text, "the day's rollup");
        assert_eq!(importance, 0.5);
        assert_eq!(event_id, None, "summary rows carry no single source event");
    }

    #[tokio::test]
    async fn summarize_day_batch_trims_the_provider_reply() {
        let events = vec![
            (1, "did a thing".to_string()),
            (2, "did another".to_string()),
        ];
        let summary = summarize_day_batch(&StubSummarizer, &events, &summary_layers(None))
            .await
            .unwrap();
        assert_eq!(summary, "Alex shipped Nostr and OP-01.", "trimmed");
    }

    // GOLD-ADAPT-SPEAKR-01 — default layers reproduce the legacy prompt exactly.
    #[test]
    fn summary_layers_default_reproduces_hardcoded_prompt() {
        let layers = summary_layers(None);
        let (system, instruction) = layers.compose_with_roles(&HashMap::new());
        assert_eq!(system, DEFAULT_SUMMARY_SYSTEM);
        assert_eq!(instruction, DEFAULT_SUMMARY_INSTRUCTION);
    }

    // GOLD-ADAPT-SPEAKR-01 — an operator `user` layer overrides the default
    // instruction on the live summarize path (the wiring this item adds).
    #[test]
    fn summary_layers_operator_override_replaces_instruction() {
        let cfg = MeetingSummaryConfig {
            user: Some("Summarize as 5 bullet points.".to_string()),
            ..Default::default()
        };
        let layers = summary_layers(Some(&cfg));
        let (_system, instruction) = layers.compose_with_roles(&HashMap::new());
        assert_eq!(instruction, "Summarize as 5 bullet points.");
    }

    #[test]
    fn prompt_is_never_empty_when_first_event_exceeds_the_cap() {
        // A single retained row longer than the cap must still seed the prompt
        // (truncated) — an empty body would make the LLM summarize nothing.
        let huge = "x".repeat(MAX_SUMMARY_INPUT_CHARS + 500);
        let p = build_summary_prompt(&[(1, huge)]);
        let body = p.split("\n\n").nth(1).unwrap_or("");
        assert!(
            !body.trim().is_empty(),
            "long first event must seed a non-empty body"
        );
        assert!(
            body.chars().count() <= MAX_SUMMARY_INPUT_CHARS + 1,
            "and stay capped"
        );
    }

    #[test]
    fn insert_summary_if_absent_writes_once_then_skips_a_racing_insert() {
        let mut conn = mem_conn();
        insert_retained(&conn, "2026-06-15", 1, "a");
        insert_retained(&conn, "2026-06-15", 2, "b");
        assert!(
            insert_summary_if_absent(&mut conn, "2026-06-15", "first", 1).unwrap(),
            "first attempt inserts"
        );
        assert!(
            !insert_summary_if_absent(&mut conn, "2026-06-15", "second", 2).unwrap(),
            "the re-check inside the txn skips the duplicate"
        );
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_consolidated WHERE kind='summary'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "exactly one summary row despite two attempts");
    }

    #[test]
    fn load_day_for_summary_returns_none_when_already_summarised() {
        let conn = mem_conn();
        insert_retained(&conn, "2026-06-15", 1, "a");
        insert_retained(&conn, "2026-06-15", 2, "b");
        insert_summary_row(&conn, "2026-06-15", "rollup", 9).unwrap();
        assert!(
            load_day_for_summary(&conn, "2026-06-15").unwrap().is_none(),
            "already has summary → None"
        );
    }

    #[test]
    fn load_day_for_summary_returns_none_when_fewer_than_two_retained() {
        let conn = mem_conn();
        insert_retained(&conn, "2026-06-15", 1, "only one");
        assert!(
            load_day_for_summary(&conn, "2026-06-15").unwrap().is_none(),
            "single retained row → None"
        );
    }

    #[test]
    fn load_day_for_summary_returns_all_retained_across_passes() {
        // The critical multi-pass scenario: rows 1+2 were migrated in pass A,
        // row 3 in pass B. load_day_for_summary must return all three, not
        // just the rows the caller happens to pass via days_needing_summary.
        let conn = mem_conn();
        insert_retained(&conn, "2026-06-15", 1, "pass-A event one");
        insert_retained(&conn, "2026-06-15", 2, "pass-A event two");
        insert_retained(&conn, "2026-06-15", 3, "pass-B event three");

        let events = load_day_for_summary(&conn, "2026-06-15")
            .unwrap()
            .expect("three retained rows → Some");
        assert_eq!(events.len(), 3, "all three retained rows must be loaded");
        let texts: Vec<&str> = events.iter().map(|(_, t)| t.as_str()).collect();
        assert!(texts.contains(&"pass-A event one"));
        assert!(texts.contains(&"pass-A event two"));
        assert!(texts.contains(&"pass-B event three"));
    }
}
