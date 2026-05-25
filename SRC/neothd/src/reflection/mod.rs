//! G-01-mini (Session 24) — minimal Day-7 reflection cron.
//!
//! A4 F2-3 + A1 pinned the gap: without ANY proactive cadence in
//! week 1, operators classify NEOTH as "another chat client" and
//! never notice it's an agent. G-01-mini delivers the smallest
//! possible reflection that:
//!
//! 1. Fires once a week (operator-config-driven cadence; this
//!    module owns only the BUILD step).
//! 2. Pulls the top-3 most-mentioned conversation topics from the
//!    last 7 days via a deterministic keyword-frequency pass over
//!    `idx_episode.text`. No LLM, no embeddings, no
//!    pattern-detection engine — those land in v0.9 G-01 proper.
//! 3. Renders one hardcoded German template:
//!    "Du hast diese Woche an [X], [Y], [Z] gearbeitet — willst du
//!     an einem mehr dranbleiben?"
//! 4. Enqueues the result into the shared [`crate::proactive::
//!    ProactiveQueue`] (G-01a substrate) at priority 50 with
//!    dedup_key `"reflection:weekly:<iso-week>"` so the same week
//!    can't double-fire even if the cron triggers multiple times.
//!
//! ## Why a deterministic frequency pass + not an LLM
//!
//! Day-7 reflection runs unattended, possibly while the operator's
//! cloud-provider quota is exhausted. A keyword-frequency pass is
//! free, instantaneous, and produces sensible results for the
//! 90% case (operator's main topic this week IS the word that
//! appears most). The 10% case where it gets the topic wrong is
//! still better than no reflection at all; v0.9 G-01 replaces the
//! frequency pass with the dedicated pattern engine.

use std::collections::HashMap;

use anyhow::Result;
use rusqlite::Connection;

use crate::proactive::ProactiveItem;

const NS_PER_DAY: i64 = 86_400 * 1_000_000_000;

/// Operator-facing template body. Pinned as a constant so tests +
/// docs reference the same string. German per the operator's
/// primary language preference (see [[user_role.md]] / CLAUDE.md).
pub const REFLECTION_BODY_TEMPLATE: &str =
    "Du hast diese Woche an {topics} gearbeitet — willst du an einem mehr dranbleiben?";

/// Stopwords excluded from frequency counting. Includes the most
/// common German function words + standard English stopwords (chat
/// is often mixed-language) + NEOTH-specific noise words operators
/// don't want as topics ("neoth" / "chat" / "ja" / "ok").
const STOPWORDS: &[&str] = &[
    // German function words
    "der", "die", "das", "den", "dem", "des", "ein", "eine", "einer", "einen", "einem", "eines",
    "und", "oder", "aber", "doch", "weil", "wenn", "dann", "ja", "nein", "nicht", "kein", "keine",
    "ich", "du", "er", "sie", "es", "wir", "ihr", "mich", "dich", "uns", "euch", "mein", "dein",
    "ist", "war", "sind", "waren", "hat", "habe", "haben", "wird", "werden", "kann", "können",
    "auf", "in", "im", "an", "am", "zu", "zum", "zur", "mit", "von", "vom", "für", "über",
    "das", "wie", "was", "wer", "wo", "warum", "wann",
    // English stopwords
    "the", "a", "an", "and", "or", "but", "of", "in", "on", "to", "for", "with", "is", "it",
    "i", "you", "he", "she", "we", "they", "this", "that", "what", "when", "where", "why",
    "have", "has", "had", "do", "does", "did", "be", "been", "being", "are", "was", "were",
    "will", "would", "should", "could", "can", "may", "might", "as", "at", "by", "from",
    // NEOTH chat noise
    "neoth", "chat", "ok", "okay", "ja", "yes", "no", "nö", "hm", "danke", "thanks",
];

/// Extract the top-`n` most-mentioned topics from the last 7 days
/// of `idx_episode.text`, ordered by frequency descending. Splits on
/// non-alphanumeric, lowercases, drops stopwords + words < 4 chars
/// (short words are usually function-word noise that slipped the
/// stopword list). Returns Vec sorted desc by count then ascending
/// alphabetically (stable across ties).
///
/// Pure helper — split out from the producer so tests assert against
/// data rather than the cron's enqueue side effect.
pub fn top_topics_last_7_days(conn: &Connection, now_ns: i64, n: usize) -> Result<Vec<String>> {
    let cutoff = now_ns.saturating_sub(7 * NS_PER_DAY);
    let mut stmt = conn.prepare(
        "SELECT text FROM idx_episode WHERE ts_ns >= ?1 AND ts_ns <= ?2",
    )?;
    let rows: Vec<String> = stmt
        .query_map(rusqlite::params![cutoff, now_ns], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(score_topics(&rows, n))
}

/// Pure frequency-pass over a slice of texts. Public so tests can
/// exercise the scoring without an open SQLite connection.
pub fn score_topics(texts: &[String], n: usize) -> Vec<String> {
    let stopwords: std::collections::HashSet<&str> = STOPWORDS.iter().copied().collect();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for text in texts {
        for word in text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
        {
            let lower = word.to_lowercase();
            if lower.chars().count() < 4 {
                continue;
            }
            if stopwords.contains(lower.as_str()) {
                continue;
            }
            *counts.entry(lower).or_insert(0) += 1;
        }
    }
    let mut pairs: Vec<(String, usize)> = counts.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    pairs.truncate(n);
    pairs.into_iter().map(|(k, _)| k).collect()
}

/// Compose the ProactiveItem that the cron enqueues. Pure helper —
/// the cron's only job is to call this then push the result through
/// `ProactiveQueue::enqueue`.
///
/// `iso_week_tag` is a stable string like `"2026-W21"` (or any
/// week-identifier the caller picks); becomes part of the dedup_key
/// so the same week can't double-fire.
pub fn build_reflection_item(
    iso_week_tag: &str,
    topics: &[String],
    scheduled_for_unix: i64,
) -> Option<ProactiveItem> {
    if topics.is_empty() {
        // No topics extracted = no signal to reflect on. Skip the
        // notification entirely rather than nudging the operator
        // with a vacuous prompt.
        return None;
    }
    let topics_phrase = format_topics_phrase(topics);
    let body = REFLECTION_BODY_TEMPLATE.replace("{topics}", &topics_phrase);
    Some(ProactiveItem {
        priority: 50,
        dedup_key: format!("reflection:weekly:{iso_week_tag}"),
        channel: String::new(),
        source: "g_01_mini".into(),
        body,
        scheduled_for_unix,
    })
}

/// Render a topics list into a German "X, Y und Z" Oxford-style
/// phrase. Cosmetic but operator-facing — a comma-only list reads
/// like a search hit, not a sentence.
fn format_topics_phrase(topics: &[String]) -> String {
    match topics.len() {
        0 => String::new(),
        1 => topics[0].clone(),
        2 => format!("{} und {}", topics[0], topics[1]),
        _ => {
            let head = topics[..topics.len() - 1].join(", ");
            format!("{}, und {}", head, topics[topics.len() - 1])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn open_db() -> Connection {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        let conn = crate::memory::store::open(&path).unwrap();
        std::mem::forget(dir);
        conn
    }

    fn insert(conn: &Connection, event_id: i64, ts_ns: i64, text: &str) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, 1, ?2, ?3, ?4, 0.5, ?2)",
            params![event_id, ts_ns, text, format!("h-{event_id}")],
        )
        .unwrap();
    }

    #[test]
    fn score_topics_ranks_by_frequency_desc() {
        let texts = vec![
            "Rust ist gut. Rust ist schnell. Rust ist sicher.".into(),
            "Python is also good. Rust again.".into(),
            "WebAssembly tooling matters.".into(),
        ];
        let topics = score_topics(&texts, 3);
        // "rust" appears 4 times → first. Other 4+letter words tie
        // at 1 and break alphabetically.
        assert_eq!(topics[0], "rust");
        assert_eq!(topics.len(), 3);
    }

    #[test]
    fn score_topics_excludes_stopwords_and_short_words() {
        let texts = vec!["der die das und oder aber I he she we".into()];
        let topics = score_topics(&texts, 5);
        assert!(topics.is_empty(), "stopwords + short words → no topics");
    }

    #[test]
    fn score_topics_is_case_insensitive() {
        let texts = vec!["Memory MEMORY memory Memory".into()];
        let topics = score_topics(&texts, 1);
        assert_eq!(topics, vec!["memory"]);
    }

    #[test]
    fn score_topics_tie_breaks_alphabetically() {
        let texts = vec!["zebra apple monkey".into()];
        let topics = score_topics(&texts, 3);
        // All tied at 1 → alphabetical.
        assert_eq!(topics, vec!["apple", "monkey", "zebra"]);
    }

    #[test]
    fn score_topics_caps_at_n() {
        let texts: Vec<String> = (0..20)
            .map(|i| format!("word{i:02} word{i:02} word{i:02}"))
            .collect();
        let topics = score_topics(&texts, 5);
        assert_eq!(topics.len(), 5);
    }

    #[test]
    fn top_topics_last_7_days_respects_window() {
        let conn = open_db();
        let now_ns: i64 = 1_700_000_000_000_000_000;
        // 3 episodes about "memory" within the window.
        insert(&conn, 1, now_ns - 1 * NS_PER_DAY, "memory tier work today");
        insert(&conn, 2, now_ns - 3 * NS_PER_DAY, "memory passing tests");
        insert(&conn, 3, now_ns - 6 * NS_PER_DAY, "memory consolidation");
        // 1 episode about "ancient" OUTSIDE the window — must be excluded.
        insert(&conn, 4, now_ns - 30 * NS_PER_DAY, "ancient ancient ancient");

        let topics = top_topics_last_7_days(&conn, now_ns, 3).unwrap();
        assert!(topics.contains(&"memory".to_string()), "in-window topic must appear");
        assert!(
            !topics.contains(&"ancient".to_string()),
            "out-of-window topic must be excluded",
        );
    }

    #[test]
    fn build_reflection_item_renders_template_with_topics() {
        let item = build_reflection_item(
            "2026-W21",
            &["memory".into(), "wal".into(), "recall".into()],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(item.priority, 50);
        assert_eq!(item.dedup_key, "reflection:weekly:2026-W21");
        assert_eq!(item.source, "g_01_mini");
        assert!(item.body.contains("memory, wal, und recall"), "got: {}", item.body);
        assert!(item.body.contains("dranbleiben"), "template tail missing");
    }

    #[test]
    fn build_reflection_item_returns_none_when_topics_empty() {
        // No reflection = no vacuous nudge. Operator gets a fresh
        // week instead of "Du hast diese Woche an  gearbeitet …".
        let r = build_reflection_item("2026-W21", &[], 0);
        assert!(r.is_none());
    }

    #[test]
    fn format_topics_phrase_handles_one_two_and_many() {
        assert_eq!(format_topics_phrase(&["a".into()]), "a");
        assert_eq!(format_topics_phrase(&["a".into(), "b".into()]), "a und b");
        assert_eq!(
            format_topics_phrase(&["a".into(), "b".into(), "c".into()]),
            "a, b, und c",
        );
    }

    #[test]
    fn reflection_item_uniquely_keyed_so_same_week_dedupes() {
        // Drift guard for the dedup contract: enqueue twice with
        // the same week tag → second is a no-op.
        let mut q = crate::proactive::ProactiveQueue::new();
        let item1 = build_reflection_item("2026-W21", &["memory".into()], 0).unwrap();
        let item2 = build_reflection_item("2026-W21", &["recall".into()], 0).unwrap();
        assert!(q.enqueue(item1));
        assert!(!q.enqueue(item2), "same week must dedupe even with different topics");
        // Next week — different tag → both can coexist.
        let item3 = build_reflection_item("2026-W22", &["wal".into()], 0).unwrap();
        assert!(q.enqueue(item3));
        assert_eq!(q.len(), 2);
    }
}
