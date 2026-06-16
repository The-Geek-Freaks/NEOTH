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

/// Daily + yearly self-reflection cadences (mirrors the weekly OB-02 pattern):
/// archivable records + Obsidian daily-notes / yearly summaries.
pub mod periodic;

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
    "auf", "in", "im", "an", "am", "zu", "zum", "zur", "mit", "von", "vom", "für", "über", "das",
    "wie", "was", "wer", "wo", "warum", "wann", // English stopwords
    "the", "a", "an", "and", "or", "but", "of", "in", "on", "to", "for", "with", "is", "it", "i",
    "you", "he", "she", "we", "they", "this", "that", "what", "when", "where", "why", "have",
    "has", "had", "do", "does", "did", "be", "been", "being", "are", "was", "were", "will",
    "would", "should", "could", "can", "may", "might", "as", "at", "by", "from",
    // NEOTH chat noise
    "neoth", "chat", "ok", "okay", "yes", "no", "nö", "hm", "danke", "thanks",
];

/// `STOPWORDS` as a set, built once. `topic_counts` is on the hot path
/// (the G-01 topic-burst detector calls it twice per pattern-cron tick),
/// so we avoid rebuilding the HashSet on every call.
static STOPWORD_SET: std::sync::LazyLock<std::collections::HashSet<&'static str>> =
    std::sync::LazyLock::new(|| STOPWORDS.iter().copied().collect());

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
    top_topics_in_days(conn, now_ns, 7, n)
}

/// Generalised window variant of [`top_topics_last_7_days`] — top `n` operator
/// topics from the last `days` (daily reflection uses 1, weekly 7, yearly 365).
/// Same `(cutoff, now]` + RAW_TEXT-only filter so summaries reflect what the
/// OPERATOR wrote, not NEOTH's replies / `[INGRESS]` rows.
pub fn top_topics_in_days(
    conn: &Connection,
    now_ns: i64,
    days: i64,
    n: usize,
) -> Result<Vec<String>> {
    let cutoff = now_ns.saturating_sub(days.max(1) * NS_PER_DAY);
    let mut stmt = conn.prepare(
        "SELECT text FROM idx_episode \
         WHERE ts_ns > ?1 AND ts_ns <= ?2 AND event_type = ?3",
    )?;
    let rows: Vec<String> = stmt
        .query_map(
            rusqlite::params![
                cutoff,
                now_ns,
                crate::wal::events::EVENT_TYPE_RAW_TEXT as i64
            ],
            |r| r.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<_>>()?;
    Ok(score_topics(&rows, n))
}

/// Pure frequency map over a slice of texts: lowercased alphanumeric
/// tokens, stopwords + sub-4-char words dropped. The shared core that
/// [`score_topics`] ranks AND `daemon::pattern_cron`'s topic-burst
/// detector (G-01) compares across two time windows. Public so both
/// consumers + tests share one tokeniser (no drift between the weekly
/// reflection topics and the burst detector's notion of a "topic").
pub fn topic_counts(texts: &[String]) -> HashMap<String, usize> {
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
            if STOPWORD_SET.contains(lower.as_str()) {
                continue;
            }
            *counts.entry(lower).or_insert(0) += 1;
        }
    }
    counts
}

/// Pure frequency-pass over a slice of texts. Public so tests can
/// exercise the scoring without an open SQLite connection. Ranks
/// [`topic_counts`] desc by count, ties broken alphabetically.
pub fn score_topics(texts: &[String], n: usize) -> Vec<String> {
    let mut pairs: Vec<(String, usize)> = topic_counts(texts).into_iter().collect();
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
        is_failure: false,
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

// ── OB-02: persistence + Obsidian vault sync ─────────────────────────────
//
// Mirrors the OB-01 dreaming surface: reflections persist as JSONL under
// `~/.neoth/reflections/<iso-week>.jsonl` (append-only, one reflection
// per line). The vault sync renders every reflection for an ISO week
// into `<vault>/<subdir>/Reflections/<iso-week>.md` via the same atomic
// `.tmp` + rename dance as OB-01.

/// One archived weekly reflection. The shape stays serde-stable so
/// historical reflections survive schema evolution — any new field
/// MUST be `#[serde(default)]`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WeeklyReflection {
    /// ISO-week tag like `"2026-W21"`. Doubles as the dedup_key
    /// suffix shared with the [`ProactiveItem`] G-01-mini already
    /// emits.
    pub iso_week_tag: String,
    /// Unix seconds when the reflection was composed.
    pub generated_ts_unix: i64,
    /// Top-N topics that fed the reflection body. Kept verbatim so
    /// Dataview queries can filter on individual topic strings.
    pub topics: Vec<String>,
    /// The operator-facing body (German template per the
    /// REFLECTION_BODY_TEMPLATE).
    pub body: String,
    /// Operator-supplied or auto-derived tags. Empty by default.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl WeeklyReflection {
    /// Render to Obsidian-flavored markdown — YAML frontmatter
    /// (iso_week / generated_unix / topics / tags) + H1 + ## Body +
    /// ## Topics list. Field order pinned for Dataview query
    /// stability.
    pub fn to_obsidian_md(&self) -> String {
        let yaml_tags = if self.tags.is_empty() {
            "tags: []".to_string()
        } else {
            let inner = self
                .tags
                .iter()
                .map(|t| format!("\"{}\"", escape_yaml_string(t)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("tags: [{inner}]")
        };
        let yaml_topics = if self.topics.is_empty() {
            "topics: []".to_string()
        } else {
            let inner = self
                .topics
                .iter()
                .map(|t| format!("\"{}\"", escape_yaml_string(t)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("topics: [{inner}]")
        };
        let topics_body = if self.topics.is_empty() {
            "(no topics)\n".to_string()
        } else {
            self.topics
                .iter()
                .map(|t| format!("- {t}\n"))
                .collect::<String>()
        };
        format!(
            "---\n\
             iso_week: \"{week}\"\n\
             generated_unix: {ts}\n\
             {yaml_topics}\n\
             {yaml_tags}\n\
             ---\n\n\
             # Reflection {week}\n\n\
             ## Body\n\n\
             {body}\n\n\
             ## Topics\n\n\
             {topics_body}",
            week = escape_yaml_string(&self.iso_week_tag),
            ts = self.generated_ts_unix,
            body = self.body,
        )
    }
}

/// Escape a string for embedding inside a YAML double-quoted scalar.
/// Same conservative rule as `dreaming::escape_yaml_string`.
fn escape_yaml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Directory under `home` that holds the per-week JSONL files.
pub fn reflections_dir(home: &std::path::Path) -> std::path::PathBuf {
    home.join("reflections")
}

/// File for a given ISO-week tag.
pub fn jsonl_file_for_week(home: &std::path::Path, iso_week: &str) -> std::path::PathBuf {
    reflections_dir(home).join(format!("{iso_week}.jsonl"))
}

/// Append one reflection to its ISO-week JSONL. Creates the
/// reflections dir on demand. Mirrors `dreaming::append_dream`.
pub fn append_reflection(
    home: &std::path::Path,
    reflection: &WeeklyReflection,
) -> std::io::Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    fs::create_dir_all(reflections_dir(home))?;
    let path = jsonl_file_for_week(home, &reflection.iso_week_tag);
    let mut line = serde_json::to_vec(reflection).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(&line)?;
    f.flush()?;
    Ok(())
}

/// Load every reflection for `iso_week`. Missing file → empty;
/// malformed lines skipped (corrupted disk doesn't kill the read path).
pub fn load_reflections_for_week(home: &std::path::Path, iso_week: &str) -> Vec<WeeklyReflection> {
    use std::fs;
    let path = jsonl_file_for_week(home, iso_week);
    let Ok(body) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    body.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Outcome of [`sync_reflections_to_obsidian`]. Same shape as
/// `DreamSyncOutcome` so a future generic "vault sync" trait can
/// adopt both without surface churn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectionSyncOutcome {
    pub iso_week_tag: String,
    pub written: bool,
    pub target_path: std::path::PathBuf,
    pub reflection_count: usize,
    pub bytes_written: usize,
}

/// OB-02 — collect every reflection for `iso_week_tag` and write a
/// single Obsidian markdown file to
/// `<vault>/<subdir>/Reflections/<iso-week>.md`. Multiple
/// reflections for the same week (rare — typically 1/week, but the
/// shape handles re-runs) concat with `\n---\n\n` thematic break.
/// Empty week → no file written; outcome carries `written: false`
/// so the vault stays clean for quiet weeks.
pub fn sync_reflections_to_obsidian(
    neoth_home: &std::path::Path,
    vault_root: &std::path::Path,
    subdir: &str,
    iso_week_tag: &str,
) -> std::io::Result<ReflectionSyncOutcome> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    let reflections = load_reflections_for_week(neoth_home, iso_week_tag);
    let dest_dir = vault_root.join(subdir).join("Reflections");
    let target_path = dest_dir.join(format!("{iso_week_tag}.md"));

    if reflections.is_empty() {
        return Ok(ReflectionSyncOutcome {
            iso_week_tag: iso_week_tag.to_string(),
            written: false,
            target_path,
            reflection_count: 0,
            bytes_written: 0,
        });
    }

    let body: String = reflections
        .iter()
        .map(WeeklyReflection::to_obsidian_md)
        .collect::<Vec<_>>()
        .join("\n---\n\n");

    fs::create_dir_all(&dest_dir)?;
    let tmp_path = dest_dir.join(format!("{iso_week_tag}.md.tmp"));
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(body.as_bytes())?;
        f.flush()?;
    }
    // Windows: rename over existing file fails — remove first.
    if target_path.exists() {
        fs::remove_file(&target_path)?;
    }
    fs::rename(&tmp_path, &target_path)?;

    Ok(ReflectionSyncOutcome {
        iso_week_tag: iso_week_tag.to_string(),
        written: true,
        target_path,
        reflection_count: reflections.len(),
        bytes_written: body.len(),
    })
}

/// Compose a [`WeeklyReflection`] from the already-extracted topics
/// + iso_week_tag + timestamp. Mirrors `build_reflection_item` but
/// returns the archivable record instead of the proactive-queue
/// item, so cron paths can do both (enqueue + archive) without
/// duplicating topic-extraction work.
pub fn build_weekly_reflection(
    iso_week_tag: &str,
    topics: &[String],
    generated_ts_unix: i64,
) -> Option<WeeklyReflection> {
    if topics.is_empty() {
        return None;
    }
    let body = REFLECTION_BODY_TEMPLATE.replace("{topics}", &format_topics_phrase(topics));
    Some(WeeklyReflection {
        iso_week_tag: iso_week_tag.to_string(),
        generated_ts_unix,
        topics: topics.to_vec(),
        body,
        tags: Vec::new(),
    })
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
        insert(&conn, 1, now_ns - NS_PER_DAY, "memory tier work today");
        insert(&conn, 2, now_ns - 3 * NS_PER_DAY, "memory passing tests");
        insert(&conn, 3, now_ns - 6 * NS_PER_DAY, "memory consolidation");
        // 1 episode about "ancient" OUTSIDE the window — must be excluded.
        insert(
            &conn,
            4,
            now_ns - 30 * NS_PER_DAY,
            "ancient ancient ancient",
        );

        let topics = top_topics_last_7_days(&conn, now_ns, 3).unwrap();
        assert!(
            topics.contains(&"memory".to_string()),
            "in-window topic must appear"
        );
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
        assert!(
            item.body.contains("memory, wal, und recall"),
            "got: {}",
            item.body
        );
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
        assert!(
            !q.enqueue(item2),
            "same week must dedupe even with different topics"
        );
        // Next week — different tag → both can coexist.
        let item3 = build_reflection_item("2026-W22", &["wal".into()], 0).unwrap();
        assert!(q.enqueue(item3));
        assert_eq!(q.len(), 2);
    }

    // ── OB-02: WeeklyReflection + archive + vault sync ─────────────────

    fn make_reflection(week: &str, topics: &[&str]) -> WeeklyReflection {
        WeeklyReflection {
            iso_week_tag: week.to_string(),
            generated_ts_unix: 1_700_000_000,
            topics: topics.iter().map(|s| (*s).to_string()).collect(),
            body: "Du hast diese Woche an rust und memory gearbeitet.".to_string(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn ob02_to_obsidian_md_has_frontmatter_and_h1() {
        let r = make_reflection("2026-W21", &["rust", "memory"]);
        let md = r.to_obsidian_md();
        assert!(md.starts_with("---\n"), "missing leading YAML delim: {md}");
        assert!(md.contains("iso_week: \"2026-W21\""));
        assert!(md.contains("generated_unix: 1700000000"));
        assert!(md.contains("topics: [\"rust\", \"memory\"]"));
        assert!(md.contains("tags: []"));
        assert!(md.contains("# Reflection 2026-W21"));
        assert!(md.contains("## Body"));
        assert!(md.contains("## Topics"));
    }

    #[test]
    fn ob02_to_obsidian_md_empty_topics_renders_placeholder() {
        let r = make_reflection("2026-W21", &[]);
        let md = r.to_obsidian_md();
        assert!(md.contains("topics: []"));
        assert!(
            md.contains("(no topics)"),
            "missing topics placeholder: {md}"
        );
    }

    #[test]
    fn ob02_to_obsidian_md_escapes_quotes_in_topic() {
        let r = make_reflection("2026-W21", &["that \"thing\""]);
        let md = r.to_obsidian_md();
        // The inline topic list must escape the embedded quote.
        assert!(
            md.contains("topics: [\"that \\\"thing\\\"\"]"),
            "quote not escaped in topics: {md}",
        );
    }

    #[test]
    fn ob02_append_and_load_roundtrip() {
        let home = tempfile::tempdir().unwrap();
        let r1 = make_reflection("2026-W21", &["rust"]);
        let r2 = make_reflection("2026-W21", &["memory"]);
        append_reflection(home.path(), &r1).unwrap();
        append_reflection(home.path(), &r2).unwrap();

        let loaded = load_reflections_for_week(home.path(), "2026-W21");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].topics, vec!["rust"]);
        assert_eq!(loaded[1].topics, vec!["memory"]);
    }

    #[test]
    fn ob02_load_missing_week_returns_empty() {
        let home = tempfile::tempdir().unwrap();
        let loaded = load_reflections_for_week(home.path(), "1999-W01");
        assert!(loaded.is_empty());
    }

    #[test]
    fn ob02_load_skips_malformed_lines() {
        let home = tempfile::tempdir().unwrap();
        let week = "2026-W21";
        std::fs::create_dir_all(reflections_dir(home.path())).unwrap();
        let path = jsonl_file_for_week(home.path(), week);
        let r = make_reflection(week, &["rust"]);
        let mut body = serde_json::to_string(&r).unwrap();
        body.push('\n');
        body.push_str("this is not json\n");
        body.push_str(&serde_json::to_string(&r).unwrap());
        body.push('\n');
        std::fs::write(&path, body).unwrap();

        let loaded = load_reflections_for_week(home.path(), week);
        assert_eq!(loaded.len(), 2, "malformed line must be skipped");
    }

    #[test]
    fn ob02_sync_no_reflections_skips_write() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let out =
            sync_reflections_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-W21").unwrap();
        assert!(!out.written);
        assert_eq!(out.reflection_count, 0);
        assert!(!out.target_path.exists());
    }

    #[test]
    fn ob02_sync_single_reflection_writes_file() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        append_reflection(home.path(), &make_reflection("2026-W21", &["rust"])).unwrap();

        let out =
            sync_reflections_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-W21").unwrap();
        assert!(out.written);
        assert_eq!(out.reflection_count, 1);
        let body = std::fs::read_to_string(&out.target_path).unwrap();
        assert!(body.contains("# Reflection 2026-W21"));
        assert!(body.contains("topics: [\"rust\"]"));
    }

    #[test]
    fn ob02_sync_multiple_reflections_joined_with_hr() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        append_reflection(home.path(), &make_reflection("2026-W21", &["rust"])).unwrap();
        append_reflection(home.path(), &make_reflection("2026-W21", &["memory"])).unwrap();

        let out =
            sync_reflections_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-W21").unwrap();
        assert_eq!(out.reflection_count, 2);
        let body = std::fs::read_to_string(&out.target_path).unwrap();
        assert!(body.contains("topics: [\"rust\"]"));
        assert!(body.contains("topics: [\"memory\"]"));
        assert!(body.contains("\n---\n\n"));
    }

    #[test]
    fn ob02_sync_overwrites_stale_existing_file() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let dest_dir = vault.path().join("NEOTH").join("Reflections");
        std::fs::create_dir_all(&dest_dir).unwrap();
        std::fs::write(dest_dir.join("2026-W21.md"), "STALE").unwrap();

        append_reflection(home.path(), &make_reflection("2026-W21", &["fresh"])).unwrap();
        let out =
            sync_reflections_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-W21").unwrap();
        let body = std::fs::read_to_string(&out.target_path).unwrap();
        assert!(!body.contains("STALE"));
        assert!(body.contains("topics: [\"fresh\"]"));
    }

    #[test]
    fn ob02_sync_target_lives_under_vault_subdir_reflections() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        append_reflection(home.path(), &make_reflection("2026-W21", &["t"])).unwrap();

        let out =
            sync_reflections_to_obsidian(home.path(), vault.path(), "CUSTOM", "2026-W21").unwrap();
        let expected = vault
            .path()
            .join("CUSTOM")
            .join("Reflections")
            .join("2026-W21.md");
        assert_eq!(out.target_path, expected);
    }

    #[test]
    fn ob02_sync_bytes_written_matches_file_size() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        append_reflection(home.path(), &make_reflection("2026-W21", &["rust"])).unwrap();

        let out =
            sync_reflections_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-W21").unwrap();
        let actual = std::fs::metadata(&out.target_path).unwrap().len() as usize;
        assert_eq!(actual, out.bytes_written);
    }

    #[test]
    fn ob02_build_weekly_reflection_empty_topics_is_none() {
        let r = build_weekly_reflection("2026-W21", &[], 0);
        assert!(r.is_none());
    }

    #[test]
    fn ob02_build_weekly_reflection_renders_body_with_topics_phrase() {
        let topics = vec!["rust".to_string(), "memory".to_string()];
        let r = build_weekly_reflection("2026-W21", &topics, 1_700_000_000).unwrap();
        assert_eq!(r.iso_week_tag, "2026-W21");
        assert_eq!(r.generated_ts_unix, 1_700_000_000);
        assert_eq!(r.topics, topics);
        assert!(r.body.contains("rust und memory"));
        assert!(r.tags.is_empty());
    }

    #[test]
    fn ob02_no_tmp_file_lingers_after_sync() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        append_reflection(home.path(), &make_reflection("2026-W21", &["t"])).unwrap();

        let out =
            sync_reflections_to_obsidian(home.path(), vault.path(), "NEOTH", "2026-W21").unwrap();
        let dest_dir = out.target_path.parent().unwrap();
        let leftover = dest_dir.join("2026-W21.md.tmp");
        assert!(!leftover.exists(), "tmp file leaked: {leftover:?}");
    }
}
