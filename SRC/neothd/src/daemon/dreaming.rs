//! R-02 Dreaming pipeline — scaffold.
//!
//! Vision: periodically (default: nightly) the daemon surveys the
//! day's events, identifies thematic clusters, and writes a "dream"
//! entry that compresses the day into a few semantic anchors. Future
//! recall reads dreams BEFORE digging through individual events —
//! same shape as a human brain reaching for "what happened
//! yesterday?" before "what was the third sentence at 14:32?".
//!
//! This module ships the storage + types + composer shape so future
//! work (LLM-driven clustering, theme detection, embedding-based
//! recall hook) snaps in without rewriting the surface. The
//! ACTUAL clustering pass is multi-week — for now `compose_dream`
//! produces a deterministic snapshot of the input events that
//! operators can read + a Dream Day record that the pipeline can
//! later refine.
//!
//! Storage: `~/.neoth/dreams/<YYYY-MM-DD>.jsonl`. One dream per
//! line. Append-only — historical dreams stay readable as the
//! schema evolves (any added field is `serde(default)`).
//!
//! ## Pipeline shape (future Phase 2)
//!
//! 1. `gather_day_events(home, date)` — load every event from the
//!    WAL + idx_episode for the target day
//! 2. `cluster_themes(events)` — embedding-based + topic-modelling
//!    grouping (Phase 2 — needs Day-14b local inference)
//! 3. For each theme:
//!    a. `summarise_theme(theme_events) -> String` (Phase 2 — LLM)
//!    b. `compose_dream(theme_summary, events, motifs) -> Dream`
//!    c. `append_dream(home, &dream)` — JSONL persist
//! 4. `recall::seed_with_dreams(home, n)` — surface the N latest
//!    dreams BEFORE episode rows (Phase 2 wiring into existing
//!    recall composite score)

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// One persisted dream entry. The deterministic v0.1 composer
/// fills `theme_label` with a stable string derived from input
/// event ids; Phase 2 replaces this with LLM-summarised themes
/// while keeping the wire shape stable.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Dream {
    /// Unix seconds at composition time.
    pub composed_ts_unix: i64,
    /// Date this dream summarises (`YYYY-MM-DD` UTC).
    pub day: String,
    /// Operator-readable theme label. v0.1 deterministic; Phase 2
    /// becomes an LLM-summarised motif.
    pub theme_label: String,
    /// Compressed narrative of the theme. v0.1 prints the source
    /// event count + first/last timestamps; Phase 2 becomes a
    /// 2-3 sentence LLM summary.
    pub summary: String,
    /// Source-event anchors so the recall layer can drill from a
    /// dream BACK to the underlying events.
    pub event_ids: Vec<i64>,
    /// Tags for fast filtering. v0.1 empty; Phase 2 fills with
    /// motif keywords.
    pub tags: Vec<String>,
}

/// Input to `compose_dream` — minimal event shape that doesn't
/// pull in WAL types so the composer stays unit-testable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRef {
    pub id: i64,
    pub ts_unix: i64,
    /// Truncated preview the composer surfaces in the summary.
    pub preview: String,
}

/// Directory under `home` that holds the daily JSONL files.
pub fn dreams_dir(home: &Path) -> PathBuf {
    home.join("dreams")
}

/// File for a given `YYYY-MM-DD`.
pub fn jsonl_file_for_day(home: &Path, day: &str) -> PathBuf {
    dreams_dir(home).join(format!("{day}.jsonl"))
}

/// Compose one dream entry from a slice of events + a deterministic
/// theme label. v0.1 produces a stable snapshot the operator can
/// read; Phase 2 replaces this with LLM-driven clustering +
/// summarisation while keeping the return shape stable.
pub fn compose_dream(day: &str, theme_label: &str, events: &[EventRef]) -> Dream {
    let composed_ts_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let summary = if events.is_empty() {
        format!("Theme `{theme_label}`: no events in window.")
    } else {
        let first_ts = events.iter().map(|e| e.ts_unix).min().unwrap_or(0);
        let last_ts = events.iter().map(|e| e.ts_unix).max().unwrap_or(0);
        // Surface the first 2 + last event previews to give the
        // operator a quick "what was this about" anchor. Truncate
        // each preview at 120 chars char-boundary-safe.
        let mut anchors: Vec<String> = events
            .iter()
            .take(2)
            .map(|e| truncate_safe(&e.preview, 120))
            .collect();
        if events.len() > 2 {
            let last = events.last().unwrap();
            anchors.push(format!("… {}", truncate_safe(&last.preview, 120)));
        }
        format!(
            "Theme `{theme_label}`: {} events between ts={} and ts={}. Anchors: {}",
            events.len(),
            first_ts,
            last_ts,
            anchors.join(" | "),
        )
    };
    Dream {
        composed_ts_unix,
        day: day.to_string(),
        theme_label: theme_label.to_string(),
        summary,
        event_ids: events.iter().map(|e| e.id).collect(),
        tags: Vec::new(),
    }
}

/// Append one dream to its date-keyed JSONL. Creates the dreams
/// dir on demand. Best-effort I/O; the caller decides whether to
/// warn-and-continue or surface the error.
pub fn append_dream(home: &Path, dream: &Dream) -> std::io::Result<()> {
    fs::create_dir_all(dreams_dir(home))?;
    let path = jsonl_file_for_day(home, &dream.day);
    let mut line = serde_json::to_vec(dream).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(&line)?;
    f.flush()?;
    Ok(())
}

/// Load every dream for `day` (`YYYY-MM-DD`). Missing file → empty.
/// Malformed lines are skipped — corrupted disk states don't kill
/// the read path.
pub fn load_dreams_for_day(home: &Path, day: &str) -> Vec<Dream> {
    let path = jsonl_file_for_day(home, day);
    let Ok(body) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in body.lines() {
        if let Ok(d) = serde_json::from_str::<Dream>(line) {
            out.push(d);
        }
    }
    out
}

/// R-02 Phase 2: load every dream from the last `lookback_days`
/// days, filter to those whose theme_label OR summary OR tags
/// contain `query` (case-insensitive substring), and return up to
/// `max_hits`. Sorted by `composed_ts_unix` descending so the
/// newest dreams surface first — the recall layer prepends these
/// rows BEFORE episode hits so an operator's "what happened
/// yesterday" question reaches yesterday's dreams first.
pub fn seed_with_dreams(
    home: &Path,
    query: &str,
    lookback_days: u32,
    max_hits: usize,
) -> Vec<Dream> {
    let q = query.to_lowercase();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut all = Vec::new();
    for back in 0..lookback_days as i64 {
        let ts = now - back * 86_400;
        let day = format_date_utc(ts);
        for dream in load_dreams_for_day(home, &day) {
            let hay = format!(
                "{} {} {}",
                dream.theme_label.to_lowercase(),
                dream.summary.to_lowercase(),
                dream.tags.join(" ").to_lowercase(),
            );
            if q.is_empty() || hay.contains(&q) {
                all.push(dream);
            }
        }
    }
    all.sort_by_key(|d| std::cmp::Reverse(d.composed_ts_unix));
    all.truncate(max_hits);
    all
}

fn format_date_utc(ts_unix: i64) -> String {
    // Same Howard Hinnant civil-from-days algorithm as usage_log.
    let days = ts_unix.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let yy = if m <= 2 { y + 1 } else { y };
    format!("{yy:04}-{m:02}-{d:02}")
}

/// Char-boundary-safe truncation. Same shape as the helpers in
/// usage_log + skills::router so a future audit finds them
/// together.
fn truncate_safe(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn ev(id: i64, ts: i64, preview: &str) -> EventRef {
        EventRef {
            id,
            ts_unix: ts,
            preview: preview.into(),
        }
    }

    #[test]
    fn compose_dream_with_no_events_says_no_events() {
        let d = compose_dream("2026-05-22", "morning", &[]);
        assert_eq!(d.day, "2026-05-22");
        assert_eq!(d.theme_label, "morning");
        assert!(d.summary.contains("no events"));
        assert!(d.event_ids.is_empty());
        assert!(d.tags.is_empty());
    }

    #[test]
    fn compose_dream_surfaces_first_two_and_last_anchor() {
        let events = vec![
            ev(1, 100, "first"),
            ev(2, 200, "second"),
            ev(3, 300, "middle"),
            ev(4, 400, "last"),
        ];
        let d = compose_dream("2026-05-22", "work", &events);
        assert_eq!(d.event_ids, vec![1, 2, 3, 4]);
        assert!(d.summary.contains("4 events"));
        assert!(d.summary.contains("ts=100"));
        assert!(d.summary.contains("ts=400"));
        assert!(d.summary.contains("first"));
        assert!(d.summary.contains("second"));
        assert!(d.summary.contains("last"));
    }

    #[test]
    fn append_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let d = compose_dream("2026-05-22", "test", &[ev(1, 100, "hi")]);
        append_dream(dir.path(), &d).unwrap();
        let loaded = load_dreams_for_day(dir.path(), "2026-05-22");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].theme_label, "test");
        assert_eq!(loaded[0].event_ids, vec![1]);
    }

    #[test]
    fn append_multiple_dreams_to_same_day() {
        let dir = tempdir().unwrap();
        for label in ["morning", "afternoon", "evening"] {
            let d = compose_dream("2026-05-22", label, &[]);
            append_dream(dir.path(), &d).unwrap();
        }
        let loaded = load_dreams_for_day(dir.path(), "2026-05-22");
        assert_eq!(loaded.len(), 3);
    }

    #[test]
    fn load_dreams_missing_file_returns_empty() {
        let dir = tempdir().unwrap();
        assert!(load_dreams_for_day(dir.path(), "2026-05-22").is_empty());
    }

    #[test]
    fn load_dreams_skips_malformed_lines() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dreams_dir(dir.path())).unwrap();
        let file = jsonl_file_for_day(dir.path(), "2026-05-22");
        std::fs::write(
            &file,
            "{not json\n\
             {\"composed_ts_unix\":1,\"day\":\"2026-05-22\",\"theme_label\":\"x\",\
             \"summary\":\"y\",\"event_ids\":[],\"tags\":[]}\n\
             garbage\n",
        )
        .unwrap();
        let loaded = load_dreams_for_day(dir.path(), "2026-05-22");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].theme_label, "x");
    }

    #[test]
    fn compose_dream_truncates_long_previews() {
        let long: String = "a".repeat(500);
        let events = vec![ev(1, 100, &long)];
        let d = compose_dream("2026-05-22", "long", &events);
        // The summary line bound includes the truncation char.
        assert!(d.summary.contains("…"));
        // Stored event_ids stay full fidelity.
        assert_eq!(d.event_ids, vec![1]);
    }

    #[test]
    fn seed_with_dreams_empty_when_no_files() {
        let dir = tempdir().unwrap();
        let hits = seed_with_dreams(dir.path(), "anything", 7, 10);
        assert!(hits.is_empty());
    }

    #[test]
    fn seed_with_dreams_empty_query_returns_all_recent() {
        let dir = tempdir().unwrap();
        // Write a few dreams for today.
        let day = format_date_utc(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
        for (i, label) in ["alpha", "beta", "gamma"].iter().enumerate() {
            let mut d = compose_dream(&day, label, &[]);
            d.composed_ts_unix = (i as i64) * 10;
            append_dream(dir.path(), &d).unwrap();
        }
        let hits = seed_with_dreams(dir.path(), "", 7, 10);
        assert_eq!(hits.len(), 3);
        // Newest first.
        assert_eq!(hits[0].theme_label, "gamma");
        assert_eq!(hits[2].theme_label, "alpha");
    }

    #[test]
    fn seed_with_dreams_filters_by_substring_in_theme_or_summary() {
        let dir = tempdir().unwrap();
        let day = format_date_utc(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
        let mut a = compose_dream(&day, "auth_bug", &[]);
        a.tags.push("debug".into());
        append_dream(dir.path(), &a).unwrap();
        let b = compose_dream(&day, "vacation_plan", &[]);
        append_dream(dir.path(), &b).unwrap();
        let auth = seed_with_dreams(dir.path(), "auth", 7, 10);
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].theme_label, "auth_bug");
        let debug = seed_with_dreams(dir.path(), "debug", 7, 10);
        assert_eq!(debug.len(), 1, "tag substring also matches");
    }

    #[test]
    fn seed_with_dreams_respects_max_hits() {
        let dir = tempdir().unwrap();
        let day = format_date_utc(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
        for i in 0..10 {
            let d = compose_dream(&day, &format!("entry_{i}"), &[]);
            append_dream(dir.path(), &d).unwrap();
        }
        let hits = seed_with_dreams(dir.path(), "entry", 7, 3);
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn dream_serde_roundtrip_preserves_every_field() {
        let d = Dream {
            composed_ts_unix: 1234,
            day: "2026-05-22".into(),
            theme_label: "label".into(),
            summary: "narrative".into(),
            event_ids: vec![1, 2, 3],
            tags: vec!["alpha".into(), "beta".into()],
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: Dream = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}
