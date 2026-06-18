//! OP-02 — hindsight session compression.
//!
//! Ported in spirit from `oh-my-pi` (MIT). Every chat session
//! ends with a "what just happened" compressed summary the
//! operator's next session can recall in one read instead of
//! grepping the full transcript.
//!
//! ## Pipeline
//!
//! 1. Session emits N message turns (operator-side + agent-side).
//! 2. On `Stop` signal (Ctrl+C / `/quit`), the pipeline collects
//!    every turn since the last session-open marker.
//! 3. [`compress_session`] runs a deterministic frequency pass
//!    over the turns + extracts:
//!      - top 5 topics (same scoring as `reflection::score_topics`)
//!      - opening + closing utterance (first + last
//!        operator-typed message)
//!      - turn count + duration window
//!      - one-line summary the next session's seed prompt
//!        consumes
//! 4. Result writes to `~/.neoth/hindsight/<session-id>.json`
//!    via atomic `.tmp` + rename, same pattern as dreams /
//!    reflections / proposals.
//!
//! ## Why deterministic, not LLM
//!
//! Same rationale as `reflection::build_reflection_item`: session-
//! end runs unattended + may fire when the operator's cloud
//! quota is exhausted. A deterministic pass is free, instant +
//! 90%-good. The 10% case where it picks the wrong topic still
//! beats no compression; v0.9 may upgrade to an LLM-driven
//! summariser behind a freedom.yaml flag.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One operator-or-agent turn the compressor consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTurn {
    /// Wall-clock unix seconds when the turn happened.
    pub ts_unix: i64,
    /// `"operator"` or `"agent"`. Pinned snake_case wire form.
    pub role: TurnRole,
    /// Verbatim utterance.
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnRole {
    Operator,
    Agent,
}

impl TurnRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Agent => "agent",
        }
    }
}

/// Compressed session card. Persisted as JSON, recall-path reads
/// it back in one shot to seed the next session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HindsightCard {
    pub session_id: String,
    pub started_at_unix: i64,
    pub ended_at_unix: i64,
    pub turn_count: usize,
    pub operator_turn_count: usize,
    pub agent_turn_count: usize,
    /// Top-5 topics ranked by token-frequency over the operator-
    /// side turns. Same scoring as `reflection::score_topics`.
    pub top_topics: Vec<String>,
    /// First operator utterance (opening of the session).
    pub opening_utterance: String,
    /// Last operator utterance (closing of the session).
    pub closing_utterance: String,
    /// One-line summary the next session's seed prompt consumes.
    /// Pinned shape: `"<turn_count> turns over <minutes> min on
    /// <topics-comma-separated>"`.
    pub one_line_summary: String,
    /// GOLD-ADOPT-21 — optional LLM-generated session title. Populated at
    /// session-card write when `memory.name_sessions` is on (via the cheap
    /// `inference.utility_provider`). `None` = deterministic `one_line_summary`
    /// is used. Display surfaces (`next_session_seed_banner`) prefer this when set.
    #[serde(default)]
    pub display_name: Option<String>,
}

impl HindsightCard {
    /// Duration in seconds. Negative duration → 0 (clock skew
    /// guard).
    pub fn duration_seconds(&self) -> i64 {
        (self.ended_at_unix - self.started_at_unix).max(0)
    }

    pub fn duration_minutes(&self) -> i64 {
        self.duration_seconds() / 60
    }
}

/// Compression pass — pure-fn over the turn list. Empty turns
/// produce an empty-shape card with the session id and zero
/// counts so the recall path still finds something.
pub fn compress_session(session_id: impl Into<String>, turns: &[SessionTurn]) -> HindsightCard {
    let session_id = session_id.into();
    if turns.is_empty() {
        return HindsightCard {
            session_id,
            started_at_unix: 0,
            ended_at_unix: 0,
            turn_count: 0,
            operator_turn_count: 0,
            agent_turn_count: 0,
            top_topics: Vec::new(),
            opening_utterance: String::new(),
            closing_utterance: String::new(),
            one_line_summary: "empty session".to_string(),
            display_name: None,
        };
    }

    let started_at_unix = turns.iter().map(|t| t.ts_unix).min().unwrap_or(0);
    let ended_at_unix = turns.iter().map(|t| t.ts_unix).max().unwrap_or(0);
    let operator_turn_count = turns
        .iter()
        .filter(|t| t.role == TurnRole::Operator)
        .count();
    let agent_turn_count = turns.iter().filter(|t| t.role == TurnRole::Agent).count();

    let operator_texts: Vec<String> = turns
        .iter()
        .filter(|t| t.role == TurnRole::Operator)
        .map(|t| t.text.clone())
        .collect();
    let top_topics = score_topics(&operator_texts, 5);

    let opening_utterance = operator_texts.first().cloned().unwrap_or_default();
    let closing_utterance = operator_texts.last().cloned().unwrap_or_default();

    let duration_min = ((ended_at_unix - started_at_unix).max(0) / 60).max(0);
    let topics_phrase = if top_topics.is_empty() {
        "no clear topic".to_string()
    } else {
        top_topics.join(", ")
    };
    let one_line_summary = format!(
        "{} turns over {} min on {}",
        turns.len(),
        duration_min,
        topics_phrase,
    );

    HindsightCard {
        session_id,
        started_at_unix,
        ended_at_unix,
        turn_count: turns.len(),
        operator_turn_count,
        agent_turn_count,
        top_topics,
        opening_utterance,
        closing_utterance,
        one_line_summary,
        display_name: None,
    }
}

/// Top-N topic extractor — same algorithm as the existing
/// `reflection::score_topics` but pinned here so OP-02 stays
/// self-contained (the reflection module's STOPWORDS list is
/// crate-private). DE + EN stopwords + 4-char minimum + drop
/// pure-digit tokens < 5 chars.
fn score_topics(texts: &[String], n: usize) -> Vec<String> {
    let stopwords: HashSet<&str> = STOPWORDS.iter().copied().collect();
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
            if lower.chars().all(|c| c.is_ascii_digit()) && lower.chars().count() < 5 {
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

const STOPWORDS: &[&str] = &[
    // German function words
    "der", "die", "das", "den", "dem", "des", "ein", "eine", "einer", "einen", "einem", "eines",
    "und", "oder", "aber", "doch", "weil", "wenn", "dann", "ja", "nein", "nicht", "kein", "keine",
    "ich", "you", "er", "sie", "wir", "ihr", "mich", "dich", "uns", "euch", "mein", "dein", "ist",
    "war", "sind", "waren", "hat", "habe", "haben", "wird", "werden", "kann", "können", "auf",
    "in", "im", "an", "am", "zu", "zum", "zur", "mit", "von", "vom", "für", "über", "wie", "was",
    "wer", "wo", "warum", "wann", // English
    "the", "and", "or", "but", "of", "in", "on", "to", "for", "with", "is", "it", "this", "that",
    "what", "when", "where", "why", "have", "has", "had", "do", "does", "did", "be", "been",
    "being", "are", "was", "were", "will", "would", "should", "could", "can", "may", "might", "as",
    "at", "by", "from", // NEOTH chat noise
    "neoth", "chat", "okay", "yes", "hmm", "danke", "thanks", "thank",
];

// ── persistence ───────────────────────────────────────────────────────────

/// Directory under `home` that holds hindsight cards.
pub fn hindsight_dir(home: &Path) -> PathBuf {
    home.join("hindsight")
}

pub fn card_path(home: &Path, session_id: &str) -> PathBuf {
    hindsight_dir(home).join(format!("{session_id}.json"))
}

/// Save the card atomically — `.tmp` + rename, Windows-safe.
/// Overwrites existing (operator may re-compress a session
/// post-hoc with corrected turn data).
pub fn save_card(home: &Path, card: &HindsightCard) -> std::io::Result<PathBuf> {
    if !is_safe_session_id(&card.session_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsafe session_id {:?}", card.session_id),
        ));
    }
    fs::create_dir_all(hindsight_dir(home))?;
    let final_path = card_path(home, &card.session_id);
    let tmp_path = final_path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(card).map_err(std::io::Error::other)?;
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(&body)?;
        f.flush()?;
    }
    if final_path.exists() {
        fs::remove_file(&final_path)?;
    }
    fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// GOLD-ADOPT-21 — set the LLM-generated `display_name` on an already-written
/// card + persist it. Load → patch → atomic re-save (reuses [`save_card`]).
/// Best-effort: a missing card or empty name is a no-op `Ok(false)` (the
/// deterministic `one_line_summary` stands); `Ok(true)` when the name landed.
pub fn update_display_name(home: &Path, session_id: &str, name: &str) -> std::io::Result<bool> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    let Some(mut card) = load_card(home, session_id) else {
        return Ok(false);
    };
    card.display_name = Some(trimmed.to_string());
    save_card(home, &card)?;
    Ok(true)
}

/// Load a card by session id. Returns None for missing or
/// malformed files.
pub fn load_card(home: &Path, session_id: &str) -> Option<HindsightCard> {
    let body = fs::read_to_string(card_path(home, session_id)).ok()?;
    serde_json::from_str(&body).ok()
}

/// List every card under `hindsight_dir`. Malformed files skip.
/// Sorted by `ended_at_unix` descending (newest first) so the
/// next-session seed reads the most recent N cards.
pub fn list_cards(home: &Path) -> Vec<HindsightCard> {
    let dir = hindsight_dir(home);
    let Ok(read) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<HindsightCard> = read
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .filter_map(|b| serde_json::from_str::<HindsightCard>(&b).ok())
        .collect();
    out.sort_by_key(|c| std::cmp::Reverse(c.ended_at_unix));
    out
}

fn is_safe_session_id(id: &str) -> bool {
    if id.is_empty() || id == "." || id == ".." {
        return false;
    }
    !id.chars()
        .any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control())
}

// ── OP-02 runtime helpers: session-end + next-session seed ───────────────────

/// Build a deterministic session-id from the operator's prompt
/// content + timestamp. xxh3 over the prompt bytes keeps the id
/// short + greppable while staying unique per session.
pub fn session_id_for(ts_unix: i64, prompt: &str) -> String {
    let h = xxhash_rust::xxh3::xxh3_64(prompt.as_bytes());
    format!("chat-{ts_unix}-{h:016x}")
}

/// One-call session-end hook for `neoth chat`: builds the 2-turn
/// transcript from the operator's prompt + agent's reply, compresses
/// it, and writes the card under `~/.neoth/hindsight/`. Errors are
/// returned for the caller's best-effort logging — a write failure
/// MUST NOT bubble up + abort the chat exit path.
pub fn save_session_card(
    home: &Path,
    ts_unix: i64,
    prompt: &str,
    reply: &str,
) -> std::io::Result<PathBuf> {
    // Single chat invocation = single round-trip. We model both
    // halves as one turn each so `compress_session` has something
    // to derive topics + opening / closing utterances from. The
    // operator-side turn always lands first (ts_unix), the agent-
    // side turn lands at +1s so the temporal ordering stays clean
    // even when the reply arrived sub-second after the prompt.
    let turns = vec![
        SessionTurn {
            ts_unix,
            role: TurnRole::Operator,
            text: prompt.to_string(),
        },
        SessionTurn {
            ts_unix: ts_unix + 1,
            role: TurnRole::Agent,
            text: reply.to_string(),
        },
    ];
    let session_id = session_id_for(ts_unix, prompt);
    let card = compress_session(session_id, &turns);
    save_card(home, &card)
}

/// Same as [`save_session_card`] but swallows the error + logs a
/// warning instead. Designed as the final call in the `neoth chat`
/// happy-path exit: hindsight compression is a soft signal, never a
/// hard correctness invariant.
pub fn save_session_card_best_effort(home: &Path, ts_unix: i64, prompt: &str, reply: &str) {
    if let Err(e) = save_session_card(home, ts_unix, prompt, reply) {
        tracing::warn!(error = %e, "hindsight save_session_card failed (non-fatal)");
    }
}

/// Most-recent hindsight card, by `ended_at_unix` desc. Used as
/// the next-session seed: the chat startup path consults this +
/// surfaces the `one_line_summary` as a banner so the next prompt
/// starts with context. Returns None when no cards exist or when
/// every card is malformed.
pub fn latest_card(home: &Path) -> Option<HindsightCard> {
    list_cards(home).into_iter().next()
}

/// Render the next-session seed banner. Empty string when there's
/// no prior card OR the latest card is the same session-id we
/// just generated (avoids "since last time: <our own prompt>"
/// when a chat invocation lands within the same second window).
/// The check against `current_session_id` guards the same-second
/// edge case in the unit tests.
pub fn next_session_seed_banner(home: &Path, current_session_id: &str) -> String {
    let Some(card) = latest_card(home) else {
        return String::new();
    };
    if card.session_id == current_session_id {
        return String::new();
    }
    if card.turn_count == 0 {
        return String::new();
    }
    // GOLD-ADOPT-21 — prefer the LLM-generated title when present; fall back to
    // the deterministic one-line summary.
    let label = card
        .display_name
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&card.one_line_summary);
    format!("[neoth] last session: {label}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(ts: i64, text: &str) -> SessionTurn {
        SessionTurn {
            ts_unix: ts,
            role: TurnRole::Operator,
            text: text.to_string(),
        }
    }

    fn ag(ts: i64, text: &str) -> SessionTurn {
        SessionTurn {
            ts_unix: ts,
            role: TurnRole::Agent,
            text: text.to_string(),
        }
    }

    // ── enum surface ──────────────────────────────────────────────

    #[test]
    fn turn_role_as_str_pinned() {
        assert_eq!(TurnRole::Operator.as_str(), "operator");
        assert_eq!(TurnRole::Agent.as_str(), "agent");
    }

    #[test]
    fn turn_role_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&TurnRole::Operator).unwrap(),
            "\"operator\"",
        );
    }

    // ── compress empty ────────────────────────────────────────────

    #[test]
    fn empty_session_returns_zero_card_with_session_id() {
        let card = compress_session("s1", &[]);
        assert_eq!(card.session_id, "s1");
        assert_eq!(card.turn_count, 0);
        assert_eq!(card.operator_turn_count, 0);
        assert_eq!(card.agent_turn_count, 0);
        assert!(card.top_topics.is_empty());
        assert!(card.opening_utterance.is_empty());
        assert!(card.closing_utterance.is_empty());
        assert!(card.one_line_summary.contains("empty"));
    }

    // ── compress with real turns ──────────────────────────────────

    #[test]
    fn compress_extracts_top_topics_from_operator_side_only() {
        // Agent talks about quantum physics; operator talks about
        // rust + memory. Top topics MUST be operator-side only.
        let turns = vec![
            op(100, "I want to refactor the rust memory module"),
            ag(110, "quantum quantum quantum entanglement quantum"),
            op(120, "the memory tier system needs rework"),
            op(130, "specifically the rust memory hippocampus path"),
        ];
        let card = compress_session("s1", &turns);
        assert!(card.top_topics.contains(&"memory".to_string()));
        assert!(card.top_topics.contains(&"rust".to_string()));
        assert!(!card.top_topics.contains(&"quantum".to_string()));
    }

    #[test]
    fn compress_counts_operator_and_agent_separately() {
        let turns = vec![
            op(100, "hello"),
            ag(101, "hi"),
            op(102, "question"),
            ag(103, "answer"),
            ag(104, "more"),
        ];
        let card = compress_session("s1", &turns);
        assert_eq!(card.turn_count, 5);
        assert_eq!(card.operator_turn_count, 2);
        assert_eq!(card.agent_turn_count, 3);
    }

    #[test]
    fn compress_started_and_ended_at_use_min_max_ts() {
        let turns = vec![op(300, "later"), op(100, "first"), op(200, "middle")];
        let card = compress_session("s1", &turns);
        assert_eq!(card.started_at_unix, 100);
        assert_eq!(card.ended_at_unix, 300);
    }

    #[test]
    fn compress_opening_and_closing_use_operator_first_and_last() {
        let turns = vec![
            op(100, "first operator"),
            ag(110, "agent reply"),
            op(120, "middle operator"),
            ag(130, "agent again"),
            op(140, "last operator"),
        ];
        let card = compress_session("s1", &turns);
        assert_eq!(card.opening_utterance, "first operator");
        assert_eq!(card.closing_utterance, "last operator");
    }

    #[test]
    fn compress_one_line_summary_shape() {
        let turns = vec![
            op(0, "rust memory refactor session"),
            op(3600, "rust memory looks great"),
        ];
        let card = compress_session("s1", &turns);
        // 2 turns over 60 min
        assert!(card.one_line_summary.contains("2 turns"));
        assert!(card.one_line_summary.contains("60 min"));
    }

    #[test]
    fn compress_one_line_summary_no_topic_fallback() {
        let turns = vec![op(0, "hi"), op(60, "ok")];
        let card = compress_session("s1", &turns);
        // No tokens ≥4 chars + non-stopword → no clear topic.
        assert!(card.one_line_summary.contains("no clear topic"));
    }

    #[test]
    fn duration_helpers_handle_clock_skew_safely() {
        let card = HindsightCard {
            session_id: "s".into(),
            started_at_unix: 200,
            ended_at_unix: 100, // reversed (skew)
            turn_count: 0,
            operator_turn_count: 0,
            agent_turn_count: 0,
            top_topics: Vec::new(),
            opening_utterance: String::new(),
            closing_utterance: String::new(),
            one_line_summary: "x".into(),
            display_name: None,
        };
        assert_eq!(card.duration_seconds(), 0);
        assert_eq!(card.duration_minutes(), 0);
    }

    #[test]
    fn duration_minutes_floors_correctly() {
        let card = HindsightCard {
            session_id: "s".into(),
            started_at_unix: 0,
            ended_at_unix: 119, // < 2 min
            turn_count: 0,
            operator_turn_count: 0,
            agent_turn_count: 0,
            top_topics: Vec::new(),
            opening_utterance: String::new(),
            closing_utterance: String::new(),
            one_line_summary: "x".into(),
            display_name: None,
        };
        assert_eq!(card.duration_minutes(), 1);
    }

    // ── persistence ───────────────────────────────────────────────

    #[test]
    fn save_load_roundtrip() {
        let home = tempfile::tempdir().unwrap();
        let card = compress_session("session-001", &[op(100, "rust memory refactor session")]);
        save_card(home.path(), &card).unwrap();
        let loaded = load_card(home.path(), &card.session_id).expect("reload");
        assert_eq!(loaded, card);
    }

    #[test]
    fn load_missing_returns_none() {
        let home = tempfile::tempdir().unwrap();
        assert!(load_card(home.path(), "nope").is_none());
    }

    #[test]
    fn save_overwrites_existing_atomically() {
        let home = tempfile::tempdir().unwrap();
        let mut card = compress_session("s1", &[op(100, "first version")]);
        save_card(home.path(), &card).unwrap();
        card.one_line_summary = "new summary".to_string();
        save_card(home.path(), &card).unwrap();
        let loaded = load_card(home.path(), "s1").unwrap();
        assert_eq!(loaded.one_line_summary, "new summary");
    }

    #[test]
    fn save_no_tmp_leak() {
        let home = tempfile::tempdir().unwrap();
        let card = compress_session("s1", &[op(0, "x")]);
        save_card(home.path(), &card).unwrap();
        let tmp = hindsight_dir(home.path()).join("s1.json.tmp");
        assert!(!tmp.exists());
    }

    #[test]
    fn save_rejects_unsafe_session_id_with_path_traversal() {
        let home = tempfile::tempdir().unwrap();
        let mut card = compress_session("safe", &[]);
        card.session_id = "../escape".into();
        let err = save_card(home.path(), &card).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn save_rejects_backslash_separator_windows_guard() {
        let home = tempfile::tempdir().unwrap();
        let mut card = compress_session("safe", &[]);
        card.session_id = "evil\\path".into();
        let err = save_card(home.path(), &card).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn save_rejects_empty_session_id() {
        let home = tempfile::tempdir().unwrap();
        let mut card = compress_session("safe", &[]);
        card.session_id = String::new();
        let err = save_card(home.path(), &card).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn list_cards_sorted_by_ended_at_descending() {
        let home = tempfile::tempdir().unwrap();
        let mut a = compress_session("s-100", &[op(100, "first")]);
        a.ended_at_unix = 100;
        let mut b = compress_session("s-300", &[op(300, "third")]);
        b.ended_at_unix = 300;
        let mut c = compress_session("s-200", &[op(200, "second")]);
        c.ended_at_unix = 200;
        save_card(home.path(), &a).unwrap();
        save_card(home.path(), &b).unwrap();
        save_card(home.path(), &c).unwrap();
        let listed = list_cards(home.path());
        assert_eq!(listed.len(), 3);
        // Newest first.
        assert_eq!(listed[0].session_id, "s-300");
        assert_eq!(listed[1].session_id, "s-200");
        assert_eq!(listed[2].session_id, "s-100");
    }

    #[test]
    fn list_cards_missing_dir_returns_empty() {
        let home = tempfile::tempdir().unwrap();
        let listed = list_cards(home.path());
        assert!(listed.is_empty());
    }

    #[test]
    fn list_cards_skips_malformed_files() {
        let home = tempfile::tempdir().unwrap();
        let card = compress_session("good", &[op(0, "x")]);
        save_card(home.path(), &card).unwrap();
        // Drop a malformed file in the hindsight dir.
        std::fs::write(
            hindsight_dir(home.path()).join("bad.json"),
            b"not json at all",
        )
        .unwrap();
        let listed = list_cards(home.path());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].session_id, "good");
    }

    // ── e2e ──────────────────────────────────────────────────────

    #[test]
    fn compress_then_save_then_load_roundtrip_preserves_every_field() {
        let home = tempfile::tempdir().unwrap();
        let turns = vec![
            op(100, "rust memory hippocampus refactor"),
            ag(110, "ok let's plan"),
            op(120, "memory tiers also need work"),
            ag(130, "got it"),
            op(140, "rust hippocampus done"),
        ];
        let card = compress_session("session-2026-05-26-001", &turns);
        save_card(home.path(), &card).unwrap();
        let loaded = load_card(home.path(), &card.session_id).unwrap();
        assert_eq!(loaded, card);
        // Sanity-check on the actual content.
        assert_eq!(loaded.turn_count, 5);
        assert_eq!(loaded.operator_turn_count, 3);
        assert_eq!(loaded.opening_utterance, "rust memory hippocampus refactor");
        assert_eq!(loaded.closing_utterance, "rust hippocampus done");
    }

    // ── OP-02 session-end + next-session seed (Session 25) ───────

    #[test]
    fn session_id_for_is_deterministic_per_ts_and_prompt() {
        let a = session_id_for(100, "hello world");
        let b = session_id_for(100, "hello world");
        let c = session_id_for(101, "hello world");
        let d = session_id_for(100, "hello there");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert!(a.starts_with("chat-100-"));
        assert_eq!(a.len(), "chat-100-".len() + 16);
    }

    #[test]
    fn save_session_card_writes_card_with_2_turns() {
        let home = tempfile::tempdir().unwrap();
        let path = save_session_card(
            home.path(),
            1_700_000_000,
            "rust memory question",
            "agent reply",
        )
        .unwrap();
        assert!(path.exists());
        let id = session_id_for(1_700_000_000, "rust memory question");
        let loaded = load_card(home.path(), &id).unwrap();
        assert_eq!(loaded.turn_count, 2);
        assert_eq!(loaded.operator_turn_count, 1);
        assert_eq!(loaded.agent_turn_count, 1);
        assert_eq!(loaded.opening_utterance, "rust memory question");
        assert_eq!(loaded.closing_utterance, "rust memory question");
    }

    #[test]
    fn save_session_card_best_effort_does_not_panic_on_missing_parent() {
        // Pass a clearly-invalid path: a file (not a dir). The
        // hindsight_dir creation will fail on Linux because we
        // can't create_dir_all under a file. The helper must
        // swallow + log instead of panicking.
        let home = tempfile::tempdir().unwrap();
        let bogus_file = home.path().join("oops.txt");
        std::fs::write(&bogus_file, b"i am a file").unwrap();
        // Use the file path AS the home dir — create_dir_all under
        // it returns AlreadyExists-as-file (Unix) / NotADirectory.
        // Either way the helper must not panic.
        save_session_card_best_effort(&bogus_file, 100, "p", "r");
    }

    #[test]
    fn latest_card_returns_most_recent() {
        let home = tempfile::tempdir().unwrap();
        save_session_card(home.path(), 100, "older prompt", "older reply").unwrap();
        save_session_card(home.path(), 200, "newer prompt", "newer reply").unwrap();
        let latest = latest_card(home.path()).unwrap();
        assert_eq!(latest.opening_utterance, "newer prompt");
    }

    #[test]
    fn latest_card_returns_none_for_empty_dir() {
        let home = tempfile::tempdir().unwrap();
        assert!(latest_card(home.path()).is_none());
    }

    #[test]
    fn next_session_seed_banner_renders_one_line_summary() {
        let home = tempfile::tempdir().unwrap();
        save_session_card(home.path(), 100, "rust memory refactor", "ok").unwrap();
        let banner = next_session_seed_banner(home.path(), "completely-different-session");
        assert!(banner.starts_with("[neoth] last session:"));
        // The compressor's `one_line_summary` is included verbatim.
        assert!(banner.contains("turns over"));
    }

    #[test]
    fn next_session_seed_banner_empty_when_no_prior_card() {
        let home = tempfile::tempdir().unwrap();
        let banner = next_session_seed_banner(home.path(), "any-session");
        assert!(banner.is_empty());
    }

    #[test]
    fn next_session_seed_banner_empty_when_current_session_id_matches_latest() {
        // Same-second edge case: the chat just wrote its own card,
        // then re-reads on banner-time. Should suppress the
        // "since last time: <my own prompt>" loop.
        let home = tempfile::tempdir().unwrap();
        save_session_card(home.path(), 100, "rust memory", "reply").unwrap();
        let current_id = session_id_for(100, "rust memory");
        let banner = next_session_seed_banner(home.path(), &current_id);
        assert!(banner.is_empty());
    }

    // ── GOLD-ADOPT-21 LLM session naming ────────────────────────────

    #[test]
    fn update_display_name_sets_persists_and_handles_misses() {
        let home = tempfile::tempdir().unwrap();
        save_session_card(home.path(), 100, "build a parser", "ok").unwrap();
        let id = session_id_for(100, "build a parser");
        // Set + persist.
        assert!(update_display_name(home.path(), &id, "Parser Build").unwrap());
        assert_eq!(
            load_card(home.path(), &id).unwrap().display_name.as_deref(),
            Some("Parser Build")
        );
        // Missing card → Ok(false), no panic.
        assert!(!update_display_name(home.path(), "chat-999-deadbeefdeadbeef", "x").unwrap());
        // Empty / whitespace name → Ok(false), leaves the existing name intact.
        assert!(!update_display_name(home.path(), &id, "   ").unwrap());
        assert_eq!(
            load_card(home.path(), &id).unwrap().display_name.as_deref(),
            Some("Parser Build"),
            "an empty update must not clobber an existing display_name"
        );
    }

    #[test]
    fn banner_prefers_display_name_over_summary() {
        let home = tempfile::tempdir().unwrap();
        save_session_card(home.path(), 200, "topic alpha", "reply").unwrap();
        let id = session_id_for(200, "topic alpha");
        update_display_name(home.path(), &id, "Alpha Deep Dive").unwrap();
        let banner = next_session_seed_banner(home.path(), "some-other-current-id");
        assert!(banner.contains("Alpha Deep Dive"), "banner: {banner}");
        assert!(
            !banner.contains("turns over"),
            "the deterministic summary must be superseded: {banner}"
        );
    }

    #[test]
    fn banner_falls_back_to_summary_when_no_display_name() {
        let home = tempfile::tempdir().unwrap();
        save_session_card(home.path(), 300, "topic beta", "reply").unwrap();
        let banner = next_session_seed_banner(home.path(), "some-other-current-id");
        assert!(
            banner.contains("turns over"),
            "no display_name → summary: {banner}"
        );
    }
}
