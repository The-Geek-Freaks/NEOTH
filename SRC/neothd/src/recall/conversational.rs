//! M-09b (Session 24) — conversational recall wrapper.
//!
//! A4 F3-1 pinned the gap: operators ask "weisst du noch als wir
//! über X geredet haben?" (or "do you remember when I said X?") and
//! NEOTH would route the whole question through the LLM — burning
//! tokens to ask a cloud model to remember something the local
//! `idx_episode` already knows verbatim. M-09b intercepts that
//! pattern BEFORE the chat dispatch falls through to the provider
//! call and answers from local recall.
//!
//! ## Two pure helpers
//!
//! - [`detect_recall_intent`] takes the operator's prompt and
//!   returns `Some(RecallQuery { topic, language })` when it
//!   matches a German or English recall pattern; `None` otherwise.
//!   No false-positive on a normal "I want to remember to..." TODO
//!   — those don't trigger the intent matcher.
//! - [`format_recall_reply`] takes a list of [`EpisodeHit`]s and
//!   renders the canonical operator-facing reply:
//!     "Ja — am 2026-05-25 hast du gesagt: '...'"
//!     "Yes — on 2026-05-25 you said: '...'"
//!   Empty hits produce the "Nothing found in memory for X" line
//!   so the operator knows the recall ran but came back empty.
//!
//! Chat-dispatch integration (call detect_recall_intent before
//! firing the provider) is the follow-up; this commit ships the
//! primitives + tests so the wiring is a 3-line change.

use chrono::{DateTime, Utc};

use crate::memory::views::EpisodeHit;

/// Result of [`detect_recall_intent`]. Carries the extracted topic
/// + the detected language so the formatter renders in the same
/// language the operator typed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecallQuery {
    pub topic: String,
    pub language: RecallLanguage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecallLanguage {
    German,
    English,
}

/// German recall openers — substrings that must appear at the
/// START of the prompt (case-insensitive, leading whitespace
/// stripped). Each entry pairs the opener with the suffix to strip
/// from the rest of the prompt before extracting the topic.
const GERMAN_OPENERS: &[&str] = &[
    "weisst du noch",
    "weißt du noch",
    "weisst du, als",
    "weißt du, als",
    "erinnerst du dich",
    "erinnere dich",
    "kannst du dich erinnern",
    "was hab ich",
    "was habe ich",
    // GOLD-WIRE-02 review: REMOVED idiomatic-filler / diagnostic openers that
    // were load-bearing false positives once the detector gates the chat path:
    //   "weißt du was" / "weisst du was" — "you know what, [any request]"
    //   "was haben wir"                  — "what do we have [bug/options/…]"
    //   "wann habe ich"                  — also "when is my next meeting"
    // Genuine recall is still covered by "weißt du noch" / "erinnerst du dich".
];

/// English recall openers — same shape as the German list.
const ENGLISH_OPENERS: &[&str] = &[
    "do you remember",
    "remember when",
    // GOLD-WIRE-02 review: REMOVED "remember that" — it is a context-setter
    // before an imperative ("remember that the build is broken, fix it"), not
    // a recall query. "remember when" / "do you remember" cover genuine recall.
    "can you recall",
    "what did i",
    "when did i",
    "have we talked",
    "did we discuss",
];

/// Detect a conversational-recall intent. Returns `None` when the
/// prompt doesn't match any opener — chat dispatch then falls
/// through to the regular LLM path unchanged.
///
/// Topic extraction is intentionally minimal: strip the opener,
/// strip filler particles ("about", "über", "als", "ob", "wenn",
/// the trailing question mark), trim. The rest is the topic. A
/// future v0.9 enhancement could route through a NER pass; for
/// v0.4 the dumb strip is good enough for the 80% case.
pub fn detect_recall_intent(prompt: &str) -> Option<RecallQuery> {
    let lower = prompt.trim().to_lowercase();
    if lower.is_empty() {
        return None;
    }
    for opener in GERMAN_OPENERS {
        if let Some(rest) = lower.strip_prefix(opener) {
            let topic = clean_topic_de(rest);
            if !topic.is_empty() && !topic_is_compound(&topic) {
                return Some(RecallQuery {
                    topic,
                    language: RecallLanguage::German,
                });
            }
        }
    }
    for opener in ENGLISH_OPENERS {
        if let Some(rest) = lower.strip_prefix(opener) {
            let topic = clean_topic_en(rest);
            if !topic.is_empty() && !topic_is_compound(&topic) {
                return Some(RecallQuery {
                    topic,
                    language: RecallLanguage::English,
                });
            }
        }
    }
    None
}

/// A cleaned topic that still carries mid-string sentence punctuation (a `?`
/// or `!` — `clean_topic_*` already stripped any TRAILING one) is almost
/// always a COMPOUND prompt where the recall opener was a rhetorical lead-in
/// ("do you remember the API for X? write me code"). Reject it (GOLD-WIRE-02
/// review) so the turn falls through to the LLM instead of being silently
/// answered from memory.
fn topic_is_compound(topic: &str) -> bool {
    topic.contains('?') || topic.contains('!')
}

/// Like [`str::strip_prefix`] but only succeeds when the match terminates at a
/// WORD BOUNDARY — the remainder is empty or starts with a separator. GR-057:
/// the raw `strip_prefix` in the leading-particle loops corrupted any topic that
/// merely STARTS with a particle substring (`"we"` ate `"weather"` → `"ather"`;
/// `"ich"` / `"als"` ate German words), because `.trim()` after the strip only
/// removes whitespace, never checking the match ended on a boundary.
fn strip_prefix_word_boundary<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = s.strip_prefix(prefix)?;
    if rest.is_empty() || rest.starts_with([' ', ',', ':', ';', '?', '!', '.']) {
        Some(rest)
    } else {
        None
    }
}

fn clean_topic_de(s: &str) -> String {
    let trimmed = s.trim_start_matches([',', ' ', ':']).trim_end_matches('?');
    let mut out = trimmed.trim().to_string();
    // Strip leading filler particles, longest first so "als wir über"
    // wins before "als". Loop until nothing matches so chains like
    // "als wir über" + "über" both peel cleanly.
    let leading = [
        "als wir über",
        "als wir uber",
        "als ich",
        "wir über",
        "wir uber",
        "was über",
        "ob ich",
        "wann ich",
        "wenn ich",
        "über",
        "uber",
        "ich",
        "wir",
        "als",
        "ob",
        "wenn",
    ];
    loop {
        let before = out.clone();
        for particle in leading {
            // GR-057 — word-boundary guard so a particle never eats into a
            // longer word it's a prefix of ("we" must not corrupt "weather").
            if let Some(stripped) = strip_prefix_word_boundary(&out, particle) {
                out = stripped.trim().to_string();
            }
        }
        if out == before {
            break;
        }
    }
    // Strip trailing conversational tails so "rust geredet haben"
    // → "rust" and "die wal gesagt habe" → "die wal".
    let trailing = [
        "geredet haben",
        "geredet hatten",
        "gesagt haben",
        "gesagt habe",
        "gesagt hatte",
        "gesprochen haben",
        "gesprochen",
        "geredet",
        "gemeint hatte",
        "gemeint habe",
        "gemeint",
        "erwähnt habe",
        "erwähnt",
        "gesagt",
        "haben",
    ];
    loop {
        let before = out.clone();
        for tail in trailing {
            if let Some(stripped) = out.strip_suffix(tail) {
                out = stripped.trim().to_string();
            }
        }
        if out == before {
            break;
        }
    }
    out.trim_end_matches([' ', ',', '?', '.', '!']).to_string()
}

fn clean_topic_en(s: &str) -> String {
    let trimmed = s.trim_start_matches([',', ' ', ':']).trim_end_matches('?');
    let mut out = trimmed.trim().to_string();
    // Longest / most-specific first so "when we talked about" peels as
    // "when we" then "talked about" rather than leaving a tail.
    let leading = [
        "talked about",
        "discussed",
        "when i said",
        "when we said",
        "when we",
        "that we",
        "that i",
        "i said",
        "we said",
        "said",
        "about",
        "i",
        "we",
        "that",
        "when",
    ];
    // COR-32: fixpoint loop (mirror clean_topic_de) — a single pass over
    // the list can't peel chained openers, because the `for` has already
    // moved past an earlier particle ("talked about") by the time a later
    // one ("when we") strips and exposes it. Loop until nothing matches.
    loop {
        let before = out.clone();
        for particle in leading {
            // GR-057 — word-boundary guard so a particle never eats into a
            // longer word it's a prefix of ("we" must not corrupt "weather").
            if let Some(stripped) = strip_prefix_word_boundary(&out, particle) {
                out = stripped.trim().to_string();
            }
        }
        if out == before {
            break;
        }
    }
    out.trim_end_matches([' ', ',', '?', '.', '!']).to_string()
}

/// Render a list of recall hits into the operator-facing reply.
/// Language picks German or English templates. Hits are formatted
/// chronologically (newest first matches the recall sort) and
/// quoted verbatim so the operator sees what they actually said.
pub fn format_recall_reply(hits: &[EpisodeHit], language: RecallLanguage, topic: &str) -> String {
    if hits.is_empty() {
        return match language {
            RecallLanguage::German => {
                format!("Ich finde keine Erinnerung an '{topic}' im lokalen Gedächtnis.")
            }
            RecallLanguage::English => {
                format!("Nothing found in local memory for '{topic}'.")
            }
        };
    }
    let (intro, on_word, said_word) = match language {
        RecallLanguage::German => ("Ja", "am", "hast du gesagt"),
        RecallLanguage::English => ("Yes", "on", "you said"),
    };
    let mut out = String::new();
    out.push_str(intro);
    out.push_str(" — ");
    for (idx, hit) in hits.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        let date = format_ts_as_date(hit.ts_ns);
        out.push_str(&format!(
            "{on_word} {date} {said_word}: '{text}'",
            text = quote_safe(&hit.text),
        ));
    }
    out
}

fn format_ts_as_date(ts_ns: i64) -> String {
    let secs = ts_ns / 1_000_000_000;
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "(unknown date)".into())
}

fn quote_safe(s: &str) -> String {
    // The wrapping is `'...'`. An inner single-quote would close
    // the wrapper visually, so swap inner singles to backtick. Any
    // embedded double-quote is fine (it doesn't interact with the
    // wrapper).
    s.replace('\'', "`")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(ts_ns: i64, text: &str) -> EpisodeHit {
        EpisodeHit {
            event_id: 1,
            event_type: 1,
            ts_ns,
            text: text.to_string(),
            text_hash: "h".into(),
            channel: None,
            sender_id: None,
            operator_id: None,
            tier: "hot".into(),
            importance: None,
            access_count: 0,
            trust: 1,
        }
    }

    // ── detect_recall_intent: positive matches ────────────────────────

    #[test]
    fn detects_german_recall_intent_with_canonical_opener() {
        let r = detect_recall_intent("Weisst du noch als wir über Rust geredet haben?").unwrap();
        assert_eq!(r.language, RecallLanguage::German);
        assert_eq!(r.topic, "rust");
    }

    #[test]
    fn detects_german_recall_intent_with_umlaut_opener() {
        let r = detect_recall_intent("Weißt du noch als wir über Memory geredet haben?").unwrap();
        assert_eq!(r.language, RecallLanguage::German);
        assert_eq!(r.topic, "memory");
    }

    #[test]
    fn detects_german_was_hab_ich_pattern() {
        let r = detect_recall_intent("Was hab ich gestern gesagt über die WAL?").unwrap();
        assert_eq!(r.language, RecallLanguage::German);
        // Topic survives after stripping particles. Exact string is
        // implementation-defined but must mention "wal".
        assert!(r.topic.contains("wal"), "got {:?}", r.topic);
    }

    #[test]
    fn detects_english_do_you_remember_pattern() {
        let r = detect_recall_intent("Do you remember when I said Rust is great?").unwrap();
        assert_eq!(r.language, RecallLanguage::English);
        assert!(r.topic.contains("rust"), "got {:?}", r.topic);
    }

    #[test]
    fn detects_english_remember_when_pattern() {
        let r = detect_recall_intent("Remember when we discussed memory tiers?").unwrap();
        assert_eq!(r.language, RecallLanguage::English);
        assert!(r.topic.contains("memory"), "got {:?}", r.topic);
    }

    #[test]
    fn detects_english_can_you_recall_pattern() {
        let r = detect_recall_intent("Can you recall about my preferences?").unwrap();
        assert_eq!(r.language, RecallLanguage::English);
        assert!(r.topic.contains("preferences"), "got {:?}", r.topic);
    }

    #[test]
    fn detect_strips_trailing_question_mark_and_punctuation() {
        let r = detect_recall_intent("Do you remember when I said rust?!").unwrap();
        // Must not contain a trailing `?` / `!`.
        assert!(!r.topic.ends_with('?'));
        assert!(!r.topic.ends_with('!'));
    }

    #[test]
    fn clean_topic_en_peels_chained_openers_via_fixpoint() {
        // COR-32: a chained opener must strip FULLY. The old single pass
        // left "talked about rust" because the `for` had already moved past
        // "talked about" by the time "when we" peeled and exposed it.
        assert_eq!(clean_topic_en("when we talked about rust"), "rust");
        assert_eq!(
            clean_topic_en("that we discussed memory tiers"),
            "memory tiers"
        );
        // Single-particle cases still behave (no over-strip / no infinite loop).
        assert_eq!(clean_topic_en("when i said rust"), "rust");
        assert_eq!(clean_topic_en("about caching"), "caching");
    }

    #[test]
    fn clean_topic_en_does_not_corrupt_word_starting_with_particle_gr057() {
        // GR-057 — a particle must NOT eat the leading chars of a longer word
        // it's merely a prefix of: "we" ⊀ "weather", "i" ⊀ "ideas".
        assert_eq!(
            clean_topic_en("when i said weather was nice"),
            "weather was nice"
        );
        assert_eq!(clean_topic_en("about ideas"), "ideas");
    }

    #[test]
    fn clean_topic_de_does_not_corrupt_word_starting_with_particle_gr057() {
        // GR-057 — "wir" must not corrupt "wirklich" (prefix without a boundary).
        assert_eq!(
            clean_topic_de("über wirklich wichtiges"),
            "wirklich wichtiges"
        );
    }

    #[test]
    fn detects_english_chained_opener_peels_to_bare_topic() {
        // End-to-end: opener + chained particles → bare topic. Pre-COR-32
        // this yielded "talked about rust".
        let r = detect_recall_intent("Do you remember when we talked about rust?").unwrap();
        assert_eq!(r.language, RecallLanguage::English);
        assert_eq!(
            r.topic, "rust",
            "chained opener must peel fully, got {:?}",
            r.topic
        );
    }

    #[test]
    fn detect_is_case_insensitive() {
        let lower = detect_recall_intent("do you remember when i said x?").unwrap();
        let upper = detect_recall_intent("DO YOU REMEMBER WHEN I SAID X?").unwrap();
        let mixed = detect_recall_intent("Do You Remember When I Said X?").unwrap();
        assert_eq!(lower, upper);
        assert_eq!(lower, mixed);
    }

    // ── detect_recall_intent: negative cases (false-positive guard) ───

    #[test]
    fn no_intent_when_prompt_is_a_normal_todo() {
        // "I want to remember to..." is a TODO request, NOT a recall.
        // Detector must not fire — the LLM should handle the TODO.
        assert!(detect_recall_intent("I want to remember to buy milk").is_none());
        assert!(detect_recall_intent("remind me later about lunch").is_none());
        assert!(detect_recall_intent("write down that the meeting moved").is_none());
    }

    #[test]
    fn no_intent_when_prompt_is_empty_or_whitespace() {
        assert!(detect_recall_intent("").is_none());
        assert!(detect_recall_intent("   ").is_none());
        assert!(detect_recall_intent("\n\t  ").is_none());
    }

    #[test]
    fn no_intent_when_prompt_is_a_regular_question() {
        // Normal chat — must fall through to the LLM.
        assert!(detect_recall_intent("What is the capital of France?").is_none());
        assert!(detect_recall_intent("Wie spät ist es?").is_none());
        assert!(detect_recall_intent("Schreib mir eine E-Mail").is_none());
    }

    #[test]
    fn no_intent_when_opener_matches_but_topic_is_empty() {
        // "Do you remember?" with no topic → no recall intent.
        // Operator probably meant a general question, not a search.
        assert!(detect_recall_intent("Do you remember?").is_none());
        assert!(detect_recall_intent("weißt du noch?").is_none());
    }

    #[test]
    fn no_intent_on_idiomatic_filler_and_compound_prompts() {
        // GOLD-WIRE-02 adversarial review: once the detector gates the chat
        // path, these NORMAL prompts must NOT be hijacked into a memory lookup
        // (they're build/diagnostic/imperative requests for the LLM).
        // German idiomatic fillers / diagnostics (removed openers):
        assert!(
            detect_recall_intent("Weißt du was, lass uns einen Parser bauen").is_none(),
            "'weißt du was' filler must not trigger recall"
        );
        assert!(
            detect_recall_intent("Was haben wir hier für einen Bug?").is_none(),
            "'was haben wir' diagnostic must not trigger recall"
        );
        assert!(
            detect_recall_intent("Wann habe ich das nächste Meeting?").is_none(),
            "'wann habe ich' schedule query must not trigger recall"
        );
        // English context-setter before an imperative (removed opener):
        assert!(
            detect_recall_intent("Remember that the build is broken, fix it").is_none(),
            "'remember that' context-setter must not trigger recall"
        );
        // Compound prompt: recall opener used as a rhetorical lead-in before a
        // real request (the mid-string `?` guard catches it).
        assert!(
            detect_recall_intent("Do you remember the API for X? Write me code").is_none(),
            "compound prompt with a trailing imperative must fall through to the LLM"
        );
    }

    // ── format_recall_reply ──────────────────────────────────────────

    #[test]
    fn format_empty_hits_returns_not_found_message_de() {
        let reply = format_recall_reply(&[], RecallLanguage::German, "memory");
        assert!(reply.contains("keine Erinnerung"));
        assert!(reply.contains("memory"));
    }

    #[test]
    fn format_empty_hits_returns_not_found_message_en() {
        let reply = format_recall_reply(&[], RecallLanguage::English, "memory");
        assert!(reply.contains("Nothing found"));
        assert!(reply.contains("memory"));
    }

    #[test]
    fn format_single_hit_renders_german_template() {
        let ts: i64 = 1_700_000_000_000_000_000; // 2023-11-14T22:13:20 UTC
        let h = hit(ts, "Rust ist gut");
        let reply = format_recall_reply(&[h], RecallLanguage::German, "rust");
        assert!(reply.starts_with("Ja — "), "got: {reply}");
        assert!(reply.contains("am 2023-11-14"));
        assert!(reply.contains("hast du gesagt"));
        assert!(reply.contains("Rust ist gut"));
    }

    #[test]
    fn format_single_hit_renders_english_template() {
        let ts: i64 = 1_700_000_000_000_000_000;
        let h = hit(ts, "Rust is great");
        let reply = format_recall_reply(&[h], RecallLanguage::English, "rust");
        assert!(reply.starts_with("Yes — "), "got: {reply}");
        assert!(reply.contains("on 2023-11-14"));
        assert!(reply.contains("you said"));
        assert!(reply.contains("Rust is great"));
    }

    #[test]
    fn format_multiple_hits_concatenated_with_newlines() {
        let ts: i64 = 1_700_000_000_000_000_000;
        let h1 = hit(ts, "first");
        let h2 = hit(ts + 86_400 * 1_000_000_000, "second");
        let reply = format_recall_reply(&[h1, h2], RecallLanguage::English, "anything");
        assert_eq!(
            reply.matches("you said:").count(),
            2,
            "two `you said:` blocks"
        );
        assert!(reply.contains("first"));
        assert!(reply.contains("second"));
        // Newline-separated, not space-separated.
        assert!(reply.contains('\n'));
    }

    #[test]
    fn format_handles_inner_single_quote_safely() {
        // Wrapper is `'...'` — an inner single-quote would close
        // the wrapper visually. quote_safe swaps inner singles to
        // backtick so the wrapper stays intact.
        let h = hit(1_700_000_000_000_000_000, "she said 'hello'");
        let reply = format_recall_reply(&[h], RecallLanguage::English, "hello");
        // Inner single quotes swapped to backticks.
        assert!(reply.contains("`hello`"), "got: {reply}");
        assert!(
            !reply.contains("'hello'"),
            "raw inner single-quote must not survive: {reply}"
        );
    }

    #[test]
    fn format_does_not_panic_on_extreme_timestamps() {
        // Drift guard: the wall-clock cast (ts_ns / 1e9) must not
        // panic for i64::MAX or i64::MIN. chrono handles a wide
        // range; either the date renders or the helper returns the
        // documented fallback — either way no panic.
        for ts in [i64::MIN, i64::MAX] {
            let h = hit(ts, "edge");
            let reply = format_recall_reply(&[h], RecallLanguage::English, "x");
            assert!(reply.contains("edge"), "got: {reply}");
        }
    }
}
