//! G-03 — rule-based follow-up tone scorer. NO LLM call: a pure, fast,
//! deterministic heuristic over an operator's chat turn, used to detect when
//! the turn reads as a CORRECTION of the preceding reply (negative) or a
//! reinforcement (positive). EN + DE patterns (the operator's two languages).
//!
//! Scores in `[-1.0, 1.0]`. A turn below [`NEGATIVE_THRESHOLD`] is treated as
//! operator pushback (emits an `OPERATOR_FEEDBACK` frame); above
//! [`POSITIVE_THRESHOLD`] is a positive signal. The middle band is neutral
//! (a normal follow-up question is NOT feedback).

/// Below this, a turn is operator pushback / correction.
pub const NEGATIVE_THRESHOLD: f32 = -0.3;
/// Above this, a turn is positive reinforcement.
pub const POSITIVE_THRESHOLD: f32 = 0.4;

/// Negative-correction phrases (lowercased substring match). EN + DE.
const NEGATIVE_PATTERNS: &[&str] = &[
    // English
    "that's wrong",
    "thats wrong",
    "that is wrong",
    "incorrect",
    "that's not right",
    "thats not right",
    "not what i asked",
    "not what i meant",
    "you misunderstood",
    "you're wrong",
    "youre wrong",
    "wrong answer",
    "bad answer",
    "that's not correct",
    "try again",
    "no, ", // leading "no," correction
    "that misses the point",
    "missed the point",
    "that doesn't help",
    "doesn't help",
    "not helpful",
    "useless",
    // German
    "das ist falsch",
    "das stimmt nicht",
    "falsch",
    "stimmt nicht",
    "nicht was ich",
    "du hast mich falsch verstanden",
    "missverstanden",
    "versuch es nochmal",
    "versuche es nochmal",
    "nochmal",
    "das hilft nicht",
    "nicht hilfreich",
    "quatsch",
    "unsinn",
];

/// Positive-reinforcement phrases (lowercased substring match). EN + DE.
const POSITIVE_PATTERNS: &[&str] = &[
    // English
    "perfect",
    "exactly",
    "that's right",
    "thats right",
    "correct",
    "well done",
    "great",
    "thank you",
    "thanks",
    "helpful",
    "that works",
    "works great",
    "nice",
    "spot on",
    // German
    "genau",
    "perfekt",
    "richtig",
    "gut gemacht",
    "danke",
    "hilfreich",
    "das passt",
    "super",
    "klasse",
];

/// The outcome of scoring one follow-up turn.
#[derive(Debug, Clone, PartialEq)]
pub struct ToneScore {
    /// `-1.0` (strong correction) .. `1.0` (strong praise). `0.0` = neutral.
    pub score: f32,
    /// The matched phrases (for the audit payload + operator context).
    pub matched: Vec<String>,
}

impl ToneScore {
    /// True when the turn is operator pushback worth recording.
    pub fn is_correction(&self) -> bool {
        self.score < NEGATIVE_THRESHOLD
    }
    /// True when the turn is positive reinforcement.
    pub fn is_positive(&self) -> bool {
        self.score > POSITIVE_THRESHOLD
    }
}

/// Score `text` as a follow-up turn. Negative patterns pull the score down,
/// positive patterns up; the net is clamped to `[-1.0, 1.0]`. Each distinct
/// matched phrase contributes a fixed weight (no double-count of repeats),
/// so a single strong "that's wrong" already crosses the negative threshold
/// while a neutral question scores 0.0.
/// Substring match that will not fire inside a longer word.
///
/// A plain `contains` made the classifier cancel itself out: the positive
/// pattern `"correct"` matches inside the negative word `"incorrect"`, so
/// "stop, this is incorrect" scored -0.5 + 0.5 = 0.0 and was read as neutral —
/// the single most explicit correction phrase in the list was the one it could
/// not detect.
///
/// Boundaries are only enforced on the side where the pattern itself ends in a
/// word character. `"no, "` ends in a space, so what follows it is free; a
/// pattern like `"correct"` must be flanked by non-word characters on both
/// sides.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let needle_starts_word = needle.chars().next().is_some_and(is_word_char);
    let needle_ends_word = needle.chars().next_back().is_some_and(is_word_char);
    let mut from = 0usize;
    while let Some(found) = haystack[from..].find(needle) {
        let start = from + found;
        let end = start + needle.len();
        let left_ok = !needle_starts_word
            || haystack[..start].chars().next_back().is_none_or(|c| !is_word_char(c));
        let right_ok = !needle_ends_word
            || haystack[end..].chars().next().is_none_or(|c| !is_word_char(c));
        if left_ok && right_ok {
            return true;
        }
        // Advance past this occurrence's first char to keep scanning.
        from = start + haystack[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

pub fn score_follow_up(text: &str) -> ToneScore {
    let lower = text.to_lowercase();
    let mut matched = Vec::new();
    let mut score = 0.0f32;

    // Per-hit weight: one clear correction phrase (−0.5) already crosses
    // −0.3; one praise phrase (+0.5) crosses +0.4. Multiple hits accumulate
    // but the net is clamped, so stuffing can't runaway.
    for pat in NEGATIVE_PATTERNS {
        if contains_word(&lower, pat) {
            score -= 0.5;
            matched.push((*pat).to_string());
        }
    }
    for pat in POSITIVE_PATTERNS {
        if contains_word(&lower, pat) {
            score += 0.5;
            matched.push((*pat).to_string());
        }
    }
    ToneScore {
        score: score.clamp(-1.0, 1.0),
        matched,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_correction_crosses_threshold() {
        let s = score_follow_up("No, that's wrong — I asked for the other file");
        assert!(s.is_correction(), "got score {}", s.score);
        assert!(!s.matched.is_empty());
    }

    #[test]
    fn german_correction_detected() {
        let s = score_follow_up("Das ist falsch, versuch es nochmal");
        assert!(s.is_correction(), "got score {}", s.score);
    }

    #[test]
    fn positive_ack_crosses_positive_threshold() {
        let s = score_follow_up("perfect, exactly what I needed");
        assert!(s.is_positive(), "got score {}", s.score);
        assert!(!s.is_correction());
    }

    #[test]
    fn neutral_follow_up_is_not_feedback() {
        let s = score_follow_up("can you also show me the config file?");
        assert!(
            !s.is_correction(),
            "neutral question must not be a correction"
        );
        assert!(!s.is_positive());
        assert_eq!(s.score, 0.0);
    }

    #[test]
    fn score_is_clamped() {
        // Many negatives still clamp at -1.0 (no runaway).
        let s = score_follow_up("wrong wrong incorrect falsch quatsch unsinn useless");
        assert!(s.score >= -1.0);
        assert!(s.is_correction());
    }

    #[test]
    fn mixed_signals_net_out() {
        // "thanks but that's wrong" — one positive + one negative net to 0.0
        // (neutral) which is the desired conservative behaviour.
        let s = score_follow_up("thanks, but that's wrong");
        assert_eq!(s.score, 0.0);
        assert!(!s.is_correction());
    }

    #[test]
    fn a_positive_pattern_inside_a_negative_word_does_not_cancel_it() {
        // "correct" sits inside "incorrect". With a plain substring match the
        // two hits cancelled to 0.0 and the clearest correction phrase in the
        // language read as neutral.
        let s = score_follow_up("stop, this is incorrect");
        assert!(
            s.is_correction(),
            "an explicit correction must not be neutralised by its own substring: {s:?}"
        );
        assert!(
            !s.matched.iter().any(|m| m == "correct"),
            "the positive pattern must not match inside a longer word: {s:?}"
        );
    }

    #[test]
    fn word_boundaries_do_not_break_phrase_patterns() {
        // Patterns ending in punctuation/space must still match mid-sentence.
        assert!(score_follow_up("no, that is wrong").is_correction());
        // And a genuine standalone praise word still scores positive.
        assert!(score_follow_up("that is correct, thanks").is_positive());
    }
}
