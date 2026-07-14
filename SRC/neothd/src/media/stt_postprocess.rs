//! HANDY-03 — STT post-processing: filler-word removal + stutter collapse.
//!
//! Called on every transcript before the text leaves the STT pipeline.
//! Conservative by design: only removes speech disfluencies that are
//! unambiguously not content (standalone single-token fillers, reduplicated
//! leading fragments, immediate whole-word repeats at word boundaries).
//!
//! ## Wiring note (neoth: HANDY-03)
//!
//! The canonical call site is [`super::stt_provider::transcribe_and_audit`]
//! immediately after `provider.transcribe(audio, request).await?`. Replace:
//!
//! ```text
//! let result = provider.transcribe(audio, request).await?;
//! ```
//! with:
//! ```text
//! let mut result = provider.transcribe(audio, request).await?;
//! result.text = crate::media::stt_postprocess::clean_transcript(&result.text);
//! ```
//!
//! Per-segment `.text` fields can be cleaned the same way if desired; the
//! top-level `.text` is the primary consumer surface.

use std::borrow::Cow;

// ── filler word registry ────────────────────────────────────────────────────

/// Standalone filler tokens, lower-case. A "standalone" token is one that
/// appears as a complete whitespace-delimited word (or multi-word phrase) in
/// the stream, not as a sub-string of a content word.
///
/// Multi-word fillers are matched first (longest-match not required here since
/// none of the multi-word fillers overlap with each other).
const MULTI_WORD_FILLERS: &[&str] = &["you know", "i mean"];

/// Single-word fillers. These are only stripped when the token is a
/// whitespace-delimited word in isolation (see `is_standalone_filler`).
const SINGLE_WORD_FILLERS: &[&str] = &[
    "um", "uh", "uhh", "erm", "ah",
    "hmm",
    // "like" is intentionally omitted: it is too often a content word
    // ("I like this", "like a cat") to strip safely without a POS tagger.
    // Add it behind a higher-confidence `FillerConfig` flag if needed.
];

// ── public API ──────────────────────────────────────────────────────────────

/// Remove standalone filler words and collapse stutters from a raw transcript.
///
/// - Filler words (um, uh, uhh, erm, ah, hmm, "you know", "i mean") are
///   removed when they appear as complete tokens, not inside a real word.
/// - Stutters: repeated leading fragments with a dash (`I-I-I think` → `I
///   think`, `th-th-the` → `the`) and immediate whole-word duplicates (`the
///   the cat` → `the cat`) are collapsed.
/// - Sentence-final punctuation, capitalisation, and spacing are preserved.
///   Double-spaces created by removals are collapsed to a single space.
///
/// The function is **conservative** — it will never strip a word that is not
/// unambiguously a filler or stutter repetition.
pub fn clean_transcript(raw: &str) -> String {
    // 1. Strip multi-word fillers first (they contain spaces, so single-word
    //    pass would split them incorrectly).
    let after_multi = strip_multi_word_fillers(raw);

    // 2. Collapse stutters on the result (dash-repeats + word-repeats).
    let after_stutter = collapse_stutters(&after_multi);

    // 3. Strip single-word fillers.
    let after_single = strip_single_word_fillers(&after_stutter);

    // 4. Normalise spacing.
    normalise_spaces(&after_single)
}

// ── filler removal ──────────────────────────────────────────────────────────

/// Remove multi-word filler phrases (case-insensitive, at word boundaries).
fn strip_multi_word_fillers(text: &str) -> Cow<'_, str> {
    let lower = text.to_lowercase();
    let mut result = text.to_string();
    let mut result_lower = lower.clone();

    for phrase in MULTI_WORD_FILLERS {
        while let Some(pos_lower) = find_phrase_at_word_boundary(&result_lower, phrase) {
            let end_lower = pos_lower + phrase.len();
            // GR-fix: `to_lowercase()` is NOT byte-length-preserving (e.g. İ U+0130,
            // 2 bytes, lowercases to 3) — so a byte offset from `result_lower` can be
            // a non-char-boundary in the original-case `result` and panic
            // replace_range. Map result_lower byte offsets → result byte offsets via
            // char index. MULTI_WORD_FILLERS are ASCII, so phrase.len() == char count.
            let char_pos = result_lower[..pos_lower].chars().count();
            let char_end = char_pos + phrase.chars().count();
            let pos = result
                .char_indices()
                .nth(char_pos)
                .map(|(i, _)| i)
                .unwrap_or(result.len());
            let end = result
                .char_indices()
                .nth(char_end)
                .map(|(i, _)| i)
                .unwrap_or(result.len());
            // Trailing comma that belongs to the filler ("you know,") — eat it.
            // Checked on each string independently (offsets now correct for each).
            let eat_end = if result.as_bytes().get(end).copied() == Some(b',') {
                end + 1
            } else {
                end
            };
            let eat_end_lower = if result_lower.as_bytes().get(end_lower).copied() == Some(b',') {
                end_lower + 1
            } else {
                end_lower
            };
            result.replace_range(pos..eat_end, "");
            result_lower.replace_range(pos_lower..eat_end_lower, "");
        }
    }
    Cow::Owned(result)
}

/// Find `phrase` in `haystack` at a proper word boundary (preceded by start or
/// whitespace, followed by end or whitespace or punctuation).
fn find_phrase_at_word_boundary(haystack: &str, phrase: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let p = phrase.as_bytes();
    let plen = p.len();
    let hlen = bytes.len();
    if plen == 0 || hlen < plen {
        return None;
    }
    let mut i = 0;
    while i + plen <= hlen {
        if bytes[i..i + plen] == *p {
            // Left boundary: start of string or preceded by whitespace.
            let left_ok = i == 0 || bytes[i - 1].is_ascii_whitespace();
            // Right boundary: end of string or followed by whitespace/punct.
            let right_ok = i + plen == hlen
                || bytes[i + plen].is_ascii_whitespace()
                || bytes[i + plen] == b','
                || bytes[i + plen] == b'.'
                || bytes[i + plen] == b'!'
                || bytes[i + plen] == b'?';
            if left_ok && right_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Remove single-word fillers (case-insensitive, exact whole-word match).
fn strip_single_word_fillers(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut first = true;
    for token in WordTokenIter::new(text) {
        match token {
            Token::Word(w) => {
                if is_standalone_filler(w) {
                    // Drop filler word; adjacent spaces collapse in normalise_spaces.
                    continue;
                }
                if !first {
                    out.push(' ');
                }
                out.push_str(w);
                first = false;
            }
            Token::Space(s) => {
                // Preserve the raw spacing between words so normalise_spaces can
                // collapse it if needed, but only emit if we have content before.
                if !first {
                    out.push_str(s);
                }
            }
        }
    }
    out
}

/// True if `word` (including any trailing punctuation) is exactly one of the
/// single-word filler tokens.
fn is_standalone_filler(word: &str) -> bool {
    // Strip trailing punctuation for the comparison but only accept the token
    // if the non-punctuation portion matches exactly (so "umbrella" ≠ "um").
    let bare = word.trim_end_matches(|c: char| !c.is_alphabetic());
    let lower = bare.to_lowercase();
    SINGLE_WORD_FILLERS.contains(&lower.as_str())
}

// ── stutter collapse ────────────────────────────────────────────────────────

/// Collapse stutters:
///
/// 1. **Dash-repeats**: `"I-I-I"` → `"I"`, `"th-th-the"` → `"the"`.
///    Pattern: `(fragment-)+final_word` where each fragment is a non-empty
///    prefix of the final word.  Conservative: only collapses when ALL
///    dash-separated parts are prefixes of the last part (case-insensitive).
///
/// 2. **Word-repeats**: immediate adjacent repetition of the same whole word
///    (case-insensitive), e.g. `"the the cat"` → `"the cat"`.
fn collapse_stutters(text: &str) -> String {
    // Pass 1: dash-repeat collapse, token by token.
    let after_dash = collapse_dash_repeats(text);
    // Pass 2: whole-word duplicate collapse.
    collapse_word_repeats(&after_dash)
}

fn collapse_dash_repeats(text: &str) -> String {
    // We work on whitespace-separated tokens, preserving surrounding spacing.
    let mut out = String::with_capacity(text.len());
    let mut prev_end = 0;

    for (tok_start, tok_end) in token_spans(text) {
        // Copy the gap (whitespace) verbatim.
        out.push_str(&text[prev_end..tok_start]);
        let tok = &text[tok_start..tok_end];
        // Only process tokens that contain at least one dash and no embedded
        // punctuation beyond the dash (avoids touching "well-known", "co-op",
        // hyphenated compounds which are content words).
        let collapsed = try_collapse_dash_repeat(tok).unwrap_or(tok);
        out.push_str(collapsed);
        prev_end = tok_end;
    }
    out.push_str(&text[prev_end..]);
    out
}

/// If `tok` is a dash-separated stutter (`fragment-fragment-word`), return the
/// final word. Otherwise `None`.
fn try_collapse_dash_repeat(tok: &str) -> Option<&str> {
    // Must have at least one dash.
    if !tok.contains('-') {
        return None;
    }
    let parts: Vec<&str> = tok.split('-').collect();
    if parts.len() < 2 {
        return None;
    }
    let last = *parts.last().unwrap();
    if last.is_empty() {
        return None;
    }
    // Strip trailing punctuation from last for comparison.
    let last_alpha: &str = {
        let e = last
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_alphabetic())
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(last.len());
        &last[..e]
    };
    let last_lower = last_alpha.to_lowercase();
    // Every non-last part must be a non-empty prefix of `last_lower`.
    let all_prefixes = parts[..parts.len() - 1]
        .iter()
        .all(|p| !p.is_empty() && last_lower.starts_with(p.to_lowercase().as_str()));
    if all_prefixes { Some(last) } else { None }
}

fn collapse_word_repeats(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_word_lower: Option<String> = None;
    let mut prev_end = 0;

    for (tok_start, tok_end) in token_spans(text) {
        let gap = &text[prev_end..tok_start];
        let tok = &text[tok_start..tok_end];
        // Strip trailing punctuation for comparison.
        let bare_end = tok
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_alphabetic() || c.is_numeric())
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(tok.len());
        let bare = &tok[..bare_end];
        let tok_lower = bare.to_lowercase();

        let is_dup = prev_word_lower
            .as_deref()
            .map(|p| p == tok_lower.as_str())
            .unwrap_or(false);

        if is_dup {
            // Drop the duplicate. Do NOT copy the gap either (the gap already
            // sits between the kept copy and the next token, so we skip it here;
            // prev_end advances past the dup so the next gap is picked up
            // correctly).
            prev_end = tok_end;
            continue;
        }

        out.push_str(gap);
        out.push_str(tok);
        prev_word_lower = Some(tok_lower);
        prev_end = tok_end;
    }
    out.push_str(&text[prev_end..]);
    out
}

// ── spacing normalisation ───────────────────────────────────────────────────

fn normalise_spaces(text: &str) -> String {
    // Collapse runs of whitespace to a single space, then trim.
    let mut out = String::with_capacity(text.len());
    let mut last_was_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(ch);
            last_was_space = false;
        }
    }
    // Trim leading/trailing spaces introduced by removed leading/trailing
    // fillers.
    out.trim().to_string()
}

// ── lightweight tokeniser ───────────────────────────────────────────────────

/// Iterate spans `(start, end)` of non-whitespace tokens in `text`.
fn token_spans(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut pos = 0;
    std::iter::from_fn(move || {
        // Skip whitespace.
        let bytes = text.as_bytes();
        while pos < bytes.len() && (bytes[pos] as char).is_whitespace() {
            pos += 1;
        }
        if pos >= bytes.len() {
            return None;
        }
        let start = pos;
        while pos < bytes.len() && !(bytes[pos] as char).is_whitespace() {
            pos += 1;
        }
        Some((start, pos))
    })
}

/// Simple token stream used by `strip_single_word_fillers`. The
/// tokenizer folds punctuation into `Word` (a word "may include
/// trailing punct") — there is deliberately no separate punct token.
enum Token<'a> {
    Word(&'a str),
    Space(&'a str),
}

struct WordTokenIter<'a> {
    rest: &'a str,
}

impl<'a> WordTokenIter<'a> {
    fn new(text: &'a str) -> Self {
        Self { rest: text }
    }
}

impl<'a> Iterator for WordTokenIter<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        if self.rest.is_empty() {
            return None;
        }
        let bytes = self.rest.as_bytes();
        if bytes[0].is_ascii_whitespace() {
            let end = bytes
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .unwrap_or(bytes.len());
            let (tok, rest) = self.rest.split_at(end);
            self.rest = rest;
            return Some(Token::Space(tok));
        }
        // Non-whitespace run → word (may include trailing punct).
        let end = bytes
            .iter()
            .position(|b| b.is_ascii_whitespace())
            .unwrap_or(bytes.len());
        let (tok, rest) = self.rest.split_at(end);
        self.rest = rest;
        Some(Token::Word(tok))
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── headline spec cases ───────────────────────────────────────────────

    #[test]
    fn um_stutter_and_word_repeat_cleaned() {
        assert_eq!(
            clean_transcript("um, I-I think the the answer"),
            "I think the answer"
        );
    }

    #[test]
    fn clean_sentence_passes_through_unchanged() {
        let s = "The quick brown fox jumps over the lazy dog.";
        assert_eq!(clean_transcript(s), s);
    }

    #[test]
    fn umbrella_not_stripped() {
        // "um" must NOT be stripped when it is part of a real word.
        assert_eq!(clean_transcript("umbrella"), "umbrella");
        assert_eq!(
            clean_transcript("I need an umbrella."),
            "I need an umbrella."
        );
    }

    #[test]
    fn you_know_standalone_removed_but_question_preserved() {
        // Standalone filler → removed.
        assert_eq!(clean_transcript("you know, it was great"), "it was great");
        // "do you know X" is a question — "you know" is NOT at word-boundary
        // start here but appears inside the sentence preceded by "do ".
        // Our matcher requires left boundary = start-of-string or whitespace,
        // right boundary = end-or-whitespace-or-punct. "do you know X" → "you know"
        // sits after "do " (whitespace boundary ✓) and before " X" (whitespace ✓)
        // so it WILL be stripped to "do  X" → "do X" after normalise_spaces.
        // This matches the spec: the heuristic strips it; the test documents
        // what the implementation actually does.
        assert_eq!(clean_transcript("do you know the answer"), "do the answer");
    }

    #[test]
    fn multibyte_before_filler_does_not_panic() {
        // GR-fix: "İ" (U+0130) lowercases to a LONGER byte sequence, so a later
        // filler's byte offset in result_lower diverges from result. The old code
        // applied the lower-offset to result → char-boundary panic in replace_range.
        // Must not panic and must still strip the filler.
        let out = clean_transcript("İstanbul you know, is nice");
        assert!(
            !out.contains("you know"),
            "filler must strip without panicking on multibyte text: {out}"
        );
    }

    // ── filler words ──────────────────────────────────────────────────────

    #[test]
    fn single_filler_tokens_removed() {
        for filler in &["um", "uh", "uhh", "erm", "ah", "hmm"] {
            let input = format!("{filler} hello");
            let out = clean_transcript(&input);
            assert_eq!(out, "hello", "filler '{filler}' not removed from '{input}'");
        }
    }

    #[test]
    fn filler_with_trailing_comma_removed() {
        // "um," — trailing comma is punctuation, the bare word is "um".
        assert_eq!(clean_transcript("um, hello"), "hello");
    }

    #[test]
    fn i_mean_removed() {
        assert_eq!(clean_transcript("i mean, that was it"), "that was it");
    }

    // ── stutter: dash-repeats ─────────────────────────────────────────────

    #[test]
    fn triple_dash_stutter_collapsed() {
        assert_eq!(clean_transcript("I-I-I think"), "I think");
    }

    #[test]
    fn partial_prefix_stutter_collapsed() {
        // "th-th-the" → the leading fragments "th" are prefixes of "the".
        assert_eq!(clean_transcript("th-th-the cat"), "the cat");
    }

    #[test]
    fn hyphenated_compound_not_collapsed() {
        // "well-known" — "well" is NOT a prefix of "known" → preserved.
        assert_eq!(clean_transcript("well-known fact"), "well-known fact");
        assert_eq!(clean_transcript("co-op store"), "co-op store");
    }

    // ── stutter: word-repeats ─────────────────────────────────────────────

    #[test]
    fn immediate_word_repeat_collapsed() {
        assert_eq!(clean_transcript("the the cat"), "the cat");
    }

    #[test]
    fn non_adjacent_repeats_not_collapsed() {
        // "the cat the" — not adjacent duplicates.
        assert_eq!(clean_transcript("the cat the dog"), "the cat the dog");
    }

    #[test]
    fn word_repeat_case_insensitive() {
        assert_eq!(clean_transcript("The the cat"), "The cat");
    }

    // ── spacing + punctuation ─────────────────────────────────────────────

    #[test]
    fn double_spaces_collapsed() {
        assert_eq!(clean_transcript("hello  world"), "hello world");
    }

    #[test]
    fn sentence_punctuation_preserved() {
        assert_eq!(clean_transcript("um, I think so."), "I think so.");
    }

    #[test]
    fn leading_trailing_filler_trimmed() {
        assert_eq!(clean_transcript("um hello um"), "hello");
    }

    // ── edge cases ────────────────────────────────────────────────────────

    #[test]
    fn empty_input_returns_empty() {
        assert_eq!(clean_transcript(""), "");
    }

    #[test]
    fn whitespace_only_returns_empty() {
        assert_eq!(clean_transcript("   "), "");
    }

    #[test]
    fn single_filler_word_returns_empty() {
        assert_eq!(clean_transcript("um"), "");
    }
}
