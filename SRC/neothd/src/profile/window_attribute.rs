//! Stage 2 — `window_attribute`. Classifies every segment in a
//! [`ConversationWindow`] as `UserSpeech` / `QuotedExternal` /
//! `ToolOutput` / `Ambiguous`. Pure-deterministic, no LLM, no I/O.
//!
//! ## Heuristic
//!
//! Per-segment scoring across multiple signals; the highest-confidence
//! signal wins. A confidence floor of 0.6 separates `Ambiguous` from
//! the three confident classes.
//!
//! 1. **Origin-derived**: `ProviderOutbound` → `ToolOutput` (confidence 1.0).
//!    The LLM produced these tokens; they are by definition not user speech.
//! 2. **Quote markers**: lines starting with `>`, fenced code blocks
//!    (``` ... ```), forwarded-message headers (`<Name> schrieb:`,
//!    `<Name> wrote:`, `Forwarded from`, `---- Original Message ----`),
//!    URL-only segments, raw email/reddit-style "On <date>, <user>
//!    wrote:" lines → `QuotedExternal`.
//! 3. **First-person ratio**: count first-person pronouns
//!    (`I / ich / mein / my / we / wir / unser`) vs total word count.
//!    Ratio ≥ 0.05 + no quote markers → `UserSpeech` (high confidence
//!    when ratio ≥ 0.10).
//! 4. **Default**: short, no signal → `Ambiguous`.

use regex::Regex;
use std::sync::OnceLock;

use crate::profile::types::{
    AttributedSegment, AttributedWindow, Attribution, ConversationSegment, ConversationWindow,
    SegmentOrigin,
};

/// Minimum confidence to escape `Ambiguous`. Set conservatively per
/// SPEC §1 ("ambiguous: confidence < 0.6 on attribution — NOT eligible").
const AMBIGUITY_FLOOR: f32 = 0.6;

/// First-person ratio above which a segment without quote markers
/// confidently classifies as `UserSpeech`. Below this, the heuristic
/// keeps the segment in `Ambiguous` so the extractor doesn't see
/// content that might be a paraphrase of something the operator was
/// quoting.
const FIRST_PERSON_RATIO_FLOOR: f32 = 0.05;

/// First-person tokens we count. Lowercase-only — the matcher
/// lowercases the input. Includes German + English. Possessives
/// (`my`, `mein`) count too because operators say "my key" all day.
const FIRST_PERSON_TOKENS: &[&str] = &[
    "i", "i'm", "i've", "i'll", "i'd", "me", "my", "mine", "we", "we're", "we've", "we'll", "our",
    "ours", // German
    "ich", "mein", "meine", "meiner", "meinem", "meinen", "wir", "uns", "unser", "unsere",
    "unserer", "unserem", "unseren",
];

/// Compile-once regex set covering quote-marker signals.
fn quote_regexes() -> &'static [Regex] {
    static REGEXES: OnceLock<Vec<Regex>> = OnceLock::new();
    REGEXES.get_or_init(|| {
        vec![
            // Quoted-reply line markers (any line starting with `>` or `»`).
            Regex::new(r"(?m)^[>»]").unwrap(),
            // Email reply header — "On <date>, <name> wrote:" / German "schrieb".
            Regex::new(r"(?i)\bon\s.{1,80}\bwrote:").unwrap(),
            Regex::new(r"(?i)\b\w{1,30}\s+schrieb:").unwrap(),
            // Forwarded-message dividers.
            Regex::new(r"(?i)-{3,}\s*(original message|forwarded message|begin forwarded)\s*-{3,}")
                .unwrap(),
            Regex::new(r"(?i)\bforwarded from\b").unwrap(),
            // Reddit-style paste markers.
            Regex::new(r"(?i)\bposted by\s+u/\w+").unwrap(),
            // Fenced code blocks — at least three backticks on a line of their own.
            Regex::new(r"(?ms)^```").unwrap(),
        ]
    })
}

/// True when the entire segment (after trim) is a single URL — the
/// operator pasted a link rather than wrote a sentence.
fn is_url_only(text: &str) -> bool {
    static URL_ONLY: OnceLock<Regex> = OnceLock::new();
    let re = URL_ONLY.get_or_init(|| Regex::new(r"^\s*https?://\S+\s*$").unwrap());
    re.is_match(text)
}

/// Classify a single segment.
pub fn attribute_segment(seg: &ConversationSegment) -> AttributedSegment {
    let mut matched_signals = Vec::new();

    // 1. Origin-derived: provider output is always tool output.
    if seg.origin == SegmentOrigin::ProviderOutbound {
        matched_signals.push("origin=provider_outbound".to_string());
        return AttributedSegment {
            segment: seg.clone(),
            attribution: Attribution::ToolOutput,
            confidence: 1.0,
            matched_signals,
        };
    }

    let text = seg.text.as_str();
    let lowered = text.to_lowercase();

    // 2. URL-only segment is treated as a paste.
    if is_url_only(text) {
        matched_signals.push("url_only".to_string());
        return AttributedSegment {
            segment: seg.clone(),
            attribution: Attribution::QuotedExternal,
            confidence: 0.85,
            matched_signals,
        };
    }

    // 3. Quote-marker scan. Any hit → quoted_external — the H1 fix is
    //    aggressive on purpose. False positives drop legitimate text
    //    from extraction, false negatives let attacker-pasted content
    //    poison the profile. The latter is the worse failure mode.
    let mut quote_score: f32 = 0.0;
    for re in quote_regexes() {
        if re.is_match(text) {
            matched_signals.push(format!("quote_re={}", re.as_str()));
            quote_score = (quote_score + 0.6).min(1.0);
        }
    }
    if quote_score >= AMBIGUITY_FLOOR {
        return AttributedSegment {
            segment: seg.clone(),
            attribution: Attribution::QuotedExternal,
            confidence: quote_score,
            matched_signals,
        };
    }

    // 4. First-person ratio. Tokenise on word-boundary; count tokens
    //    that appear in FIRST_PERSON_TOKENS. Lowercase, ASCII-friendly.
    let words: Vec<&str> = lowered
        .split(|c: char| !c.is_alphanumeric() && c != '\'')
        .filter(|w| !w.is_empty())
        .collect();
    let total = words.len();
    if total == 0 {
        return AttributedSegment {
            segment: seg.clone(),
            attribution: Attribution::Ambiguous,
            confidence: 0.0,
            matched_signals,
        };
    }
    let first_person_hits = words
        .iter()
        .filter(|w| FIRST_PERSON_TOKENS.contains(w))
        .count();
    let ratio = first_person_hits as f32 / total as f32;

    if ratio >= FIRST_PERSON_RATIO_FLOOR && quote_score < AMBIGUITY_FLOOR {
        matched_signals.push(format!("first_person_ratio={ratio:.3}"));
        // Map the ratio to a confidence: 0.05 → 0.65, 0.10 → 0.80, 0.20 → 1.0.
        let confidence = (0.6 + (ratio - FIRST_PERSON_RATIO_FLOOR) * 3.0).clamp(0.6, 1.0);
        return AttributedSegment {
            segment: seg.clone(),
            attribution: Attribution::UserSpeech,
            confidence,
            matched_signals,
        };
    }

    // 5. Default: insufficient signal → ambiguous.
    matched_signals.push(format!("first_person_ratio={ratio:.3} below floor"));
    AttributedSegment {
        segment: seg.clone(),
        attribution: Attribution::Ambiguous,
        confidence: ratio,
        matched_signals,
    }
}

/// Classify every segment in a window. Pure-functional over the input.
pub fn attribute_segments(window: &ConversationWindow) -> AttributedWindow {
    let segments = window.segments.iter().map(attribute_segment).collect();
    AttributedWindow {
        trigger_event_id: window.trigger_event_id,
        segments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(origin: SegmentOrigin, text: &str) -> ConversationSegment {
        ConversationSegment {
            event_id: 1,
            ts_ns: 0,
            origin,
            text: text.to_string(),
        }
    }

    #[test]
    fn provider_outbound_is_always_tool_output() {
        let s = seg(
            SegmentOrigin::ProviderOutbound,
            "Of course, I'd be happy to help with that.",
        );
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::ToolOutput);
        assert_eq!(a.confidence, 1.0);
    }

    #[test]
    fn first_person_inbound_is_user_speech() {
        let s = seg(
            SegmentOrigin::OperatorInbound,
            "I think my Rust setup is broken and I want to fix it",
        );
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::UserSpeech);
        assert!(a.confidence >= 0.6);
    }

    #[test]
    fn first_person_german_is_user_speech() {
        let s = seg(
            SegmentOrigin::OperatorInbound,
            "Ich glaube mein Rust-Setup ist kaputt und ich will das fixen",
        );
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::UserSpeech);
    }

    #[test]
    fn block_quote_markers_become_quoted_external() {
        let s = seg(
            SegmentOrigin::OperatorInbound,
            "> they said the migration is safe\n> but I'm not sure",
        );
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::QuotedExternal);
    }

    #[test]
    fn forwarded_email_header_is_quoted_external() {
        let s = seg(
            SegmentOrigin::OperatorInbound,
            "------ Forwarded message ------\nFrom: someone\nSubject: x",
        );
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::QuotedExternal);
    }

    #[test]
    fn schrieb_header_triggers_quoted_external() {
        let s = seg(
            SegmentOrigin::OperatorInbound,
            "Sam schrieb:\n> the server is at 10.0.0.1",
        );
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::QuotedExternal);
    }

    #[test]
    fn fenced_code_block_is_quoted_external() {
        let s = seg(
            SegmentOrigin::OperatorInbound,
            "Look at this:\n```\nfn main() {}\n```",
        );
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::QuotedExternal);
    }

    #[test]
    fn url_only_segment_is_quoted_external() {
        let s = seg(
            SegmentOrigin::OperatorInbound,
            "https://example.com/article",
        );
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::QuotedExternal);
    }

    #[test]
    fn third_person_short_text_is_ambiguous() {
        let s = seg(SegmentOrigin::OperatorInbound, "The weather is nice today.");
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::Ambiguous);
    }

    #[test]
    fn empty_text_is_ambiguous() {
        let s = seg(SegmentOrigin::OperatorInbound, "");
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::Ambiguous);
    }

    #[test]
    fn attribute_segments_processes_full_window() {
        let window = ConversationWindow {
            trigger_event_id: 100,
            turns_back: 2,
            segments: vec![
                seg(SegmentOrigin::OperatorInbound, "I work in Berlin"),
                seg(SegmentOrigin::ProviderOutbound, "Got it. Berlin noted."),
                seg(SegmentOrigin::OperatorInbound, "> external paste"),
            ],
        };
        let attributed = attribute_segments(&window);
        assert_eq!(attributed.segments.len(), 3);
        assert_eq!(attributed.segments[0].attribution, Attribution::UserSpeech);
        assert_eq!(attributed.segments[1].attribution, Attribution::ToolOutput);
        assert_eq!(
            attributed.segments[2].attribution,
            Attribution::QuotedExternal
        );
        assert_eq!(attributed.trigger_event_id, 100);
    }

    #[test]
    fn unknown_origin_with_first_person_still_classifies_user_speech() {
        // PROVIDER_REQUEST text gets origin=Unknown but operator-originated.
        // The attribution pass should still let strong first-person signals
        // through.
        let s = seg(
            SegmentOrigin::Unknown,
            "I personally believe my plan is the right one",
        );
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::UserSpeech);
    }

    #[test]
    fn quote_score_above_floor_overrides_first_person_signal() {
        // A segment with both first-person AND quote markers must
        // classify as quoted_external — operator quoting a source plus
        // saying "I think" is still a paste from their PoV. The H1 fix
        // requires we err on the side of caution.
        let s = seg(
            SegmentOrigin::OperatorInbound,
            "> they wrote the system is broken\n> see this\n> and that",
        );
        let a = attribute_segment(&s);
        assert_eq!(a.attribution, Attribution::QuotedExternal);
    }

    #[test]
    fn matched_signals_carry_audit_metadata() {
        let s = seg(SegmentOrigin::OperatorInbound, "I work in Berlin");
        let a = attribute_segment(&s);
        assert!(
            !a.matched_signals.is_empty(),
            "user-speech classification must record which signal fired"
        );
    }
}
