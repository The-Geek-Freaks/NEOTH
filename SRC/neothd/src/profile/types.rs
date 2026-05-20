//! Typed structs for the profile-learning pipeline.
//!
//! `ConversationWindow` is what `window_extract` produces — a slice of
//! prior turns around a trigger event. `AttributedWindow` is what
//! `window_attribute` produces — the same slice but with every segment
//! tagged by attribution class.

use serde::{Deserialize, Serialize};

/// Origin of one segment as recorded in the WAL / episodic index.
///
/// Distinguishes operator-typed inbound text from provider-generated
/// outbound text. The attribution pass treats them differently:
/// inbound segments are candidates for `UserSpeech`; outbound segments
/// always classify as [`Attribution::ToolOutput`] (they're LLM-produced).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentOrigin {
    /// Operator-authored — `RAW_TEXT` event or inbound channel message.
    OperatorInbound,
    /// Provider-authored — `PROVIDER_RESPONSE` or `CHANNEL_EGRESS`.
    ProviderOutbound,
    /// Unknown — segment did not carry an event-type hint.
    Unknown,
}

/// One segment of the conversation window, pre-attribution. The
/// `event_id` lets downstream stages cite the exact WAL row a claim is
/// backed by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationSegment {
    pub event_id: i64,
    pub ts_ns: i64,
    pub origin: SegmentOrigin,
    pub text: String,
}

/// Output of `window_extract` (stage 1 of `profile_learn.yaml`). Ordered
/// oldest-first so the attribution pass + downstream LLM see the
/// conversation chronologically.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationWindow {
    /// The event id that triggered this extraction. The window includes
    /// segments leading up to AND including this event.
    pub trigger_event_id: i64,
    /// Number of turn-pairs (operator + provider) that were requested.
    pub turns_back: u32,
    /// Segments ordered oldest-first.
    pub segments: Vec<ConversationSegment>,
}

impl ConversationWindow {
    /// Total length of every segment's text concatenated. Useful for the
    /// extractor's complexity gate (`min_assembled_tokens`).
    pub fn total_bytes(&self) -> usize {
        self.segments.iter().map(|s| s.text.len()).sum()
    }
}

/// Attribution class for one segment. Drives whether the extractor LLM
/// is allowed to derive claims from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    /// First-person operator speech. Eligible for claim extraction.
    UserSpeech,
    /// Pasted / quoted / forwarded text. NOT eligible — claims derived
    /// from this content fail at `ProfileClaimGuard` (H1 fix).
    QuotedExternal,
    /// Provider-generated output. NOT eligible — agents talk to agents,
    /// not about operators.
    ToolOutput,
    /// Confidence below the attribution heuristic's threshold. NOT
    /// eligible — better to drop than to mis-attribute.
    Ambiguous,
}

impl Attribution {
    /// True iff the extractor LLM may derive claims from this segment.
    pub fn is_extraction_eligible(self) -> bool {
        matches!(self, Attribution::UserSpeech)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Attribution::UserSpeech => "user_speech",
            Attribution::QuotedExternal => "quoted_external",
            Attribution::ToolOutput => "tool_output",
            Attribution::Ambiguous => "ambiguous",
        }
    }
}

/// One segment from `window_attribute`. The wrapper preserves the
/// pre-attribution metadata (event_id, ts_ns, origin, text) and tacks
/// on the attribution class + the heuristic's confidence so downstream
/// auditors can see WHY a segment was classified the way it was.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttributedSegment {
    pub segment: ConversationSegment,
    pub attribution: Attribution,
    /// 0.0..=1.0 from the heuristic. Below 0.6 → `Ambiguous`.
    pub confidence: f32,
    /// Which signals fired during attribution — useful for audit + for
    /// debugging false positives ("why was this quoted_external?").
    pub matched_signals: Vec<String>,
}

impl AttributedSegment {
    pub fn is_extraction_eligible(&self) -> bool {
        self.attribution.is_extraction_eligible()
    }
}

/// Output of `window_attribute` (stage 2 of `profile_learn.yaml`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AttributedWindow {
    pub trigger_event_id: i64,
    pub segments: Vec<AttributedSegment>,
}

impl AttributedWindow {
    /// True iff at least one segment is `UserSpeech` — required by the
    /// guard's `require_first_person_window` config.
    pub fn has_user_speech_segments(&self) -> bool {
        self.segments
            .iter()
            .any(|s| s.attribution == Attribution::UserSpeech)
    }

    /// Subset of segments the extractor LLM is allowed to see.
    pub fn extraction_eligible(&self) -> Vec<&AttributedSegment> {
        self.segments
            .iter()
            .filter(|s| s.is_extraction_eligible())
            .collect()
    }

    /// Concatenated user-speech text. Used by the behavioral-style
    /// embedder (SPEC_profile_claim_guard §4) — only first-person text
    /// contributes to the style signature.
    pub fn collected_user_speech(&self) -> String {
        let mut out = String::new();
        for s in &self.segments {
            if s.attribution == Attribution::UserSpeech {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&s.segment.text);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(event_id: i64, origin: SegmentOrigin, text: &str) -> ConversationSegment {
        ConversationSegment {
            event_id,
            ts_ns: 0,
            origin,
            text: text.to_string(),
        }
    }

    fn att(seg: ConversationSegment, a: Attribution) -> AttributedSegment {
        AttributedSegment {
            segment: seg,
            attribution: a,
            confidence: 0.9,
            matched_signals: vec![],
        }
    }

    #[test]
    fn attribution_serde_roundtrip_uses_snake_case() {
        let serialised = serde_json::to_string(&Attribution::QuotedExternal).unwrap();
        assert_eq!(serialised, "\"quoted_external\"");
    }

    #[test]
    fn attribution_user_speech_is_only_eligible_class() {
        assert!(Attribution::UserSpeech.is_extraction_eligible());
        assert!(!Attribution::QuotedExternal.is_extraction_eligible());
        assert!(!Attribution::ToolOutput.is_extraction_eligible());
        assert!(!Attribution::Ambiguous.is_extraction_eligible());
    }

    #[test]
    fn has_user_speech_segments_detects_a_single_match() {
        let w = AttributedWindow {
            trigger_event_id: 1,
            segments: vec![
                att(
                    seg(1, SegmentOrigin::OperatorInbound, "hi"),
                    Attribution::QuotedExternal,
                ),
                att(
                    seg(2, SegmentOrigin::OperatorInbound, "yep"),
                    Attribution::UserSpeech,
                ),
            ],
        };
        assert!(w.has_user_speech_segments());
    }

    #[test]
    fn has_user_speech_segments_returns_false_when_only_quoted_or_tool() {
        let w = AttributedWindow {
            trigger_event_id: 1,
            segments: vec![
                att(
                    seg(1, SegmentOrigin::OperatorInbound, "hi"),
                    Attribution::QuotedExternal,
                ),
                att(
                    seg(2, SegmentOrigin::ProviderOutbound, "ack"),
                    Attribution::ToolOutput,
                ),
            ],
        };
        assert!(!w.has_user_speech_segments());
    }

    #[test]
    fn extraction_eligible_returns_only_user_speech() {
        let w = AttributedWindow {
            trigger_event_id: 1,
            segments: vec![
                att(
                    seg(1, SegmentOrigin::OperatorInbound, "yes"),
                    Attribution::UserSpeech,
                ),
                att(
                    seg(2, SegmentOrigin::OperatorInbound, "quote"),
                    Attribution::QuotedExternal,
                ),
                att(
                    seg(3, SegmentOrigin::ProviderOutbound, "ack"),
                    Attribution::ToolOutput,
                ),
            ],
        };
        let elig = w.extraction_eligible();
        assert_eq!(elig.len(), 1);
        assert_eq!(elig[0].segment.event_id, 1);
    }

    #[test]
    fn collected_user_speech_concatenates_eligible_text_only() {
        let w = AttributedWindow {
            trigger_event_id: 0,
            segments: vec![
                att(
                    seg(1, SegmentOrigin::OperatorInbound, "I work in Berlin"),
                    Attribution::UserSpeech,
                ),
                att(
                    seg(2, SegmentOrigin::OperatorInbound, "> external quote"),
                    Attribution::QuotedExternal,
                ),
                att(
                    seg(3, SegmentOrigin::OperatorInbound, "and I like Rust"),
                    Attribution::UserSpeech,
                ),
            ],
        };
        let collected = w.collected_user_speech();
        assert!(collected.contains("Berlin"));
        assert!(collected.contains("Rust"));
        assert!(!collected.contains("external quote"));
    }

    #[test]
    fn total_bytes_sums_segment_text_lengths() {
        let w = ConversationWindow {
            trigger_event_id: 1,
            turns_back: 2,
            segments: vec![
                seg(1, SegmentOrigin::OperatorInbound, "abc"),
                seg(2, SegmentOrigin::ProviderOutbound, "defgh"),
            ],
        };
        assert_eq!(w.total_bytes(), 8);
    }
}
