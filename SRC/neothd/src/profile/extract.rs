//! Stage 3 — `profile.extract`. Schicht-0 LLM call that produces a
//! [`ProfileDelta`] from an [`AttributedWindow`].
//!
//! v0.1 surface: takes an existing Provider trait object, renders a
//! deterministic system prompt instructing the LLM to output strict
//! `ProfileDelta` JSON, parses the response. Temperature 0 + a hash-
//! derived seed mean the same window always produces the same delta
//! (G.1 conformance).
//!
//! What this stage does NOT do — they live downstream:
//!   - Schema validation (stage 4).
//!   - Redaction / quota / extension-registry / timestamp checks (stage 5).
//!   - WAL emission (stage 6).
//!
//! What this stage produces: a parsed `ProfileDelta`, including the
//! LLM's claim list. The validator + guard decide what survives.

use anyhow::{Context, Result};

use crate::profile::delta::ProfileDelta;
use crate::profile::types::{AttributedWindow, SegmentOrigin};
use crate::providers::{Provider, Request};

/// Conservative default — token budget per spec §profile_extract.
pub const DEFAULT_MAX_TOKENS: u32 = 800;

/// Compose the system prompt the extractor LLM sees. Deterministic over
/// the input — same window text always produces the same prompt.
///
/// The prompt:
///   1. States the goal (extract profile facts from operator first-
///      person speech ONLY).
///   2. Lists the categories the operator-fact taxonomy covers.
///   3. Pins the output format to strict JSON matching `ProfileDelta`.
///   4. Tells the LLM that quoted/forwarded/tool content is OFF-LIMITS
///      (the H1 constraint).
fn build_system_prompt() -> String {
    "You are NEOTH's profile-extraction subagent. Your only job is to read \
the operator's conversation window and emit a strict JSON object matching \
this schema:

{
  \"extraction_id\": string,         // uuid-like, generate one
  \"conversation_hash\": string,     // sha256 hex of the eligible segments
  \"claims\": [
    {
      \"field\": string,             // dot-path e.g. \"identity.location\"
      \"value_json\": <any>,         // the asserted value (string, number, bool, obj, arr)
      \"confidence\": number,         // [0.0, 1.0]
      \"reasoning\": string,         // why you believe this — cite the segment
      \"evidence_event_ids\": [int]  // event ids supporting the claim
    }
  ],
  \"contradictions\": [
    { \"field\": string, \"note\": string, \"existing_event_id\": int | null }
  ]
}

HARD RULES:
1. Only derive claims from segments marked attribution=user_speech.
2. Quoted/forwarded/tool-output content is OFF-LIMITS — even if the operator pasted a CV.
3. If no claims are extractable, return an empty claims array — that is valid.
4. Use ONLY these top-level categories: identity, preferences, relationships, \
skills, goals, health, schedule, emotional_baseline, operator_preferences.
5. Output ONLY the JSON object. No prose, no markdown fences."
        .to_string()
}

/// Render the window into the prompt the LLM sees. Each segment is
/// labelled with its attribution + event_id so the LLM can cite
/// evidence in `evidence_event_ids`.
fn render_user_prompt(window: &AttributedWindow) -> String {
    let mut out = String::from("CONVERSATION WINDOW:\n\n");
    for seg in &window.segments {
        let origin = match seg.segment.origin {
            SegmentOrigin::OperatorInbound => "operator-inbound",
            SegmentOrigin::ProviderOutbound => "provider-outbound",
            SegmentOrigin::Unknown => "unknown-origin",
        };
        out.push_str(&format!(
            "[event_id={} attribution={} origin={}]\n{}\n\n",
            seg.segment.event_id,
            seg.attribution.as_str(),
            origin,
            seg.segment.text,
        ));
    }
    out.push_str(
        "Extract the operator's profile claims from the user_speech segments \
only. Output the JSON object now:",
    );
    out
}

/// Strip an optional leading ```json ... ``` fence so the LLM-emit-JSON
/// path is forgiving of common LLM output styles. Returns the inner
/// JSON text on success.
fn strip_code_fence(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("```json") {
        return rest.trim_start().trim_end_matches("```").trim();
    }
    if let Some(rest) = trimmed.strip_prefix("```") {
        return rest.trim_start().trim_end_matches("```").trim();
    }
    trimmed
}

/// Best-effort JSON extraction: if the LLM ignored "only the JSON
/// object" and prefixed prose, find the first `{` and the matching
/// terminating `}` (depth-counted, ignoring strings).
fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let bytes = raw.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (idx, &b) in bytes.iter().enumerate().skip(start) {
        if escape {
            escape = false;
            continue;
        }
        match b {
            b'\\' if in_string => escape = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(&raw[start..=idx]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Invoke the extractor against the given provider. Returns the parsed
/// `ProfileDelta`. The caller is expected to feed this into stage 4
/// (validate) + stage 5 (guard) before applying anything.
pub async fn extract(provider: &dyn Provider, window: &AttributedWindow) -> Result<ProfileDelta> {
    // Short-circuit: if there are zero extraction-eligible segments,
    // skip the LLM call entirely. The spec says zero-claims is a valid
    // outcome; burning a paid provider call to confirm "nothing here"
    // is wasteful.
    if window.extraction_eligible().is_empty() {
        return Ok(ProfileDelta {
            extraction_id: stable_extraction_id(window),
            conversation_hash: stable_window_hash(window),
            claims: Vec::new(),
            ..Default::default()
        });
    }

    let req = Request {
        prompt: render_user_prompt(window),
        system: Some(build_system_prompt()),
        model: None,
        temperature: Some(0.0),
        top_p: None,
        sampling_seed: Some(seed_from_window(window)),
        stop_sequences: vec![],
    };
    let completion = provider
        .complete(req)
        .await
        .context("profile.extract: provider call")?;

    parse_delta(&completion.text, window)
}

/// Parse the LLM response into a [`ProfileDelta`]. Forgiving of common
/// LLM quirks (code-fence wrapping, prose-prefix). Returns a typed
/// error when the JSON is unrecoverable.
pub fn parse_delta(raw: &str, window: &AttributedWindow) -> Result<ProfileDelta> {
    let unfenced = strip_code_fence(raw);
    let candidate = extract_json_object(unfenced).unwrap_or(unfenced);
    let mut delta: ProfileDelta = serde_json::from_str(candidate).with_context(|| {
        format!(
            "profile.extract: parse JSON. First 200 bytes: {}",
            &candidate.chars().take(200).collect::<String>()
        )
    })?;
    // Fill in any required fields the LLM might have skipped.
    if delta.extraction_id.trim().is_empty() {
        delta.extraction_id = stable_extraction_id(window);
    }
    if delta.conversation_hash.trim().is_empty() {
        delta.conversation_hash = stable_window_hash(window);
    }
    Ok(delta)
}

/// Deterministic seed derived from the user-speech text the LLM sees.
/// G.1: same input → same seed → same output (subject to provider
/// honouring the seed).
fn seed_from_window(window: &AttributedWindow) -> u64 {
    let user_speech: String = window
        .extraction_eligible()
        .iter()
        .map(|s| s.segment.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    xxhash_rust::xxh3::xxh3_64(user_speech.as_bytes())
}

/// Stable extraction id derived from the trigger + first event_id.
/// Used when the LLM forgets to populate it (or short-circuit path
/// when there's nothing to extract).
fn stable_extraction_id(window: &AttributedWindow) -> String {
    format!(
        "ext-{}-{}",
        window.trigger_event_id,
        first_eligible_event_id(window).unwrap_or(0)
    )
}

fn stable_window_hash(window: &AttributedWindow) -> String {
    let bytes: String = window
        .segments
        .iter()
        .map(|s| s.segment.text.clone())
        .collect::<Vec<_>>()
        .join("\u{1F}");
    format!("{:016x}", xxhash_rust::xxh3::xxh3_64(bytes.as_bytes()))
}

fn first_eligible_event_id(window: &AttributedWindow) -> Option<i64> {
    window
        .extraction_eligible()
        .first()
        .map(|s| s.segment.event_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::types::{
        AttributedSegment, Attribution, ConversationSegment, SegmentOrigin,
    };
    use crate::providers::{Completion, Provider, Request};
    use async_trait::async_trait;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Mock provider that returns a fixed reply, records the most-recent
    /// request for inspection.
    struct MockProvider {
        reply: String,
        last_request: Mutex<Option<Request>>,
    }

    impl MockProvider {
        fn new(reply: impl Into<String>) -> Self {
            Self {
                reply: reply.into(),
                last_request: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl Provider for MockProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn complete(&self, req: Request) -> anyhow::Result<Completion> {
            *self.last_request.lock().unwrap() = Some(req);
            Ok(Completion {
                text: self.reply.clone(),
                model: "mock-1".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(10),
                output_tokens: Some(20),
            })
        }
    }

    fn segment(event_id: i64, attribution: Attribution, text: &str) -> AttributedSegment {
        AttributedSegment {
            segment: ConversationSegment {
                event_id,
                ts_ns: 0,
                origin: SegmentOrigin::OperatorInbound,
                text: text.into(),
            },
            attribution,
            confidence: 0.9,
            matched_signals: vec![],
        }
    }

    fn user_speech_window() -> AttributedWindow {
        AttributedWindow {
            trigger_event_id: 100,
            segments: vec![segment(
                10,
                Attribution::UserSpeech,
                "I work as a security researcher in Berlin",
            )],
        }
    }

    fn quoted_only_window() -> AttributedWindow {
        AttributedWindow {
            trigger_event_id: 100,
            segments: vec![segment(
                11,
                Attribution::QuotedExternal,
                "> someone pasted a CV here",
            )],
        }
    }

    const VALID_JSON_REPLY: &str = r#"{
  "extraction_id": "ext-abc",
  "conversation_hash": "deadbeef",
  "claims": [
    {
      "field": "identity.location",
      "value_json": "Berlin",
      "confidence": 0.9,
      "reasoning": "Alex said he works in Berlin",
      "evidence_event_ids": [10]
    }
  ],
  "contradictions": []
}"#;

    #[tokio::test]
    async fn extract_skips_llm_when_no_eligible_segments() {
        let provider = MockProvider::new("should never be returned");
        let delta = extract(&provider, &quoted_only_window()).await.unwrap();
        assert!(delta.claims.is_empty());
        // The mock should NOT have received a request.
        assert!(provider.last_request.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn extract_parses_valid_json_reply() {
        let provider = MockProvider::new(VALID_JSON_REPLY);
        let delta = extract(&provider, &user_speech_window()).await.unwrap();
        assert_eq!(delta.extraction_id, "ext-abc");
        assert_eq!(delta.claims.len(), 1);
        assert_eq!(delta.claims[0].field, "identity.location");
        // Request used temperature 0 + a deterministic seed.
        let req = provider.last_request.lock().unwrap().clone().unwrap();
        assert_eq!(req.temperature, Some(0.0));
        assert!(req.sampling_seed.is_some());
    }

    #[tokio::test]
    async fn extract_seed_is_deterministic_across_runs() {
        let provider_1 = MockProvider::new(VALID_JSON_REPLY);
        let provider_2 = MockProvider::new(VALID_JSON_REPLY);
        let _ = extract(&provider_1, &user_speech_window()).await.unwrap();
        let _ = extract(&provider_2, &user_speech_window()).await.unwrap();
        let seed_1 = provider_1
            .last_request
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .sampling_seed
            .unwrap();
        let seed_2 = provider_2
            .last_request
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .sampling_seed
            .unwrap();
        assert_eq!(seed_1, seed_2, "same input must produce same seed");
    }

    #[test]
    fn parse_delta_handles_code_fenced_json() {
        let raw =
            "```json\n{\"extraction_id\":\"x\",\"conversation_hash\":\"y\",\"claims\":[]}\n```";
        let d = parse_delta(raw, &user_speech_window()).unwrap();
        assert_eq!(d.extraction_id, "x");
        assert!(d.claims.is_empty());
    }

    #[test]
    fn parse_delta_handles_prose_prefixed_json() {
        let raw = "Sure, here's the result: {\"extraction_id\":\"x\",\"conversation_hash\":\"y\",\"claims\":[]} hope that helps!";
        let d = parse_delta(raw, &user_speech_window()).unwrap();
        assert_eq!(d.extraction_id, "x");
    }

    #[test]
    fn parse_delta_fills_missing_extraction_id_from_window() {
        let raw = r#"{"extraction_id":"","conversation_hash":"","claims":[]}"#;
        let d = parse_delta(raw, &user_speech_window()).unwrap();
        assert_eq!(d.extraction_id, "ext-100-10");
        assert!(!d.conversation_hash.is_empty());
    }

    #[test]
    fn parse_delta_fails_on_unrecoverable_json() {
        let raw = "definitely not json at all";
        let err = parse_delta(raw, &user_speech_window()).unwrap_err();
        assert!(err.to_string().contains("parse JSON"));
    }

    #[test]
    fn strip_code_fence_removes_prefix_and_suffix() {
        assert_eq!(strip_code_fence("```json\n{}\n```"), "{}");
        assert_eq!(strip_code_fence("```\n{}\n```"), "{}");
        assert_eq!(strip_code_fence("plain"), "plain");
    }

    #[test]
    fn extract_json_object_handles_nested_braces_and_strings() {
        let raw = "noise {\"a\":\"} fake {\",\"b\":{\"c\":1}} trailing";
        let extracted = extract_json_object(raw).unwrap();
        // Should extract just the outer object — strings with } don't trip
        // the brace counter.
        assert!(extracted.starts_with('{'));
        assert!(extracted.ends_with('}'));
        let parsed: serde_json::Value = serde_json::from_str(extracted).unwrap();
        assert_eq!(parsed["b"]["c"], 1);
    }

    #[test]
    fn extract_json_object_returns_none_when_no_object_present() {
        assert!(extract_json_object("definitely no braces").is_none());
    }

    #[test]
    fn build_system_prompt_includes_hard_rules() {
        let p = build_system_prompt();
        assert!(p.contains("user_speech"));
        assert!(p.contains("HARD RULES"));
        assert!(p.contains("Quoted/forwarded/tool-output content is OFF-LIMITS"));
    }

    #[test]
    fn render_user_prompt_labels_every_segment() {
        let w = AttributedWindow {
            trigger_event_id: 1,
            segments: vec![
                segment(1, Attribution::UserSpeech, "I love Rust"),
                segment(2, Attribution::QuotedExternal, "> paste"),
            ],
        };
        let p = render_user_prompt(&w);
        assert!(p.contains("event_id=1"));
        assert!(p.contains("attribution=user_speech"));
        assert!(p.contains("attribution=quoted_external"));
    }
}
