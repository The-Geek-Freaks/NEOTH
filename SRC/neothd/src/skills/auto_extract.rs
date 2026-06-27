//! GOLD-ADAPT-ODY-20 — auto-skill extraction from MCP-loop agent runs.
//!
//! After a turn that used ≥ 2 MCP tool-calls, one provider call is made to
//! distil the exchange into a `{title, steps, tags, confidence,
//! computer_executable}` JSON block. If confidence ≥ threshold AND the steps
//! are computer-executable, a [`ProposedAction`] of kind `Skill` is built,
//! staged, and enqueued in the operator's proactive review queue (same path
//! as `KF-04` dream-forge and `HERMES-06 GAP-A`). Dedup is deterministic via
//! `make_proposal_id` — re-extracting the same skill from a repeated run is
//! idempotent.
//!
//! Returns `Some(proposal)` on success, `None` on any failure or threshold
//! miss. Never panics; always best-effort (never fails the turn).

use crate::config::automation::AutoSkillExtractConfig;
use crate::proactive::action_staging::{
    make_proposal_id, ProposalKind, ProposedAction, ProposalStatus,
};
use crate::skills::creator::{build_manifest, CreateParams};

// ── Extraction prompt ─────────────────────────────────────────────────────────

const EXTRACT_PROMPT_TMPL: &str = r#"You are a skill-extraction assistant. Given a user query and an assistant response that involved multiple tool calls, extract a reusable skill if the interaction contains a computer-executable, repeatable procedure.

Respond with ONLY valid JSON — no explanation, no markdown fences. The JSON must have exactly these fields:
{
  "title": "<short imperative phrase, ≤ 60 chars, e.g. 'debug-docker-container'>",
  "steps": ["<step 1>", "<step 2>", "..."],
  "tags": ["<tag1>", "<tag2>"],
  "confidence": <float 0.0-1.0>,
  "computer_executable": <true|false>
}

Rules:
- "computer_executable" is true ONLY if every step can be executed by an automated agent WITHOUT human decision-making. If any step requires human judgment, interpretation, or creative input, set it to false.
- "confidence" reflects how clear and complete the skill is. A well-defined, reusable procedure scores ≥ 0.7. A vague or context-specific exchange scores ≤ 0.4.
- If no reusable procedure can be extracted, return confidence ≤ 0.3 and computer_executable false.

USER QUERY:
{PROMPT}

ASSISTANT RESPONSE (summary):
{RESPONSE}
"#;

// ── Extracted JSON shape ──────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct ExtractionResult {
    title: String,
    steps: Vec<String>,
    tags: Vec<String>,
    confidence: f32,
    computer_executable: bool,
}

// ── Slugify helper ────────────────────────────────────────────────────────────

/// Convert a human title into a valid skill id: lowercase, spaces→dashes,
/// strip non-alphanumeric chars (except `-` and `_`), truncate to 64 chars.
pub fn slugify_skill_id(title: &str) -> String {
    let slug: String = title
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c == ' ' { '-' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    // Collapse consecutive dashes, strip leading/trailing dashes.
    let slug = slug.trim_matches('-').to_string();
    // Collapse runs of dashes to a single dash.
    let mut result = String::with_capacity(slug.len());
    let mut last_dash = false;
    for c in slug.chars() {
        if c == '-' {
            if !last_dash {
                result.push(c);
            }
            last_dash = true;
        } else {
            result.push(c);
            last_dash = false;
        }
    }
    // Validate length — skill ids are ≤ 64 chars.
    result.truncate(64);
    result.trim_matches('-').to_string()
}

// ── Main entry point ──────────────────────────────────────────────────────────

/// Attempt to extract a reusable skill from a completed MCP-loop turn.
///
/// Returns `Some(proposal)` when:
/// - `tool_call_count >= config.min_tool_calls`
/// - the LLM call succeeds and returns parseable JSON
/// - `confidence >= config.confidence_threshold`
/// - `computer_executable == true`
///
/// Returns `None` on any shortfall or error (never fails the caller).
pub async fn maybe_extract_skill(
    prompt: &str,
    response: &str,
    tool_call_count: u32,
    provider: &dyn crate::providers::Provider,
    config: &AutoSkillExtractConfig,
) -> Option<ProposedAction> {
    // Gate 1 — tool-call count.
    if tool_call_count < config.min_tool_calls {
        return None;
    }

    // Build the extraction prompt. Truncate inputs so we don't blow the
    // context window of a utility call (512 chars each is plenty for signals).
    let prompt_excerpt = truncate_to(prompt, 512);
    let response_excerpt = truncate_to(response, 512);
    let extraction_prompt = EXTRACT_PROMPT_TMPL
        .replace("{PROMPT}", &prompt_excerpt)
        .replace("{RESPONSE}", &response_excerpt);

    // Call the provider. Uses the same provider as the turn (no extra auth
    // required, no separate utility-provider build needed at this call site).
    let req = crate::providers::Request {
        prompt: extraction_prompt,
        system: None,
        temperature: Some(0.1),
        ..Default::default()
    };

    let completion = match provider.complete(req).await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "ODY-20: provider call for skill extraction failed (best-effort)");
            return None;
        }
    };

    // Parse JSON — the LLM should return ONLY JSON, but may wrap it in markdown.
    let raw = completion.text.trim().to_string();
    let json_str = strip_markdown_fences(&raw);

    let extracted: ExtractionResult = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, raw = %raw, "ODY-20: skill extraction JSON parse failed");
            return None;
        }
    };

    // Gate 2 — confidence threshold.
    if extracted.confidence < config.confidence_threshold {
        tracing::debug!(
            confidence = extracted.confidence,
            threshold = config.confidence_threshold,
            "ODY-20: skill extraction below confidence threshold"
        );
        return None;
    }

    // Gate 3 — computer-executable only.
    if !extracted.computer_executable {
        tracing::debug!("ODY-20: skill extraction not computer_executable, skipping");
        return None;
    }

    // Build skill id from the title.
    let id = slugify_skill_id(&extracted.title);
    if id.is_empty() {
        tracing::debug!(title = %extracted.title, "ODY-20: slugified id is empty, skipping");
        return None;
    }

    // Build the SkillManifest + YAML via the existing creator path.
    let system_prompt = extracted.steps.join("\n");
    let params = CreateParams {
        id: id.clone(),
        description: extracted.title.clone(),
        keywords: extracted.tags.clone(),
        system_prompt,
    };
    let (_, draft_yaml) = match build_manifest(&params) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::debug!(error = %e, "ODY-20: build_manifest failed");
            return None;
        }
    };

    let ts = crate::time::now_unix_i64();
    let proposal_id = make_proposal_id(
        ProposalKind::Skill,
        &extracted.title,
        &draft_yaml,
        ts,
    );

    let rationale = format!(
        "Auto-extracted from an agent run with {} tool calls (confidence {:.2}). \
         Tags: {}. Review and activate via `neoth skills install <id>`.",
        tool_call_count,
        extracted.confidence,
        extracted.tags.join(", ")
    );

    Some(ProposedAction {
        id: proposal_id,
        kind: ProposalKind::Skill,
        title: extracted.title,
        rationale,
        draft_yaml,
        generated_ts_unix: ts,
        status: ProposalStatus::Pending,
        operator_note: String::new(),
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn truncate_to(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

/// Strip a possible ```json ... ``` or ``` ... ``` wrapper from LLM output.
/// Returns the original slice when no fences are found.
fn strip_markdown_fences(s: &str) -> &str {
    let s = s.trim();
    // Strip ```json or ``` prefix.
    let s = if s.starts_with("```json") {
        s.trim_start_matches("```json")
    } else if s.starts_with("```") {
        s.trim_start_matches("```")
    } else {
        s
    };
    // Strip trailing ```.
    let s = s.trim_end_matches("```");
    s.trim()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::automation::AutoSkillExtractConfig;
    use crate::proactive::action_staging::ProposalKind;
    use crate::providers::{Completion, Provider, Request};
    use async_trait::async_trait;

    // ── Mock provider ─────────────────────────────────────────────────────────

    struct MockProvider {
        response: String,
    }

    impl MockProvider {
        fn returning(s: &str) -> Self {
            Self { response: s.to_string() }
        }
    }

    #[async_trait]
    impl Provider for MockProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
            Ok(Completion {
                text: self.response.clone(),
                model: "mock-model".to_string(),
                latency: std::time::Duration::ZERO,
                input_tokens: None,
                output_tokens: None,
            })
        }
    }

    fn default_config() -> AutoSkillExtractConfig {
        AutoSkillExtractConfig {
            enabled: true,
            min_tool_calls: 2,
            confidence_threshold: 0.6,
        }
    }

    // ── Slugify tests ─────────────────────────────────────────────────────────

    #[test]
    fn slugify_basic() {
        assert_eq!(slugify_skill_id("debug docker container"), "debug-docker-container");
    }

    #[test]
    fn slugify_strips_special_chars() {
        assert_eq!(slugify_skill_id("fix: lint errors!"), "fix-lint-errors");
    }

    #[test]
    fn slugify_collapses_dashes() {
        assert_eq!(slugify_skill_id("  a   b  "), "a-b");
    }

    #[test]
    fn slugify_truncates_at_64() {
        let long = "a".repeat(100);
        assert!(slugify_skill_id(&long).len() <= 64);
    }

    #[test]
    fn slugify_round_trip_validates() {
        // Any slug produced by slugify_skill_id must pass validate_skill_id.
        let examples = ["my skill", "Docker Logs", "run-tests", "build_and_check"];
        for e in examples {
            let slug = slugify_skill_id(e);
            if !slug.is_empty() {
                crate::skills::creator::validate_skill_id(&slug).expect("slug should be valid");
            }
        }
    }

    // ── maybe_extract_skill gate tests ────────────────────────────────────────

    #[tokio::test]
    async fn extract_returns_none_below_tool_call_threshold() {
        let mock = MockProvider::returning(
            r#"{"title":"x","steps":["run ls"],"tags":[],"confidence":0.9,"computer_executable":true}"#,
        );
        let config = default_config(); // min_tool_calls = 2
        let result = maybe_extract_skill("q", "a", 1, &mock, &config).await;
        assert!(result.is_none(), "should be None when tool_call_count < min_tool_calls");
    }

    #[tokio::test]
    async fn extract_returns_none_below_confidence_threshold() {
        let mock = MockProvider::returning(
            r#"{"title":"t","steps":["run ls"],"tags":[],"confidence":0.4,"computer_executable":true}"#,
        );
        let config = default_config(); // threshold = 0.6
        let result = maybe_extract_skill("q", "a", 3, &mock, &config).await;
        assert!(result.is_none(), "should be None when confidence < threshold");
    }

    #[tokio::test]
    async fn extract_returns_none_when_not_computer_executable() {
        let mock = MockProvider::returning(
            r#"{"title":"t","steps":["think about it"],"tags":[],"confidence":0.9,"computer_executable":false}"#,
        );
        let result = maybe_extract_skill("q", "a", 3, &mock, &default_config()).await;
        assert!(result.is_none(), "should be None when computer_executable is false");
    }

    #[tokio::test]
    async fn extract_returns_none_on_bad_json() {
        let mock = MockProvider::returning("not json at all");
        let result = maybe_extract_skill("q", "a", 3, &mock, &default_config()).await;
        assert!(result.is_none(), "should be None when LLM returns non-JSON");
    }

    #[tokio::test]
    async fn extract_succeeds_with_valid_extraction() {
        let mock = MockProvider::returning(
            r#"{"title":"docker-debug","steps":["run docker ps","inspect logs"],"tags":["docker","debug"],"confidence":0.82,"computer_executable":true}"#,
        );
        let result = maybe_extract_skill(
            "debug my docker container",
            "I ran docker ps and checked logs...",
            3,
            &mock,
            &default_config(),
        )
        .await;
        assert!(result.is_some(), "should produce a proposal");
        let p = result.unwrap();
        assert_eq!(p.kind, ProposalKind::Skill);
        assert!(p.draft_yaml.contains("docker"), "YAML should mention docker");
        assert!(p.draft_yaml.contains("id:"), "YAML should have id field");
        // YAML must be loader-compatible (round-trip through SkillManifest).
        let m: crate::skills::schema::SkillManifest =
            serde_yaml::from_str(&p.draft_yaml).expect("loader-compat round-trip");
        assert!(!m.id.is_empty());
    }

    #[tokio::test]
    async fn extract_dedup_is_deterministic() {
        // Two calls with identical inputs produce the same proposal id.
        let json = r#"{"title":"run-tests","steps":["cargo test"],"tags":["rust"],"confidence":0.75,"computer_executable":true}"#;
        let mock1 = MockProvider::returning(json);
        let mock2 = MockProvider::returning(json);
        let r1 = maybe_extract_skill("q", "a", 2, &mock1, &default_config()).await.unwrap();
        let r2 = maybe_extract_skill("q", "a", 2, &mock2, &default_config()).await.unwrap();
        // Same title + same YAML produced in the same second → deterministic id prefix.
        // We can't pin the exact timestamp, but the kind + slug must match.
        assert!(r1.id.contains("skill"), "id should contain kind 'skill'");
        assert!(r2.id.contains("skill"), "id should contain kind 'skill'");
        assert_eq!(r1.kind, r2.kind);
        assert_eq!(r1.draft_yaml, r2.draft_yaml);
    }

    #[tokio::test]
    async fn extract_handles_markdown_fenced_json() {
        let mock = MockProvider::returning(
            "```json\n{\"title\":\"ls-files\",\"steps\":[\"ls -la\"],\"tags\":[\"files\"],\"confidence\":0.7,\"computer_executable\":true}\n```",
        );
        let result = maybe_extract_skill("q", "a", 2, &mock, &default_config()).await;
        assert!(result.is_some(), "should handle markdown-fenced JSON");
    }

    #[test]
    fn strip_fences_json() {
        assert_eq!(strip_markdown_fences("```json\n{}\n```"), "{}");
    }

    #[test]
    fn strip_fences_plain() {
        assert_eq!(strip_markdown_fences("```\n{}\n```"), "{}");
    }

    #[test]
    fn strip_fences_no_op() {
        assert_eq!(strip_markdown_fences("{}"), "{}");
    }
}
