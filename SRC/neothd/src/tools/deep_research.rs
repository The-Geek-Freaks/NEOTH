//! GOLD-ADAPT-ODY-17 — iterative deep-research engine.
//!
//! Implements a multi-step search→read→synthesize loop that:
//! 1. Uses an LLM call to decompose the operator's topic into N sub-queries.
//! 2. For each round: calls `web_search::search_cached` → fetches up to
//!    `pages_per_round` URLs via `web_fetch::fetch_with_goal` → serializes every
//!    page as typed `Web` data before handing it to the LLM → accumulates
//!    evidence + citations.
//! 3. After each round asks the LLM whether the evidence is sufficient;
//!    if yes, or after `max_rounds`, runs a final synthesis pass.
//! 4. Emits WAL `0x6B DEEP_RESEARCH_STARTED` / `0x6C DEEP_RESEARCH_COMPLETED`.
//!
//! The generic model-planned engine is called from `cli/chat.rs`. The pinned
//! channel operator's explicit external release uses a separate deterministic,
//! one-request search path below; it never hands model output to HTTP.

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::pipeline::{RenderedUntrustedContext, UntrustedContext, UntrustedContextClass};
use crate::providers::{Provider, Request};
use crate::secret::SecretString;
use crate::tools::web_fetch;
use crate::tools::web_search::{self, Provider as SearchProvider, SearchHit};
use crate::wal::writer::WalWriterHandle;

// ── Compiled-in defaults (all operator-overrideable via DeepResearchConfig) ──

const DEFAULT_MAX_ROUNDS: u8 = 5;
const DEFAULT_RESULTS_PER_QUERY: usize = 5;
const DEFAULT_PAGES_PER_ROUND: usize = 3;

/// Byte ceiling on accumulated evidence fed to each synthesis/continue prompt.
/// Keeps the context window cost bounded; older rounds are truncated first.
const MAX_EVIDENCE_BYTES: usize = 24_000;

/// Char ceiling on text from a single page before it is truncated in the
/// evidence buffer. Matches `web_fetch::MAX_EXTRACTED_BYTES / 10` —
/// research pages contribute a summary, not the raw dump.
const MAX_PAGE_EVIDENCE_CHARS: usize = 2_000;

/// Hard security boundary for the explicit channel release. This path issues
/// exactly one search request with the normalized operator topic and never
/// enables model-planned queries or follow-up page fetches.
const MAX_RELEASED_RESEARCH_RESULTS: usize = 5;
const MAX_RELEASED_RESULT_TITLE_CHARS: usize = 180;
const MAX_RELEASED_RESULT_SNIPPET_CHARS: usize = 600;
const MAX_RELEASED_RESULT_URL_BYTES: usize = 2_048;

// ── Public surface types ───────────────────────────────────────────────────

/// A single source cited in the research report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CitedSource {
    pub title: String,
    pub url: String,
}

/// The output of a completed deep-research run.
#[derive(Debug, Clone)]
pub struct ResearchReport {
    /// The full synthesised article (Markdown).
    pub article: String,
    /// Sources cited in the article, in discovery order.
    pub citations: Vec<CitedSource>,
}

// ── Runtime budget (resolved once per call from config + defaults) ─────────

struct Budget {
    max_rounds: u8,
    results_per_query: usize,
    pages_per_round: usize,
}

impl Budget {
    fn from_config(cfg: &crate::config::DeepResearchConfig) -> Self {
        Self {
            max_rounds: cfg.max_rounds.unwrap_or(DEFAULT_MAX_ROUNDS).max(1),
            results_per_query: cfg
                .results_per_query
                .unwrap_or(DEFAULT_RESULTS_PER_QUERY)
                .clamp(1, 20),
            pages_per_round: cfg
                .pages_per_round
                .unwrap_or(DEFAULT_PAGES_PER_ROUND)
                .max(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleasedChannelResearchPlan {
    query: String,
    max_results: usize,
}

impl ReleasedChannelResearchPlan {
    fn for_exact_topic(topic: &str) -> Result<Self> {
        let topic = topic.trim();
        if topic.is_empty() {
            anyhow::bail!("released channel research topic is empty");
        }
        if topic.len() > crate::permissions::ifc::MAX_OPERATOR_RELEASED_RESEARCH_TOPIC_BYTES {
            anyhow::bail!(
                "released channel research topic exceeds the {}-byte limit",
                crate::permissions::ifc::MAX_OPERATOR_RELEASED_RESEARCH_TOPIC_BYTES
            );
        }
        Ok(Self {
            query: topic.to_owned(),
            max_results: MAX_RELEASED_RESEARCH_RESULTS,
        })
    }
}

// ── Main entry point ───────────────────────────────────────────────────────

/// Execute the pinned channel operator's explicit external research release.
///
/// Unlike [`run_deep_research`], this capability-scoped path performs one
/// deterministic search whose query bytes equal the normalized released topic.
/// It does not call an LLM, accept model-generated subqueries, use the shared
/// search cache/analytics store, or fetch result URLs. Hard caps remain
/// compiled in rather than operator-configurable so one release cannot widen
/// into an unbounded HTTP session.
pub async fn run_operator_released_channel_research(
    topic: &str,
    search_key: &SecretString,
    search_provider: SearchProvider,
    writer: &WalWriterHandle,
    http: &crate::tools::external_http::ExternalHttpAuthorizer,
) -> Result<ResearchReport> {
    let plan = ReleasedChannelResearchPlan::for_exact_topic(topic)?;
    let release_id = http
        .arm_operator_released_exact_topic(&plan.query)
        .context("released channel research requires an unused exact-topic release")?;

    emit_released_research_started(writer, &release_id)
        .await
        .context("append mandatory released research start frame")?;
    info!(
        research_release_id = %release_id,
        topic_len = plan.query.len(),
        max_results = plan.max_results,
        "released channel research: starting bounded exact-topic search"
    );

    let hits = match web_search::search_authorized(
        search_provider,
        search_key,
        &plan.query,
        plan.max_results,
        http,
    )
    .await
    {
        Ok(hits) => hits,
        Err(error) => {
            if let Err(audit) =
                emit_released_research_completed(writer, &release_id, "failure", 0).await
            {
                return Err(anyhow::anyhow!(
                    "released channel research search failed: {error:#}; terminal audit also failed: {audit:#}"
                ));
            }
            return Err(error).context("released channel research exact-topic search failed");
        }
    };

    let report = render_released_search_report(hits);
    emit_released_research_completed(writer, &release_id, "success", report.citations.len())
        .await
        .context("append mandatory released research completion frame")?;
    info!(
        research_release_id = %release_id,
        result_count = report.citations.len(),
        "released channel research: bounded search complete"
    );
    Ok(report)
}

fn render_released_search_report(hits: Vec<SearchHit>) -> ResearchReport {
    let mut article = String::from(
        "# Released external research results\n\n\
         This bounded path used the exact operator-released topic for one search. \
         It did not run model planning or fetch result pages.\n",
    );
    let mut citations = Vec::new();

    for hit in hits.into_iter().take(MAX_RELEASED_RESEARCH_RESULTS) {
        let Ok(parsed) = url::Url::parse(&hit.url) else {
            continue;
        };
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            continue;
        }
        let canonical_url = parsed.to_string();
        if canonical_url.len() > MAX_RELEASED_RESULT_URL_BYTES {
            continue;
        }

        let title = compact_released_result_text(&hit.title, MAX_RELEASED_RESULT_TITLE_CHARS);
        let snippet = compact_released_result_text(&hit.snippet, MAX_RELEASED_RESULT_SNIPPET_CHARS);
        let title = if title.is_empty() {
            "Untitled public result".to_owned()
        } else {
            title
        };
        let number = citations.len() + 1;
        article.push_str(&format!("\n## Result {number}: {title}\n"));
        if !snippet.is_empty() {
            article.push_str(&format!("\n{snippet}\n"));
        }
        citations.push(CitedSource {
            title,
            url: canonical_url,
        });
    }

    if citations.is_empty() {
        article.push_str("\nNo valid public HTTP(S) search results were returned.\n");
    }
    ResearchReport { article, citations }
}

fn compact_released_result_text(input: &str, max_chars: usize) -> String {
    let mut output = String::new();
    let mut pending_space = false;
    let mut written = 0usize;
    for character in input.chars() {
        if character.is_control() || is_invisible_format_character(character) {
            continue;
        }
        if character.is_whitespace() {
            pending_space = !output.is_empty();
            continue;
        }
        if pending_space {
            if written >= max_chars.saturating_sub(1) {
                break;
            }
            output.push(' ');
            written += 1;
            pending_space = false;
        }
        let escape_markdown = matches!(
            character,
            '\\' | '`'
                | '*'
                | '_'
                | '{'
                | '}'
                | '['
                | ']'
                | '('
                | ')'
                | '<'
                | '>'
                | '#'
                | '+'
                | '-'
                | '.'
                | '!'
                | '|'
                | '~'
        );
        let required = usize::from(escape_markdown) + 1;
        if written.saturating_add(required) > max_chars {
            break;
        }
        if escape_markdown {
            output.push('\\');
            written += 1;
        }
        output.push(character);
        written += 1;
    }
    output
}

fn is_invisible_format_character(character: char) -> bool {
    matches!(
        character as u32,
        0x061c
            | 0x200b..=0x200f
            | 0x202a..=0x202e
            | 0x2060..=0x206f
            | 0xfeff
    )
}

/// Run a multi-step deep-research loop on `topic`.
///
/// * `provider`        — LLM provider for plan/synthesis/continue calls.
/// * `search_key`      — API key for the search provider (empty for SearXNG).
/// * `search_provider` — Which search backend to use.
/// * `budget`          — Operator-tunable iteration caps.
/// * `writer`          — WAL writer for audit frames.
///
/// Returns a [`ResearchReport`] on success. Network errors on individual
/// pages are logged at `warn` and skipped rather than aborting the run.
pub async fn run_deep_research(
    topic: &str,
    provider: &dyn Provider,
    search_key: &SecretString,
    search_provider: SearchProvider,
    budget: &crate::config::DeepResearchConfig,
    writer: &WalWriterHandle,
    http: &crate::tools::external_http::ExternalHttpAuthorizer,
) -> Result<ResearchReport> {
    let budget = Budget::from_config(budget);

    // ── WAL: DEEP_RESEARCH_STARTED ─────────────────────────────────────────
    // xxh3 matches the pattern used by all other WAL payload hashes in chat.rs;
    // formatted as 16-char hex so log grepping works the same way.
    let topic_hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(topic.as_bytes()));
    emit_wal_started(writer, &topic_hash).await;

    info!(topic_hash = %topic_hash, max_rounds = budget.max_rounds, "deep_research: starting");

    // ── Step 1: Plan — LLM decomposes the topic into sub-queries ──────────
    let queries = plan_queries(topic, provider).await.unwrap_or_else(|e| {
        warn!(error = %e, "deep_research: plan call failed; using single-query fallback");
        vec![topic.to_string()]
    });
    debug!(queries = ?queries, "deep_research: planned sub-queries");

    // ── Step 2: Round loop ─────────────────────────────────────────────────
    let mut all_evidence: Vec<RenderedUntrustedContext> = Vec::new();
    let mut citations: Vec<CitedSource> = Vec::new();
    let mut rounds_done: u8 = 0;

    for (round_idx, query) in queries.iter().enumerate().take(budget.max_rounds as usize) {
        rounds_done += 1;
        eprintln!(
            "\n[deep-research] round {}/{} — searching: {}",
            rounds_done, budget.max_rounds, query
        );

        let round_evidence = research_round(
            query,
            topic,
            provider,
            search_key,
            search_provider,
            &budget,
            http,
        )
        .await;

        match round_evidence {
            Ok((evidence_blocks, new_citations)) => {
                all_evidence.extend(evidence_blocks);
                citations.extend(new_citations);
            }
            Err(e) => {
                warn!(round = round_idx, error = %e, "deep_research: round failed; continuing");
            }
        }

        // ── Step 2c: Continue-check — should we stop early? ───────────────
        if rounds_done < budget.max_rounds {
            let satisfied = check_satisfied(
                topic,
                &all_evidence,
                rounds_done,
                budget.max_rounds,
                provider,
            )
            .await
            .unwrap_or(false);
            if satisfied {
                info!(
                    rounds = rounds_done,
                    "deep_research: LLM satisfied — stopping early"
                );
                break;
            }
        }
    }

    eprintln!(
        "\n[deep-research] synthesising {} evidence blocks…",
        all_evidence.len()
    );

    // ── Step 3: Synthesis ─────────────────────────────────────────────────
    let article = synthesize(topic, &all_evidence, &citations, provider)
        .await
        .context("deep_research: synthesis LLM call failed")?;

    let word_count = article.split_whitespace().count();
    let citation_count = citations.len();

    // ── WAL: DEEP_RESEARCH_COMPLETED ──────────────────────────────────────
    emit_wal_completed(writer, &topic_hash, rounds_done, word_count, citation_count).await;

    info!(
        topic_hash = %topic_hash,
        rounds = rounds_done,
        words = word_count,
        citations = citation_count,
        "deep_research: complete"
    );

    Ok(ResearchReport { article, citations })
}

// ── LLM sub-calls ─────────────────────────────────────────────────────────

/// Ask the LLM to produce 3-5 focused search queries that together cover
/// the topic. Returns a `Vec<String>`; on parse failure falls back to the
/// topic itself (handled by the caller).
async fn plan_queries(topic: &str, provider: &dyn Provider) -> Result<Vec<String>> {
    const PLAN_SYSTEM: &str = "You are a senior research librarian. \
Given a research topic, produce 3 to 5 focused search queries that together \
cover different angles. Respond ONLY with a JSON array of strings — no \
markdown, no extra keys. Example: [\"query one\", \"query two\", \"query three\"]";

    let req = Request {
        prompt: format!("Research topic: {topic}"),
        system: Some(PLAN_SYSTEM.to_string()),
        ..Request::default()
    };
    let completion = provider
        .complete(req)
        .await
        .context("deep_research plan: LLM call failed")?;

    let raw = completion.text.trim();
    // Strip optional markdown fences
    let stripped = raw
        .strip_prefix("```json")
        .or_else(|| raw.strip_prefix("```"))
        .map(|s| s.trim_start())
        .and_then(|s| s.strip_suffix("```"))
        .map(|s| s.trim_end())
        .unwrap_or(raw);

    let queries: Vec<String> = serde_json::from_str(stripped)
        .context("deep_research plan: LLM returned non-array JSON")?;

    if queries.is_empty() {
        anyhow::bail!("deep_research plan: LLM returned empty query list");
    }
    Ok(queries)
}

/// Execute one research round: search → fetch pages → goal-extract → fence.
/// Returns `(evidence_blocks, new_citations)`.
async fn research_round(
    query: &str,
    topic: &str,
    provider: &dyn Provider,
    search_key: &SecretString,
    search_provider: SearchProvider,
    budget: &Budget,
    http: &crate::tools::external_http::ExternalHttpAuthorizer,
) -> Result<(Vec<RenderedUntrustedContext>, Vec<CitedSource>)> {
    let hits = web_search::search_cached_authorized(
        search_provider,
        search_key,
        query,
        budget.results_per_query,
        http,
    )
    .await
    .context("deep_research: web_search failed")?;

    if hits.is_empty() {
        debug!(query = query, "deep_research: no search hits for query");
        return Ok((vec![], vec![]));
    }

    let mut evidence_blocks: Vec<RenderedUntrustedContext> = Vec::new();
    let mut new_citations: Vec<CitedSource> = Vec::new();

    for hit in hits.iter().take(budget.pages_per_round) {
        match web_fetch::fetch_with_goal_authorized(&hit.url, topic, provider, http).await {
            Ok(extraction) => {
                if extraction.summary.is_empty() && extraction.evidence.is_empty() {
                    debug!(url = %hit.url, "deep_research: page not relevant; skipping");
                    continue;
                }

                // Build a concise evidence block from the goal extraction
                let mut page_block = String::new();
                if !extraction.rational.is_empty() {
                    page_block.push_str(&extraction.rational);
                    page_block.push('\n');
                }
                for ev in &extraction.evidence {
                    page_block.push_str("• ");
                    page_block.push_str(ev);
                    page_block.push('\n');
                }
                if !extraction.summary.is_empty() {
                    page_block.push_str(&extraction.summary);
                }

                // Truncate to per-page ceiling
                let truncated: String = page_block.chars().take(MAX_PAGE_EVIDENCE_CHARS).collect();

                let fenced = UntrustedContext::new(
                    UntrustedContextClass::Web,
                    format!("deep-research:web:{}", hit.url),
                    &truncated,
                )
                .render();

                evidence_blocks.push(fenced);
                new_citations.push(CitedSource {
                    title: hit.title.clone(),
                    url: hit.url.clone(),
                });
            }
            Err(e) => {
                warn!(url = %hit.url, error = %e, "deep_research: page fetch/extract failed; skipping");
            }
        }
    }

    Ok((evidence_blocks, new_citations))
}

/// Ask the LLM whether the accumulated evidence is already sufficient to
/// write a complete answer to the topic. Returns `true` = satisfied.
async fn check_satisfied(
    topic: &str,
    evidence: &[RenderedUntrustedContext],
    rounds_done: u8,
    max_rounds: u8,
    provider: &dyn Provider,
) -> Result<bool> {
    const CONTINUE_SYSTEM: &str = "You are a research director. \
Given a research topic, the evidence collected so far, and how many rounds have \
been completed, decide whether the evidence is sufficient to write a comprehensive \
answer. Respond ONLY with the single JSON boolean true or false.";

    // Feed a truncated view of evidence to keep token cost low
    let evidence_preview = truncate_evidence(evidence, MAX_EVIDENCE_BYTES / 2);

    let req = Request {
        prompt: format!(
            "Research topic: {topic}\n\nRounds completed: {rounds_done}/{max_rounds}\n\n\
             Evidence so far:\n{evidence_preview}\n\n\
             Is this evidence sufficient? Respond only with true or false."
        ),
        system: Some(CONTINUE_SYSTEM.to_string()),
        ..Request::default()
    };

    let completion = provider
        .complete(req)
        .await
        .context("deep_research continue-check: LLM call failed")?;

    let raw = completion.text.trim().to_lowercase();
    Ok(raw.starts_with("true"))
}

/// Run the final synthesis pass and return the full article text.
async fn synthesize(
    topic: &str,
    evidence: &[RenderedUntrustedContext],
    citations: &[CitedSource],
    provider: &dyn Provider,
) -> Result<String> {
    const SYNTH_SYSTEM: &str = "You are an expert research writer. \
Given a topic and evidence collected from multiple web sources, write a \
comprehensive, well-structured article (at least 800 words). \
Cite your sources inline as [1], [2], etc. using the source numbers provided. \
Use Markdown headings. Be factual, accurate, and analytical.";

    let evidence_block = truncate_evidence(evidence, MAX_EVIDENCE_BYTES);

    let citation_list: String = citations
        .iter()
        .enumerate()
        .map(|(i, c)| format!("[{}] {} — {}", i + 1, c.title, c.url))
        .collect::<Vec<_>>()
        .join("\n");
    let citation_context = UntrustedContext::with_payload_limit(
        UntrustedContextClass::Web,
        "deep-research:citations",
        citation_list,
        MAX_EVIDENCE_BYTES / 2,
    )
    .render()
    .fit_to_wire_limit(MAX_EVIDENCE_BYTES / 2)
    .ok_or_else(|| anyhow::anyhow!("citation envelope cannot fit the synthesis wire budget"))?;
    let citation_list = citation_context.as_str();

    let req = Request {
        prompt: format!(
            "Research topic: {topic}\n\n\
             Available sources:\n{citation_list}\n\n\
             Collected evidence:\n{evidence_block}\n\n\
             Write the comprehensive research article now."
        ),
        system: Some(SYNTH_SYSTEM.to_string()),
        ..Request::default()
    };

    let completion = provider
        .complete(req)
        .await
        .context("deep_research synthesis: LLM call failed")?;

    Ok(completion.text)
}

// ── WAL helpers ───────────────────────────────────────────────────────────

fn released_research_started_payload(release_id: &str) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "research_release_id": release_id,
        "status": "started",
        "ts_unix": crate::time::now_unix_secs(),
    }))
    .context("serialise released channel research start payload")
}

fn released_research_completed_payload(
    release_id: &str,
    status: &str,
    result_count: usize,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "research_release_id": release_id,
        "status": status,
        "result_count": result_count,
        "ts_unix": crate::time::now_unix_secs(),
    }))
    .context("serialise released channel research completion payload")
}

async fn emit_released_research_started(writer: &WalWriterHandle, release_id: &str) -> Result<()> {
    let payload = released_research_started_payload(release_id)?;
    let header = crate::wal::make_header(
        crate::wal::events::EVENT_TYPE_DEEP_RESEARCH_STARTED,
        &payload,
    );
    writer
        .append(header, payload)
        .await
        .context("append released channel research start")
        .map(|_| ())
}

async fn emit_released_research_completed(
    writer: &WalWriterHandle,
    release_id: &str,
    status: &str,
    result_count: usize,
) -> Result<()> {
    let payload = released_research_completed_payload(release_id, status, result_count)?;
    let header = crate::wal::make_header(
        crate::wal::events::EVENT_TYPE_DEEP_RESEARCH_COMPLETED,
        &payload,
    );
    writer
        .append(header, payload)
        .await
        .context("append released channel research completion")
        .map(|_| ())
}

async fn emit_wal_started(writer: &WalWriterHandle, topic_hash: &str) {
    let payload = match serde_json::to_vec(&serde_json::json!({
        "topic_hash": topic_hash,
        "ts_unix": crate::time::now_unix_secs(),
    })) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "deep_research: failed to serialise DEEP_RESEARCH_STARTED payload");
            return;
        }
    };
    let header = crate::wal::make_header(
        crate::wal::events::EVENT_TYPE_DEEP_RESEARCH_STARTED,
        &payload,
    );
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "deep_research: WAL DEEP_RESEARCH_STARTED write failed");
    }
}

async fn emit_wal_completed(
    writer: &WalWriterHandle,
    topic_hash: &str,
    rounds: u8,
    word_count: usize,
    citation_count: usize,
) {
    let payload = match serde_json::to_vec(&serde_json::json!({
        "topic_hash": topic_hash,
        "rounds": rounds,
        "word_count": word_count,
        "citation_count": citation_count,
        "ts_unix": crate::time::now_unix_secs(),
    })) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "deep_research: failed to serialise DEEP_RESEARCH_COMPLETED payload");
            return;
        }
    };
    let header = crate::wal::make_header(
        crate::wal::events::EVENT_TYPE_DEEP_RESEARCH_COMPLETED,
        &payload,
    );
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "deep_research: WAL DEEP_RESEARCH_COMPLETED write failed");
    }
}

// ── Utility ───────────────────────────────────────────────────────────────

/// Concatenate complete canonical evidence blocks within a wire-byte budget.
/// Newest evidence wins; an older boundary block is re-rendered from a shorter
/// raw payload rather than slicing its serialized JSON/header/footer.
fn truncate_evidence(evidence: &[RenderedUntrustedContext], max_bytes: usize) -> String {
    let mut selected = Vec::new();
    let mut remaining = max_bytes;
    for block in evidence.iter().rev() {
        let separator = usize::from(!selected.is_empty());
        if block.as_str().len() + separator <= remaining {
            remaining -= block.as_str().len() + separator;
            selected.push(block.clone());
            continue;
        }

        let available = remaining.saturating_sub(separator);
        if let Some(fitted) = block.fit_to_wire_limit(available) {
            selected.push(fitted);
        }
        break;
    }

    selected.reverse();
    selected
        .iter()
        .map(RenderedUntrustedContext::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Key resolution helpers (shared by chat.rs and serve_pipeline.rs) ──────

/// Resolve the web-search API key using the same pattern as `cli/search.rs`:
/// 1. `NEOTH_WEB_SEARCH_KEY` env var
/// 2. empty string (for keyless providers like SearXNG)
///
/// Callers that need to bail on missing keys (for paid providers) should call
/// `resolve_search_key_required` instead.
pub fn resolve_search_key_optional() -> SecretString {
    std::env::var("NEOTH_WEB_SEARCH_KEY")
        .map(SecretString::from)
        .unwrap_or_else(|_| SecretString::from(String::new()))
}

/// Resolve the web-search API key, bailing if the provider needs one and
/// none is configured. Mirrors `cli/search.rs:58-70`.
pub fn resolve_search_key(provider: SearchProvider) -> Result<SecretString> {
    if !provider.needs_api_key() {
        return Ok(SecretString::from(String::new()));
    }
    match std::env::var("NEOTH_WEB_SEARCH_KEY") {
        Ok(k) => Ok(SecretString::from(k)),
        Err(_) => anyhow::bail!(
            "no API key for web search. Pass NEOTH_WEB_SEARCH_KEY env var \
             or add `web_search_key` to credentials.yaml."
        ),
    }
}

/// Resolve the search provider from the env var or default to Brave.
pub fn resolve_search_provider() -> SearchProvider {
    std::env::var("NEOTH_WEB_SEARCH_PROVIDER")
        .ok()
        .and_then(|s| SearchProvider::from_str(&s))
        .unwrap_or(SearchProvider::Brave)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Completion, Provider, Request};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Deterministic provider that cycles through a list of canned responses.
    struct CycleProvider {
        responses: Vec<String>,
        cursor: Arc<AtomicUsize>,
        prompts: Arc<Mutex<Vec<String>>>,
    }

    impl CycleProvider {
        fn new(responses: Vec<impl Into<String>>) -> Self {
            Self {
                responses: responses.into_iter().map(Into::into).collect(),
                cursor: Arc::new(AtomicUsize::new(0)),
                prompts: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn last_prompt(&self) -> String {
            self.prompts
                .lock()
                .expect("prompt capture lock")
                .last()
                .cloned()
                .expect("provider was called")
        }
    }

    #[async_trait]
    impl Provider for CycleProvider {
        fn name(&self) -> &'static str {
            "cycle-test"
        }
        async fn complete(&self, req: Request) -> anyhow::Result<Completion> {
            self.prompts
                .lock()
                .expect("prompt capture lock")
                .push(req.prompt);
            let idx = self.cursor.fetch_add(1, Ordering::SeqCst) % self.responses.len();
            Ok(Completion {
                termination: Default::default(),
                text: self.responses[idx].clone(),
                identity: Default::default(),
                model: "test".into(),
                latency: Duration::from_millis(1),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: None,
            })
        }
    }

    #[test]
    fn truncate_evidence_respects_limit() {
        let blocks = ["abc", "def", "ghi"]
            .into_iter()
            .enumerate()
            .map(|(index, data)| {
                UntrustedContext::new(
                    UntrustedContextClass::Web,
                    format!("test:web:{index}"),
                    data,
                )
                .render()
            })
            .collect::<Vec<_>>();
        let limit = blocks[2].as_str().len();
        let out = truncate_evidence(&blocks, limit);
        assert!(out.len() <= limit);
        assert!(out.contains("\"source_id\":\"test:web:2\""));
        assert!(!out.contains("\"source_id\":\"test:web:1\""));
        assert!(
            crate::pipeline::untrusted_context::parse_rendered_untrusted(&out).is_some(),
            "budgeted evidence must remain one complete canonical envelope"
        );
    }

    #[test]
    fn truncate_evidence_empty_input() {
        let out = truncate_evidence(&[], 100);
        assert!(out.is_empty());
    }

    #[test]
    fn released_channel_research_uses_one_exact_hard_bounded_query() {
        let plan = ReleasedChannelResearchPlan::for_exact_topic("  exact operator topic  ")
            .expect("valid released topic");
        assert_eq!(plan.query, "exact operator topic");
        assert_eq!(plan.max_results, MAX_RELEASED_RESEARCH_RESULTS);
        assert!(ReleasedChannelResearchPlan::for_exact_topic("   ").is_err());
        assert!(
            ReleasedChannelResearchPlan::for_exact_topic(
                &"x".repeat(
                    crate::permissions::ifc::MAX_OPERATOR_RELEASED_RESEARCH_TOPIC_BYTES + 1
                )
            )
            .is_err()
        );
    }

    #[test]
    fn released_search_report_filters_non_http_and_bounds_untrusted_fields() {
        let report = render_released_search_report(vec![
            SearchHit {
                title: format!(
                    "[ok]\u{202e}\n{}",
                    "t".repeat(MAX_RELEASED_RESULT_TITLE_CHARS + 40)
                ),
                url: "https://example.test/result".into(),
                snippet: format!(
                    "summary\r\n{}",
                    "s".repeat(MAX_RELEASED_RESULT_SNIPPET_CHARS + 40)
                ),
            },
            SearchHit {
                title: "credential URL".into(),
                url: "https://user:secret@example.test/private".into(),
                snippet: "must be filtered".into(),
            },
            SearchHit {
                title: "non-http".into(),
                url: "javascript:alert(1)".into(),
                snippet: "must be filtered".into(),
            },
        ]);

        assert_eq!(report.citations.len(), 1);
        assert_eq!(report.citations[0].url, "https://example.test/result");
        assert!(!report.citations[0].title.contains('\n'));
        assert!(!report.citations[0].title.contains('\u{202e}'));
        assert!(report.citations[0].title.starts_with("\\[ok\\]"));
        assert!(!report.article.contains('\r'));
        assert!(!report.article.contains("secret"));
        assert!(report.article.len() < 2_000);
        assert_eq!(compact_released_result_text("abcd next", 4), "abcd");
        assert_eq!(compact_released_result_text("[x]", 3), "\\[x");
    }

    #[test]
    fn released_research_wal_payloads_use_only_random_release_correlation() {
        let started = released_research_started_payload("opaque-release-id").unwrap();
        let completed =
            released_research_completed_payload("opaque-release-id", "success", 3).unwrap();
        for payload in [started, completed] {
            let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(value["research_release_id"], "opaque-release-id");
            assert!(value.get("topic").is_none());
            assert!(value.get("topic_hash").is_none());
            assert!(value.get("released_topic_sha256").is_none());
        }
    }

    #[test]
    fn resolve_search_key_keyless_provider() {
        // SearXNG is keyless — should always succeed without env vars.
        let result = resolve_search_key(SearchProvider::SearXng);
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_search_key_paid_provider_no_env_fails() {
        // Remove the key from env so we can test the bail path.
        // NOTE: This test must be robust to CI where the var might be set.
        if std::env::var("NEOTH_WEB_SEARCH_KEY").is_ok() {
            // If a key IS set in the environment, resolution succeeds — skip.
            return;
        }
        let result = resolve_search_key(SearchProvider::Brave);
        assert!(result.is_err(), "expected Err when no key is set");
    }

    #[tokio::test]
    async fn plan_queries_parses_json_array() {
        let provider = CycleProvider::new(vec![
            r#"["quantum entanglement basics","entanglement experiments","entanglement applications"]"#,
        ]);
        let queries = plan_queries("quantum entanglement", &provider)
            .await
            .unwrap();
        assert_eq!(queries.len(), 3);
        assert!(queries[0].contains("quantum"));
    }

    #[tokio::test]
    async fn plan_queries_handles_fenced_json() {
        let provider = CycleProvider::new(vec!["```json\n[\"a\",\"b\"]\n```"]);
        let queries = plan_queries("topic", &provider).await.unwrap();
        assert_eq!(queries, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn check_satisfied_returns_true() {
        let provider = CycleProvider::new(vec!["true"]);
        let evidence =
            UntrustedContext::new(UntrustedContextClass::Web, "test:web", "ev1").render();
        let result = check_satisfied("topic", &[evidence], 3, 5, &provider)
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn check_satisfied_returns_false() {
        let provider = CycleProvider::new(vec!["false"]);
        let result = check_satisfied("topic", &[], 1, 5, &provider)
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn synthesize_returns_provider_text() {
        let expected = "## Title\n\nThis is the article.\n\nWith multiple paragraphs.";
        let provider = CycleProvider::new(vec![expected]);
        let citations = vec![CitedSource {
            title: "Test".into(),
            url: "https://example.com".into(),
        }];
        let evidence =
            UntrustedContext::new(UntrustedContextClass::Web, "test:web", "evidence block")
                .render();
        let article = synthesize("topic", &[evidence], &citations, &provider)
            .await
            .unwrap();
        assert_eq!(article, expected);
    }

    #[tokio::test]
    async fn synthesize_caps_escape_expanding_citations_by_wire_bytes() {
        let provider = CycleProvider::new(vec!["article"]);
        let citations = vec![CitedSource {
            title: "\u{202e}".repeat(MAX_EVIDENCE_BYTES),
            url: format!(
                "https://example.test/{}",
                "\u{030a}".repeat(MAX_EVIDENCE_BYTES)
            ),
        }];

        synthesize("topic", &[], &citations, &provider)
            .await
            .expect("synthesis request");
        let prompt = provider.last_prompt();
        let citation_wire = prompt
            .split_once("Available sources:\n")
            .expect("citation section")
            .1
            .split_once("\n\nCollected evidence:")
            .expect("evidence section")
            .0;

        assert!(citation_wire.len() <= MAX_EVIDENCE_BYTES / 2);
        assert!(
            crate::pipeline::untrusted_context::parse_rendered_untrusted(citation_wire).is_some(),
            "wire-budgeted citations remain a complete canonical envelope"
        );
    }
}
