//! Hacker News as a tech-currency knowledge source for NEOTH self-reflect.
//!
//! Adapted from rajat-mehra05/hackerpedia — which is, on inspection, a React
//! Hacker-News *reader* (its `package.json` is literally `hacker-news-clone`),
//! NOT a knowledge base. The only reusable part is its backend: three calls to
//! the public HN Firebase API (`topstories.json` + `item/{id}.json`). We port
//! that surface to Rust and add what NEOTH actually needs — a deterministic
//! GAP pass that flags trending tech topics the operator's installed skills /
//! recent memory don't yet cover. That gap list is fuel for self-reflection
//! ("bin ich noch aktuell?") and, when self-improve is on, a staged proposal.
//!
//! No UI, no state-management, no LLM: pure fetch + frequency analysis, same
//! rationale as the G-01-mini reflection ([`crate::reflection`]) — it must run
//! unattended and free even when a cloud quota is exhausted.
//!
//! ## Signal quality — shipped vs. future
//!
//! HN titles are noisy; token-frequency + stopwords is a coarse first pass.
//! SHIPPED: a ≥2-distinct-title threshold, a covered-term filter (skills +
//! memory), and per-operator [`GapFilter::ignore`] / [`GapFilter::pin`] lists
//! (`neoth reflect ignore` / `pin`) — the cheap, high-leverage tamers.
//! FUTURE (real NLP work, tracked, not faked here): topic clustering of
//! near-duplicate headlines, a synonym map (`k8s`↔`kubernetes`), and skill-
//! ontology matching so "covered" understands capability overlap, not just
//! substrings.

use anyhow::{Context, Result};
use futures_util::StreamExt;
use serde::de::DeserializeOwned;

use crate::proactive::ProactiveItem;
use crate::tools::external_http::{
    ExternalHttpAuthorizer, ExternalHttpRequest, ExternalHttpSurface,
};

/// Public HN Firebase API base (ported verbatim from hackerpedia's `hnAPI.js`).
pub const HN_BASE: &str = "https://hacker-news.firebaseio.com/v0/";

/// The top-stories payload is normally only a few KiB. Keep a generous hard
/// ceiling so a compromised endpoint cannot make the daemon buffer forever.
const MAX_TOP_STORIES_BYTES: usize = 1024 * 1024;
/// A story item is tiny in normal operation; 256 KiB leaves ample forward
/// compatibility while bounding every per-item allocation.
const MAX_ITEM_BYTES: usize = 256 * 1024;

/// One Hacker News story (the subset NEOTH reflects on).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HnStory {
    pub id: i64,
    pub title: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub score: i64,
    #[serde(default)]
    pub by: String,
}

/// Fetch the top `limit` HN stories (capped at 100 — one `topstories` page is
/// ~500 ids and self-reflect only ever wants the head). Network. Dead, deleted,
/// and non-story items are represented as `Ok(None)` and skipped. Transport,
/// policy, audit, status, body, and parse failures abort the pass so the cron
/// cannot commit a partial refresh as a successful weekly run.
pub async fn top_stories(
    authorizer: &ExternalHttpAuthorizer,
    limit: usize,
) -> Result<Vec<HnStory>> {
    top_stories_from_base(HN_BASE, authorizer, limit).await
}

async fn top_stories_from_base(
    base: &str,
    authorizer: &ExternalHttpAuthorizer,
    limit: usize,
) -> Result<Vec<HnStory>> {
    let limit = limit.min(100);
    let client = reqwest::Client::builder()
        .user_agent(concat!("neoth/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let ids_url = format!("{base}topstories.json");
    let ids_request = ExternalHttpRequest::get(ids_url.clone(), ExternalHttpSurface::HackerNews);
    let ids: Vec<i64> = authorizer
        .execute(ids_request.clone(), |permit| {
            let client = client.clone();
            let ids_request = ids_request.clone();
            async move {
                permit.require(&ids_request)?;
                let response = client.get(ids_url).send().await?;
                response_json_limited(response, MAX_TOP_STORIES_BYTES, "HN top stories").await
            }
        })
        .await?;
    let mut out = Vec::with_capacity(limit);
    for id in ids.into_iter().take(limit) {
        if let Some(story) = fetch_item(base, &client, authorizer, id)
            .await
            .with_context(|| format!("fetch HN item {id}"))?
        {
            out.push(story);
        }
    }
    Ok(out)
}

async fn fetch_item(
    base: &str,
    client: &reqwest::Client,
    authorizer: &ExternalHttpAuthorizer,
    id: i64,
) -> Result<Option<HnStory>> {
    let item_url = format!("{base}item/{id}.json");
    let item_request = ExternalHttpRequest::get(item_url.clone(), ExternalHttpSurface::HackerNews);
    let v: serde_json::Value = authorizer
        .execute(item_request.clone(), |permit| {
            let client = client.clone();
            let item_request = item_request.clone();
            async move {
                permit.require(&item_request)?;
                let response = client.get(item_url).send().await?;
                response_json_limited(response, MAX_ITEM_BYTES, "HN item").await
            }
        })
        .await?;
    Ok(parse_item(&v))
}

async fn response_json_limited<T: DeserializeOwned>(
    response: reqwest::Response,
    max_bytes: usize,
    context: &'static str,
) -> Result<T> {
    let response = response
        .error_for_status()
        .with_context(|| format!("{context} HTTP status"))?;
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        anyhow::bail!("{context} response exceeds {max_bytes}-byte limit");
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("read {context} response body"))?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            anyhow::bail!("{context} response exceeds {max_bytes}-byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).with_context(|| format!("parse {context} JSON"))
}

/// Parse a raw HN item JSON into an [`HnStory`]. `None` for anything that isn't
/// a live story with a title (comments, polls, deleted/dead items). Pure — the
/// network-free core, so the analysis path is fully testable.
pub fn parse_item(v: &serde_json::Value) -> Option<HnStory> {
    if v.get("type").and_then(|t| t.as_str()) != Some("story") {
        return None;
    }
    if v.get("dead").and_then(|b| b.as_bool()).unwrap_or(false)
        || v.get("deleted").and_then(|b| b.as_bool()).unwrap_or(false)
    {
        return None;
    }
    let title = v.get("title").and_then(|t| t.as_str())?.trim().to_string();
    if title.is_empty() {
        return None;
    }
    Some(HnStory {
        id: v.get("id").and_then(|i| i.as_i64()).unwrap_or(0),
        title,
        url: v.get("url").and_then(|u| u.as_str()).map(|s| s.to_string()),
        score: v.get("score").and_then(|s| s.as_i64()).unwrap_or(0),
        by: v
            .get("by")
            .and_then(|b| b.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// A trending tech term from HN titles that the operator's skills/memory don't
/// cover yet — a self-reflection gap.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TechGap {
    pub term: String,
    pub mentions: usize,
    /// One title the term appeared in (operator context, not just a word).
    pub example_title: String,
    /// The operator pinned this topic — surfaced even when covered / single-
    /// mention, and ranked first.
    #[serde(default)]
    pub pinned: bool,
}

/// Per-operator tuning for the gap pass. `covered` comes from the operator's
/// installed skills + recent memory (auto). `ignore` + `pin` are explicit
/// operator lists (`neoth reflect ignore/pin`) that tame the noisy HN-title
/// frequency signal: ignore drops a term entirely; pin force-surfaces it (even
/// if covered or single-mention) and ranks it first. All matched
/// case-insensitively, substring either-way (so `rust` covers `rustls`).
#[derive(Clone, Debug, Default)]
pub struct GapFilter {
    pub covered: Vec<String>,
    pub ignore: Vec<String>,
    pub pin: Vec<String>,
}

/// Lowercase + drop empties — the form the matcher compares against.
fn lc(list: &[String]) -> Vec<String> {
    list.iter()
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty())
        .collect()
}

/// Does `term` match any entry (substring either-way, both already lowercase)?
fn any_match(term: &str, list_lc: &[String]) -> bool {
    list_lc.iter().any(|c| c.contains(term) || term.contains(c))
}

/// Title tokens excluded from trend counting: generic words + HN-title noise
/// that would otherwise dominate ("show", "ask", "new", "using", …). Kept
/// lowercase; matched case-insensitively.
const TITLE_STOPWORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "of", "in", "on", "to", "for", "with", "is", "are",
    "was", "be", "by", "at", "as", "from", "how", "why", "what", "when", "your", "you", "i", "my",
    "we", "it", "its", "this", "that", "new", "now", "can", "will", "has", "have", "do", "does",
    "not", "show", "ask", "tell", "hn", "using", "use", "used", "via", "vs", "into", "out", "up",
    "more", "about", "after", "over", "than", "they", "their", "our", "all", "one", "two", "first",
    "best", "free", "open", "source", "release", "released", "version", "app", "tool", "tools",
    "way", "get",
];

/// Rank trending terms across `stories` and return the top `max_gaps` the
/// operator isn't already on top of. Deterministic, no network, no LLM.
///
/// Rules: a term is tokenised from titles (stopwords + <3 chars dropped). A
/// NON-pinned term surfaces only if it appears in ≥2 distinct titles AND is
/// neither covered (skills/memory) nor on the ignore list. A PINNED term that
/// appears at least once always surfaces (bypassing the ≥2 / covered checks)
/// and is ranked first — operator intent overrides the heuristic. Order:
/// pinned first, then mention count desc, then alphabetical (stable output).
pub fn tech_currency_gaps(
    stories: &[HnStory],
    filter: &GapFilter,
    max_gaps: usize,
) -> Vec<TechGap> {
    use std::collections::HashMap;
    let covered_lc = lc(&filter.covered);
    let ignore_lc = lc(&filter.ignore);
    let pin_lc = lc(&filter.pin);

    // term -> (distinct-title mentions, first example title)
    let mut counts: HashMap<String, (usize, String)> = HashMap::new();
    for story in stories {
        let mut seen_in_title: std::collections::HashSet<String> = std::collections::HashSet::new();
        for raw in story
            .title
            .split(|c: char| !c.is_alphanumeric() && c != '+' && c != '#')
        {
            let term = normalize_term(raw);
            if term.len() < 3 || TITLE_STOPWORDS.contains(&term.as_str()) {
                continue;
            }
            if seen_in_title.insert(term.clone()) {
                let e = counts.entry(term).or_insert((0, story.title.clone()));
                e.0 += 1;
            }
        }
    }

    let mut gaps: Vec<TechGap> = counts
        .into_iter()
        .filter_map(|(term, (mentions, example_title))| {
            let pinned = any_match(&term, &pin_lc);
            if pinned {
                // Operator intent wins over ignore/covered/≥2.
                return Some(TechGap {
                    term,
                    mentions,
                    example_title,
                    pinned: true,
                });
            }
            if mentions < 2 || any_match(&term, &ignore_lc) || any_match(&term, &covered_lc) {
                return None;
            }
            Some(TechGap {
                term,
                mentions,
                example_title,
                pinned: false,
            })
        })
        .collect();
    gaps.sort_by(|a, b| {
        b.pinned
            .cmp(&a.pinned)
            .then_with(|| b.mentions.cmp(&a.mentions))
            .then_with(|| a.term.cmp(&b.term))
    });
    gaps.truncate(max_gaps);
    gaps
}

/// Lowercase + strip a leading/trailing punctuation a tokenizer split missed.
fn normalize_term(raw: &str) -> String {
    raw.trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase()
}

/// Render the operator-facing self-reflection line (German, matching the
/// G-01-mini register). `None` when there are no gaps — never nudge with a
/// vacuous prompt (same rule as [`crate::reflection::build_reflection_item`]).
pub fn render_tech_currency_reflection(gaps: &[TechGap]) -> Option<String> {
    if gaps.is_empty() {
        return None;
    }
    let terms = gaps
        .iter()
        .map(|g| g.term.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "Trending in Tech, das in deinen Skills/Memory noch fehlt: {terms}. Willst du dich da einlesen?"
    ))
}

/// Build a [`ProactiveItem`] so an opt-in cron can enqueue the tech-currency
/// reflection. `None` when there are no gaps. Dedup is keyed per day-tag so a
/// repeated pass within the same day can't double-fire. Kept SEPARATE from the
/// offline weekly reflection cron — this one needs network, that one must not.
pub fn build_tech_currency_item(
    day_tag: &str,
    gaps: &[TechGap],
    scheduled_for_unix: i64,
) -> Option<ProactiveItem> {
    let body = render_tech_currency_reflection(gaps)?;
    Some(ProactiveItem {
        priority: 50,
        dedup_key: format!("reflection:tech-currency:{day_tag}"),
        channel: String::new(),
        source: "hn_tech_currency".into(),
        body,
        scheduled_for_unix,
        is_failure: false,
        // JV-PRO-10 — a tech-currency digest is stale a day after its
        // scheduled surface; if the daily cap held it back, drop it rather
        // than fire yesterday's news late.
        expires_unix: scheduled_for_unix.saturating_add(86_400),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mock_base(server: &MockServer) -> String {
        format!("{}/v0/", server.uri())
    }

    #[tokio::test]
    async fn fetches_top_list_and_each_concrete_item_through_authorizer() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/topstories.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![7]))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v0/item/7.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "type": "story", "id": 7, "title": "A bound HN request"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let stories = top_stories_from_base(
            &mock_base(&server),
            &ExternalHttpAuthorizer::test_allow(),
            1,
        )
        .await
        .unwrap();
        assert_eq!(stories.len(), 1);
        assert_eq!(stories[0].id, 7);
        server.verify().await;
    }

    #[tokio::test]
    async fn item_transport_failure_aborts_the_refresh_instead_of_returning_partial_data() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/topstories.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![7, 8]))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v0/item/7.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "type": "story", "id": 7, "title": "This result must not be committed alone"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v0/item/8.json"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let error = top_stories_from_base(
            &mock_base(&server),
            &ExternalHttpAuthorizer::test_allow(),
            2,
        )
        .await
        .expect_err("one failed item must abort the whole cron input");

        assert!(format!("{error:#}").contains("fetch HN item 8"));
        server.verify().await;
    }

    #[tokio::test]
    async fn fail_closed_deny_never_reaches_hn_transport() {
        use crate::permissions::{AutonomyLevel, AutonomyPolicySnapshot, ConfirmStrategy};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/topstories.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<i64>::new()))
            .mount(&server)
            .await;
        let authorizer = ExternalHttpAuthorizer::test_policy(
            AutonomyPolicySnapshot::test_level(AutonomyLevel::Strict),
            ConfirmStrategy::FailClosed,
        );

        assert!(
            top_stories_from_base(&mock_base(&server), &authorizer, 1)
                .await
                .is_err()
        );
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "FailClosed deny must stop before the HTTP transport"
        );
    }

    #[tokio::test]
    async fn live_policy_reload_to_custom_deny_prevents_transport() {
        use crate::config::reload::{ReloadController, ReloadResult};
        use crate::permissions::{ActionKind, AutonomyLevel, ConfirmStrategy, CustomDecision};

        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("freedom.yaml");
        let initial = crate::config::FreedomConfig {
            autonomy: AutonomyLevel::Full,
            ..Default::default()
        };
        std::fs::write(&config_path, serde_yaml::to_string(&initial).unwrap()).unwrap();
        let controller = Arc::new(ReloadController::new(initial.clone(), config_path.clone()));
        let authorizer = ExternalHttpAuthorizer::test_reload(
            Arc::clone(&controller),
            ConfirmStrategy::FailClosed,
        );

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/topstories.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<i64>::new()))
            .mount(&server)
            .await;
        let base = mock_base(&server);
        top_stories_from_base(&base, &authorizer, 1)
            .await
            .expect("Full policy should reach the transport");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);

        let mut denied = initial;
        denied.autonomy = AutonomyLevel::Custom;
        denied
            .custom_autonomy
            .overrides
            .insert(ActionKind::ExternalHttpRequest, CustomDecision::Deny);
        std::fs::write(&config_path, serde_yaml::to_string(&denied).unwrap()).unwrap();
        assert!(matches!(
            controller.try_reload().unwrap(),
            ReloadResult::Reloaded { .. }
        ));

        let error = top_stories_from_base(&base, &authorizer, 1)
            .await
            .expect_err("the reloaded Custom deny must block HN");
        assert!(format!("{error:#}").contains("autonomy gate denied"));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "the denied request must not reach the transport"
        );
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/topstories.json"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", "/redirect-target"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redirect-target"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<i64>::new()))
            .mount(&server)
            .await;

        assert!(
            top_stories_from_base(
                &mock_base(&server),
                &ExternalHttpAuthorizer::test_allow(),
                1,
            )
            .await
            .is_err()
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "redirect target must never be requested");
        assert_eq!(requests[0].url.path(), "/v0/topstories.json");
    }

    #[tokio::test]
    async fn top_story_response_is_hard_bounded() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/topstories.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b'0'; MAX_TOP_STORIES_BYTES + 1]),
            )
            .mount(&server)
            .await;

        let error = top_stories_from_base(
            &mock_base(&server),
            &ExternalHttpAuthorizer::test_allow(),
            1,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("response exceeds"));
    }

    fn story(id: i64, title: &str) -> HnStory {
        HnStory {
            id,
            title: title.into(),
            url: None,
            score: 0,
            by: String::new(),
        }
    }

    #[test]
    fn parse_item_accepts_story_rejects_comment_and_dead() {
        let s = parse_item(&json!({
            "type": "story", "id": 1, "title": "Rust 2.0 ships", "url": "https://x",
            "score": 99, "by": "alice"
        }))
        .expect("story parses");
        assert_eq!(s.id, 1);
        assert_eq!(s.title, "Rust 2.0 ships");
        assert_eq!(s.url.as_deref(), Some("https://x"));
        assert_eq!(s.score, 99);
        assert_eq!(s.by, "alice");

        assert!(parse_item(&json!({"type": "comment", "id": 2, "text": "nice"})).is_none());
        assert!(
            parse_item(&json!({"type": "story", "id": 3, "title": "x", "dead": true})).is_none()
        );
        assert!(
            parse_item(&json!({"type": "story", "id": 4, "title": "x", "deleted": true})).is_none()
        );
        assert!(parse_item(&json!({"type": "story", "id": 5, "title": "  "})).is_none());
    }

    fn covered(c: &[&str]) -> GapFilter {
        GapFilter {
            covered: c.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn gaps_surface_repeated_uncovered_terms_only() {
        let stories = vec![
            story(1, "Kubernetes operator patterns in production"),
            story(2, "Why Kubernetes networking is hard"),
            story(3, "WebGPU comes to Firefox"),
            story(4, "WebGPU shaders explained"),
            story(5, "A one-off about quantum"), // single mention → not a trend
        ];
        // Operator already covers kubernetes via an installed skill.
        let gaps = tech_currency_gaps(&stories, &covered(&["kubernetes"]), 5);
        let terms: Vec<&str> = gaps.iter().map(|g| g.term.as_str()).collect();
        assert!(terms.contains(&"webgpu"), "webgpu is a 2x uncovered trend");
        assert!(
            !terms.contains(&"kubernetes"),
            "covered skill must be filtered out"
        );
        assert!(
            !terms.contains(&"quantum"),
            "single mention is not a trend (needs >=2)"
        );
        // webgpu appeared in 2 distinct titles.
        let wg = gaps.iter().find(|g| g.term == "webgpu").unwrap();
        assert_eq!(wg.mentions, 2);
        assert!(!wg.example_title.is_empty());
    }

    #[test]
    fn gaps_respect_max_and_stable_order() {
        let stories = vec![
            story(1, "Zig compiler speed"),
            story(2, "Zig allocators"),
            story(3, "Bun runtime perf"),
            story(4, "Bun bundler"),
            story(5, "Deno permissions"),
            story(6, "Deno deploy"),
        ];
        let gaps = tech_currency_gaps(&stories, &GapFilter::default(), 2);
        assert_eq!(gaps.len(), 2, "max_gaps truncates");
        // All three trend equally (2 each) → alphabetical tie-break: bun, deno.
        assert_eq!(gaps[0].term, "bun");
        assert_eq!(gaps[1].term, "deno");
    }

    #[test]
    fn ignore_drops_and_pin_force_surfaces_and_ranks_first() {
        let stories = vec![
            story(1, "Rust async runtime"),
            story(2, "Rust borrow checker"),
            story(3, "Show HN: my agent framework"),
            story(4, "Agent orchestration patterns"),
            story(5, "Quantum supremacy claim"), // single mention
        ];
        let filter = GapFilter {
            covered: vec!["rust".to_string()], // already covered → normally dropped
            ignore: vec!["agent".to_string()], // operator: stop showing me "agent"
            pin: vec!["quantum".to_string()],  // operator: always flag quantum
        };
        let gaps = tech_currency_gaps(&stories, &filter, 10);
        let terms: Vec<&str> = gaps.iter().map(|g| g.term.as_str()).collect();
        assert!(!terms.contains(&"agent"), "ignore list drops the term");
        assert!(!terms.contains(&"rust"), "covered still drops the term");
        assert!(
            terms.contains(&"quantum"),
            "pinned term surfaces despite single mention"
        );
        // pinned ranks first.
        assert!(gaps[0].pinned);
        assert_eq!(gaps[0].term, "quantum");
    }

    #[test]
    fn render_and_item_none_on_empty_gaps() {
        assert!(render_tech_currency_reflection(&[]).is_none());
        assert!(build_tech_currency_item("2026-06-16", &[], 0).is_none());
        let gaps = vec![TechGap {
            term: "webgpu".into(),
            mentions: 3,
            example_title: "WebGPU ships".into(),
            pinned: false,
        }];
        let body = render_tech_currency_reflection(&gaps).unwrap();
        assert!(body.contains("webgpu"));
        let item = build_tech_currency_item("2026-06-16", &gaps, 1_700_000_000).unwrap();
        assert_eq!(item.source, "hn_tech_currency");
        assert_eq!(item.dedup_key, "reflection:tech-currency:2026-06-16");
        assert_eq!(item.priority, 50);
    }
}
