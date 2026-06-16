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

use anyhow::Result;

use crate::proactive::ProactiveItem;

/// Public HN Firebase API base (ported verbatim from hackerpedia's `hnAPI.js`).
pub const HN_BASE: &str = "https://hacker-news.firebaseio.com/v0/";

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
/// ~500 ids and self-reflect only ever wants the head). Network. Per-item
/// failures are logged + skipped so one dead id never sinks the whole pass.
pub async fn top_stories(limit: usize) -> Result<Vec<HnStory>> {
    let limit = limit.min(100);
    let client = reqwest::Client::builder()
        .user_agent(concat!("neoth/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let ids: Vec<i64> = client
        .get(format!("{HN_BASE}topstories.json"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut out = Vec::with_capacity(limit);
    for id in ids.into_iter().take(limit) {
        match fetch_item(&client, id).await {
            Ok(Some(s)) => out.push(s),
            Ok(None) => {} // comment / poll / dead — not a story
            Err(e) => tracing::warn!(error = %e, id, "hn: item fetch failed; skipping"),
        }
    }
    Ok(out)
}

async fn fetch_item(client: &reqwest::Client, id: i64) -> Result<Option<HnStory>> {
    let v: serde_json::Value = client
        .get(format!("{HN_BASE}item/{id}.json"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(parse_item(&v))
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
        url: v
            .get("url")
            .and_then(|u| u.as_str())
            .map(|s| s.to_string()),
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
}

/// Title tokens excluded from trend counting: generic words + HN-title noise
/// that would otherwise dominate ("show", "ask", "new", "using", …). Kept
/// lowercase; matched case-insensitively.
const TITLE_STOPWORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "of", "in", "on", "to", "for", "with", "is", "are", "was",
    "be", "by", "at", "as", "from", "how", "why", "what", "when", "your", "you", "i", "my", "we",
    "it", "its", "this", "that", "new", "now", "can", "will", "has", "have", "do", "does", "not",
    "show", "ask", "tell", "hn", "using", "use", "used", "via", "vs", "into", "out", "up", "more",
    "about", "after", "over", "than", "they", "their", "our", "all", "one", "two", "first", "best",
    "free", "open", "source", "release", "released", "version", "app", "tool", "tools", "way", "get",
];

/// Rank trending terms across `stories` and return the top `max_gaps` that
/// DON'T appear in `covered` (lowercased skill names + recent memory topics).
/// Deterministic, no network, no LLM. A term counts when it appears in ≥2
/// distinct titles (a one-off headline isn't a "trend"). Ordering is by mention
/// count desc, then alphabetically for stable output.
pub fn tech_currency_gaps(stories: &[HnStory], covered: &[String], max_gaps: usize) -> Vec<TechGap> {
    use std::collections::HashMap;
    let covered_lc: Vec<String> = covered
        .iter()
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty())
        .collect();

    // term -> (distinct-title mentions, first example title)
    let mut counts: HashMap<String, (usize, String)> = HashMap::new();
    for story in stories {
        let mut seen_in_title: std::collections::HashSet<String> = std::collections::HashSet::new();
        for raw in story.title.split(|c: char| !c.is_alphanumeric() && c != '+' && c != '#') {
            let term = normalize_term(raw);
            if term.len() < 3 || TITLE_STOPWORDS.contains(&term.as_str()) {
                continue;
            }
            // Already covered by a skill/memory topic? Substring either way so
            // "rust" covers "rustls" and "kubernetes" covers a "k8s"-tagged
            // skill named "kubernetes".
            if covered_lc
                .iter()
                .any(|c| c.contains(&term) || term.contains(c))
            {
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
        .filter(|(_, (n, _))| *n >= 2)
        .map(|(term, (mentions, example_title))| TechGap {
            term,
            mentions,
            example_title,
        })
        .collect();
    gaps.sort_by(|a, b| {
        b.mentions
            .cmp(&a.mentions)
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        let covered = vec!["kubernetes".to_string()];
        let gaps = tech_currency_gaps(&stories, &covered, 5);
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
        let gaps = tech_currency_gaps(&stories, &[], 2);
        assert_eq!(gaps.len(), 2, "max_gaps truncates");
        // All three trend equally (2 each) → alphabetical tie-break: bun, deno.
        assert_eq!(gaps[0].term, "bun");
        assert_eq!(gaps[1].term, "deno");
    }

    #[test]
    fn render_and_item_none_on_empty_gaps() {
        assert!(render_tech_currency_reflection(&[]).is_none());
        assert!(build_tech_currency_item("2026-06-16", &[], 0).is_none());
        let gaps = vec![TechGap {
            term: "webgpu".into(),
            mentions: 3,
            example_title: "WebGPU ships".into(),
        }];
        let body = render_tech_currency_reflection(&gaps).unwrap();
        assert!(body.contains("webgpu"));
        let item = build_tech_currency_item("2026-06-16", &gaps, 1_700_000_000).unwrap();
        assert_eq!(item.source, "hn_tech_currency");
        assert_eq!(item.dedup_key, "reflection:tech-currency:2026-06-16");
        assert_eq!(item.priority, 50);
    }
}
