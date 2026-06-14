//! Operator-facing tools — the "things the agent can do beyond LLM
//! call" layer.
//!
//! Each tool is a small, single-purpose surface that the daemon /
//! skills / channels can invoke. Every tool emits its WAL audit pair
//! (`0xC0 TOOL_INVOKED` + `0xC1 TOOL_COMPLETED` or `0xC2 TOOL_FAILED`)
//! and routes through the existing autonomy gate.
//!
//! v0.1.x ships:
//!   - `web_fetch` (A-21): HTTP GET + clean-text extraction from HTML
//!   - `web_search` (A-20): Brave / Tavily / Google CSE provider routing
//!
//! Phase 2 picks up Playwright MCP, Firecrawl, ArXiv, etc., on top of
//! the same trait.

pub mod arxiv;
pub mod caldav;
/// EM-02b — CalDAV calendar (VEVENT) read/write. Reuses the `caldav` VTODO
/// primitives + the shared `email::calendar` model/renderer.
pub mod caldav_calendar;
pub mod github;
pub mod google_tasks;
pub mod microsoft_todo;
pub mod todoist;
pub mod tts;
pub mod web_fetch;
pub mod web_search;
/// GOLD-ADAPT-ODY-29 — disk-backed LRU cache for `web_search` results
/// (SHA-256 key, TTL freshness, 1000-entry mtime-LRU). Kills redundant paid
/// search-API calls. Wraps `web_search::search` via `search_cached`.
pub mod search_cache;
/// GOLD-ADAPT-ODY-30 — on-disk `web_search` usage analytics (normalized-query
/// frequency + success/fail/cache-hit counters). Surfaced via
/// `neoth search --stats`.
pub mod search_analytics;
/// GOLD-ADOPT-26 — zero-config web-to-Markdown via https://r.jina.ai/<url>.
/// Last-resort URL fetcher for the ingest pipeline; no API key required.
pub mod jina_reader;
/// GOLD-ADOPT-04 — native CSS HTML extraction + adaptive fingerprint re-find.
pub mod web_extract;
/// GOLD-ADOPT-04 — persistent selector cache wrapping web_extract with
/// adaptive recovery + WAL audit.
pub mod web_selector_cache;
/// GOLD-ADAPT-SKILL-03 — conditional-GET (HTTP-304) doc cache for `web_fetch`
/// (the NEOTH-correct form of the agent-skills `sdd-cache` hook).
pub mod web_doc_cache;
