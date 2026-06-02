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
pub mod github;
pub mod google_tasks;
pub mod todoist;
pub mod tts;
pub mod web_fetch;
pub mod web_search;
