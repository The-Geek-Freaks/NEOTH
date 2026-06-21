//! `neoth search <query>` — A-20 operator-facing web search.
//!
//! Provider picked from `freedom.yaml::web_search_provider` (or
//! `--provider` override). API key from `credentials.yaml::web_search_key`.

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;
use crate::secret::SecretString;
use crate::tools::web_search::{self, Provider};

#[derive(Args, Debug, Clone)]
pub struct SearchArgs {
    /// Query string. Optional only when `--stats` is given.
    pub query: Option<String>,
    /// Provider override: `brave`, `tavily`, or `searxng` (self-hosted, keyless).
    #[arg(long, value_name = "NAME")]
    pub provider: Option<String>,
    /// API key override. Defaults to `credentials.yaml::web_search_key`
    /// or the `NEOTH_WEB_SEARCH_KEY` env variable.
    #[arg(long, value_name = "KEY")]
    pub api_key: Option<String>,
    /// Max results (1-20).
    #[arg(long, default_value = "5")]
    pub limit: usize,
    /// GOLD-ADAPT-ODY-30 — print `web_search` usage analytics (top queries +
    /// success/fail/cache-hit counters) instead of running a search.
    #[arg(long)]
    pub stats: bool,

    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_search(args: SearchArgs) -> Result<()> {
    if args.stats {
        return print_search_stats(args.output);
    }
    let query = match args.query.clone() {
        Some(q) => q,
        None => {
            anyhow::bail!("neoth search: provide a <query> (or pass --stats for usage analytics)")
        }
    };
    let provider_name = args
        .provider
        .clone()
        .or_else(|| std::env::var("NEOTH_WEB_SEARCH_PROVIDER").ok())
        .unwrap_or_else(|| "brave".to_string());
    let provider = Provider::from_str(&provider_name).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown web_search provider `{provider_name}` — known: brave, tavily, searxng"
        )
    })?;
    // SearXNG is self-hosted + keyless (instance from `NEOTH_SEARXNG_URL`);
    // every other provider needs an API key.
    let key = if provider.needs_api_key() {
        match args.api_key.clone() {
            Some(k) => SecretString::from(k),
            None => match std::env::var("NEOTH_WEB_SEARCH_KEY") {
                Ok(k) => SecretString::from(k),
                Err(_) => anyhow::bail!(
                    "no API key. Pass --api-key, set NEOTH_WEB_SEARCH_KEY, or add to credentials.yaml."
                ),
            },
        }
    } else {
        SecretString::from(String::new())
    };
    // GOLD-ADAPT-ODY-29 — go through the disk-LRU cache so a repeated query
    // inside the TTL window is served free instead of re-billing the provider.
    let hits = web_search::search_cached(provider, &key, &query, args.limit).await?;

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&hits)?);
        }
        OutputFormat::Table => {
            if hits.is_empty() {
                println!("no results");
                return Ok(());
            }
            for (i, h) in hits.iter().enumerate() {
                println!("[{}] {}", i + 1, h.title);
                println!("    {}", h.url);
                if !h.snippet.is_empty() {
                    let snippet: String = h.snippet.chars().take(200).collect();
                    println!("    {snippet}");
                }
                println!();
            }
        }
    }
    Ok(())
}

/// GOLD-ADAPT-ODY-30 — render `web_search` usage analytics for `--stats`.
fn print_search_stats(output: OutputFormat) -> Result<()> {
    use crate::tools::search_analytics::SearchAnalytics;
    let a = SearchAnalytics::load(&SearchAnalytics::default_path());
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&a)?);
        }
        OutputFormat::Table => {
            let total = a.total();
            let hit_rate = if total > 0 {
                a.cache_hit as f64 / total as f64 * 100.0
            } else {
                0.0
            };
            println!("web_search analytics:");
            println!(
                "  total: {total}   success: {}   fail: {}   cache_hit: {}",
                a.success, a.fail, a.cache_hit
            );
            println!("  cache hit-rate: {hit_rate:.1}%");
            println!("  top queries:");
            let top = a.top_patterns(10);
            if top.is_empty() {
                println!("    (none recorded yet)");
            } else {
                for (q, c) in top {
                    println!("    {c:>5}  {q}");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn search_unknown_provider_errors() {
        let args = SearchArgs {
            query: Some("rust".to_string()),
            provider: Some("googlebot".to_string()),
            api_key: Some("dummy".to_string()),
            limit: 5,
            stats: false,
            output: OutputFormat::Json,
        };
        let err = run_search(args).await.unwrap_err();
        assert!(err.to_string().contains("unknown web_search provider"));
    }

    // Holds crate::test_env::lock() across the run_search().await; the
    // awaited code never re-locks it, so the bounded hold is safe.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn search_missing_api_key_errors() {
        let _env = crate::test_env::lock();
        unsafe { std::env::remove_var("NEOTH_WEB_SEARCH_KEY") };
        let args = SearchArgs {
            query: Some("rust".to_string()),
            provider: Some("brave".to_string()),
            api_key: None,
            limit: 5,
            stats: false,
            output: OutputFormat::Json,
        };
        let err = run_search(args).await.unwrap_err();
        assert!(err.to_string().contains("no API key"));
    }

    #[tokio::test]
    async fn missing_query_without_stats_errors() {
        let args = SearchArgs {
            query: None,
            provider: Some("brave".to_string()),
            api_key: Some("dummy".to_string()),
            limit: 5,
            stats: false,
            output: OutputFormat::Json,
        };
        let err = run_search(args).await.unwrap_err();
        assert!(err.to_string().contains("provide a <query>"));
    }

    #[tokio::test]
    async fn stats_flag_runs_without_a_query() {
        // `--stats` short-circuits to the analytics printer before any query /
        // provider / key resolution, so it succeeds with no query.
        let args = SearchArgs {
            query: None,
            provider: None,
            api_key: None,
            limit: 5,
            stats: true,
            output: OutputFormat::Json,
        };
        run_search(args).await.unwrap();
    }
}
