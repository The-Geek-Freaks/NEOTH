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
    /// Query string.
    pub query: String,
    /// Provider override: `brave` or `tavily`.
    #[arg(long, value_name = "NAME")]
    pub provider: Option<String>,
    /// API key override. Defaults to `credentials.yaml::web_search_key`
    /// or the `NEOTH_WEB_SEARCH_KEY` env variable.
    #[arg(long, value_name = "KEY")]
    pub api_key: Option<String>,
    /// Max results (1-20).
    #[arg(long, default_value = "5")]
    pub limit: usize,

    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_search(args: SearchArgs) -> Result<()> {
    let provider_name = args
        .provider
        .clone()
        .or_else(|| std::env::var("NEOTH_WEB_SEARCH_PROVIDER").ok())
        .unwrap_or_else(|| "brave".to_string());
    let provider = Provider::from_str(&provider_name).ok_or_else(|| {
        anyhow::anyhow!("unknown web_search provider `{provider_name}` — known: brave, tavily")
    })?;
    let key = match args.api_key.clone() {
        Some(k) => SecretString::from(k),
        None => match std::env::var("NEOTH_WEB_SEARCH_KEY") {
            Ok(k) => SecretString::from(k),
            Err(_) => anyhow::bail!(
                "no API key. Pass --api-key, set NEOTH_WEB_SEARCH_KEY, or add to credentials.yaml."
            ),
        },
    };
    let hits = web_search::search(provider, &key, &args.query, args.limit).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn search_unknown_provider_errors() {
        let args = SearchArgs {
            query: "rust".to_string(),
            provider: Some("googlebot".to_string()),
            api_key: Some("dummy".to_string()),
            limit: 5,
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
            query: "rust".to_string(),
            provider: Some("brave".to_string()),
            api_key: None,
            limit: 5,
            output: OutputFormat::Json,
        };
        let err = run_search(args).await.unwrap_err();
        assert!(err.to_string().contains("no API key"));
    }
}
