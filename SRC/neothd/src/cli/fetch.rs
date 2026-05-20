//! `neoth fetch <url>` — operator-facing web_fetch surface.
//!
//! Wraps `tools::web_fetch::fetch` so operators can pull a URL into
//! their terminal (or pipe to recall via `neoth ingest --url`,
//! deferred to Phase 2). Honours the Hysteria SOCKS5 proxy via
//! `providers::http_client::build_client`.

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;

#[derive(Args, Debug, Clone)]
pub struct FetchArgs {
    /// URL to fetch. Only http(s) schemes accepted.
    pub url: String,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_fetch(args: FetchArgs) -> Result<()> {
    let result = crate::tools::web_fetch::fetch(&args.url).await?;
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Table => {
            println!("url:          {}", result.url);
            println!("status:       {}", result.status);
            println!("content-type: {}", result.content_type);
            println!("bytes:        {}", result.bytes);
            if result.truncated {
                println!("truncated:    yes (extracted text > ceiling)");
            }
            println!();
            println!("{}", result.text);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_fetch_rejects_non_http() {
        let args = FetchArgs {
            url: "file:///etc/passwd".to_string(),
            output: OutputFormat::Json,
        };
        let err = run_fetch(args).await.unwrap_err();
        assert!(err.to_string().contains("http(s)"));
    }
}
