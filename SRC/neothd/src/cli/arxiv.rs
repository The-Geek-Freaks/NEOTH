//! `neoth arxiv search <query>` — A-24. Public ArXiv search.
//!
//! No API key. Results land as JSON or table; operator pipes the PDF
//! URL into `neoth fetch` then `neoth ingest` to land the paper text
//! in recall.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::tools::arxiv;

#[derive(Args, Debug, Clone)]
pub struct ArxivArgs {
    #[command(subcommand)]
    pub action: ArxivAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ArxivAction {
    /// Search ArXiv. Query syntax: `all:keyword`, `ti:title`,
    /// `au:author`, `cat:cs.CL`, `AND` / `OR` / `ANDNOT`.
    Search {
        /// The query string.
        query: String,
        /// Max results (1-50).
        #[arg(long, default_value = "10")]
        limit: usize,
    },
}

pub async fn run_arxiv(args: ArxivArgs) -> Result<()> {
    match args.action {
        ArxivAction::Search { query, limit } => {
            let papers = arxiv::search(&query, limit).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&papers)?);
                }
                OutputFormat::Table => {
                    if papers.is_empty() {
                        println!("no results for `{query}`");
                        return Ok(());
                    }
                    println!("# {} result(s) for `{query}`", papers.len());
                    for (i, p) in papers.iter().enumerate() {
                        println!();
                        println!("[{}] {}", i + 1, p.title);
                        if !p.authors.is_empty() {
                            println!("    by {}", p.authors.join(", "));
                        }
                        if !p.published.is_empty() {
                            println!("    {}", p.published);
                        }
                        if !p.categories.is_empty() {
                            println!("    categories: {}", p.categories.join(", "));
                        }
                        println!("    pdf: {}", p.pdf_url);
                        if !p.abstract_text.is_empty() {
                            let preview: String = p.abstract_text.chars().take(300).collect();
                            println!("    {preview}...");
                        }
                    }
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
    async fn arxiv_search_rejects_empty_query() {
        let args = ArxivArgs {
            action: ArxivAction::Search {
                query: "".to_string(),
                limit: 10,
            },
            output: OutputFormat::Json,
        };
        let err = run_arxiv(args).await.unwrap_err();
        assert!(err.to_string().contains("empty"));
    }
}
