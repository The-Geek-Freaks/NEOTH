//! `neoth arxiv search <query>` — A-24. Public ArXiv search.
//!
//! No API key. Results land as JSON or table; operator pipes the PDF
//! URL into `neoth fetch` then `neoth ingest` to land the paper text
//! in recall.

use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::cli::arxiv_ingest_task::{self, PassReport};
use crate::config::FreedomConfig;
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
    /// Run one immediate pass of the enabled configured arXiv ingest feed.
    Ingest {
        /// Confirm the immediate one-shot pass; this never enables the daemon cadence.
        #[arg(long)]
        now: bool,
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
        ArxivAction::Ingest { now } => {
            anyhow::ensure!(now, "arxiv ingest requires --now");
            run_ingest_now(args.output).await?;
        }
    }
    Ok(())
}

async fn run_ingest_now(output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let config = FreedomConfig::load_from_default_path_or_default()
        .context("load arxiv ingest configuration")?;
    let report = arxiv_ingest_task::run_configured_one_shot(&home, &config).await?;
    render_ingest_report(&report, output)?;
    Ok(())
}

fn ingest_report_json(report: &PassReport) -> serde_json::Value {
    serde_json::json!({
        "topics_queried": report.topics_queried,
        "topics_failed": report.topics_failed,
        "papers_indexed": report.papers_indexed,
        "papers_skipped": report.papers_skipped,
    })
}

fn render_ingest_report(report: &PassReport, output: OutputFormat) -> Result<()> {
    let value = ingest_report_json(report);
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
        OutputFormat::Table => println!(
            "arXiv ingest complete: {} topic(s), {} failed, {} indexed, {} skipped",
            report.topics_queried,
            report.topics_failed,
            report.papers_indexed,
            report.papers_skipped
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct ArxivTestCli {
        #[command(subcommand)]
        action: ArxivAction,
    }

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

    #[tokio::test]
    async fn immediate_ingest_requires_explicit_now_before_config_or_io() {
        let args = ArxivArgs {
            action: ArxivAction::Ingest { now: false },
            output: OutputFormat::Json,
        };
        let error = run_arxiv(args).await.expect_err("missing --now denies");
        assert!(error.to_string().contains("requires --now"));
    }

    #[test]
    fn cli_exposes_an_explicit_immediate_ingest_action() {
        assert!(matches!(
            ArxivTestCli::try_parse_from(["neoth-arxiv", "ingest", "--now"])
                .expect("parse immediate ingest")
                .action,
            ArxivAction::Ingest { now: true }
        ));
        assert!(matches!(
            ArxivTestCli::try_parse_from(["neoth-arxiv", "ingest"])
                .expect("parse missing confirmation")
                .action,
            ArxivAction::Ingest { now: false }
        ));
    }

    #[test]
    fn immediate_ingest_jsonl_report_is_one_line_and_content_free() {
        let report = PassReport {
            topics_queried: 2,
            topics_failed: 1,
            papers_indexed: 3,
            papers_skipped: 1,
        };
        let jsonl = serde_json::to_string(&ingest_report_json(&report)).expect("serialize");
        assert!(!jsonl.contains('\n'));
        let decoded: serde_json::Value = serde_json::from_str(&jsonl).expect("parse line");
        assert_eq!(decoded["topics_queried"], 2);
        assert_eq!(decoded["topics_failed"], 1);
        assert_eq!(decoded["papers_indexed"], 3);
        assert_eq!(decoded["papers_skipped"], 1);
        assert!(decoded.get("abstract").is_none());
    }
}
