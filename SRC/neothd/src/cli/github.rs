//! `neoth github` — A-3 + A-4. Wraps the operator's `gh` CLI.
//!
//! Subcommands:
//!   `issues [--repo <r>] [--state open|closed|all] [--limit N]`
//!   `issue-create [--repo <r>] --title <t> --body <b>`
//!   `prs [--repo <r>] [--state open|closed|merged|all] [--limit N]`
//!   `pr-view [--repo <r>] <number>`
//!   `pr-review [--repo <r>] <number> --verdict comment|approve|changes --body <b>`

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::tools::github::{self, ReviewVerdict};

#[derive(Args, Debug, Clone)]
pub struct GithubArgs {
    #[command(subcommand)]
    pub action: GithubAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GithubAction {
    /// List issues.
    Issues {
        #[arg(long, value_name = "OWNER/REPO")]
        repo: Option<String>,
        #[arg(long, default_value = "open")]
        state: String,
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Create an issue.
    IssueCreate {
        #[arg(long, value_name = "OWNER/REPO")]
        repo: Option<String>,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        body: String,
    },
    /// List pull requests.
    Prs {
        #[arg(long, value_name = "OWNER/REPO")]
        repo: Option<String>,
        #[arg(long, default_value = "open")]
        state: String,
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// View a single PR (number, title, body, head/base, stats).
    PrView {
        number: u64,
        #[arg(long, value_name = "OWNER/REPO")]
        repo: Option<String>,
    },
    /// Post a review (comment / approve / request-changes).
    PrReview {
        number: u64,
        #[arg(long, value_name = "OWNER/REPO")]
        repo: Option<String>,
        /// Review verdict: `comment` / `approve` / `changes`.
        #[arg(long, default_value = "comment")]
        verdict: String,
        #[arg(long)]
        body: String,
    },
}

pub async fn run_github(args: GithubArgs) -> Result<()> {
    match args.action {
        GithubAction::Issues { repo, state, limit } => {
            let issues = github::list_issues(repo.as_deref(), Some(&state), limit)?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&issues)?);
                }
                OutputFormat::Table => {
                    if issues.is_empty() {
                        println!("no issues");
                        return Ok(());
                    }
                    for i in &issues {
                        let labels = i
                            .labels
                            .iter()
                            .map(|l| l.name.as_str())
                            .collect::<Vec<_>>()
                            .join(",");
                        println!(
                            "#{} [{}] {}  by {}{}",
                            i.number,
                            i.state,
                            i.title,
                            i.author.login,
                            if labels.is_empty() {
                                String::new()
                            } else {
                                format!("  ({labels})")
                            },
                        );
                    }
                }
            }
        }
        GithubAction::IssueCreate { repo, title, body } => {
            let url = github::create_issue(repo.as_deref(), &title, &body)?;
            println!("{url}");
        }
        GithubAction::Prs { repo, state, limit } => {
            let prs = github::list_prs(repo.as_deref(), Some(&state), limit)?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&prs)?);
                }
                OutputFormat::Table => {
                    if prs.is_empty() {
                        println!("no PRs");
                        return Ok(());
                    }
                    for p in &prs {
                        println!(
                            "#{}{} [{}] {} ({} → {}) by {}",
                            p.number,
                            if p.draft { " DRAFT" } else { "" },
                            p.state,
                            p.title,
                            p.head,
                            p.base,
                            p.author.login,
                        );
                    }
                }
            }
        }
        GithubAction::PrView { number, repo } => {
            let view = github::view_pr(repo.as_deref(), number)?;
            println!("{}", serde_json::to_string_pretty(&view)?);
        }
        GithubAction::PrReview {
            number,
            repo,
            verdict,
            body,
        } => {
            let v = ReviewVerdict::parse(&verdict).ok_or_else(|| {
                anyhow::anyhow!("unknown verdict `{verdict}` — known: comment, approve, changes")
            })?;
            github::review_pr(repo.as_deref(), number, v, &body)?;
            println!("review posted on PR #{number}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pr_review_unknown_verdict_errors() {
        let args = GithubArgs {
            action: GithubAction::PrReview {
                number: 1,
                repo: None,
                verdict: "yolo".to_string(),
                body: "lgtm".to_string(),
            },
            output: OutputFormat::Json,
        };
        let err = run_github(args).await.unwrap_err();
        assert!(err.to_string().contains("unknown verdict"));
    }
}
