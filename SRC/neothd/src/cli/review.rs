//! `neoth review` — GOLD-ADOPT-15 — AI code review via OpenCodeReview (`ocr`).
//!
//! A thin, NEOTH-idiomatic wrapper over the `ocr` CLI
//! ([alibaba/open-code-review]). With no flags it reviews the working-tree
//! changes (staged + unstaged + untracked); `--from/--to` reviews a branch
//! against its base, `--commit` a single commit. The global `--output json`
//! maps to `ocr --format json` so the result pipes into other tooling.
//!
//! NEOTH only invokes the binary — OCR owns its LLM config
//! (`~/.opencodereview/config.json`: model + auth); NEOTH never reads that token.
//!
//! [alibaba/open-code-review]: https://github.com/alibaba/open-code-review

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;
use crate::installers::ocr;

#[derive(Args, Debug, Clone)]
pub struct ReviewArgs {
    /// Source ref to diff from (branch/merge-base mode), e.g. `main`.
    #[arg(long)]
    pub from: Option<String>,

    /// Target ref for the diff (defaults to the current branch when `--from`
    /// is set).
    #[arg(long)]
    pub to: Option<String>,

    /// Review a single commit (or tag) against its parent.
    #[arg(long, short = 'c', value_name = "SHA")]
    pub commit: Option<String>,

    /// Optional requirement / business context to steer the review.
    #[arg(long, short = 'b', value_name = "TEXT")]
    pub background: Option<String>,

    /// Preview which files would be reviewed — no LLM calls (free, fast).
    #[arg(long, short = 'p')]
    pub preview: bool,

    /// Agent mode: summary only, no human progress lines (for piping).
    #[arg(long)]
    pub agent: bool,

    /// Repository root (defaults to the current directory).
    #[arg(long, value_name = "DIR")]
    pub repo: Option<PathBuf>,

    /// Output format. Inherited from the global `--output` flag (`json` →
    /// `ocr --format json`).
    #[arg(skip)]
    pub output: OutputFormat,
}

/// Map [`ReviewArgs`] to the `ocr` CLI argv. Pure — the testable core of the
/// wrapper. With no diff selectors `ocr review` reviews the working tree.
fn build_ocr_argv(a: &ReviewArgs) -> Vec<String> {
    let mut v = vec!["review".to_string()];
    if let Some(f) = &a.from {
        v.push("--from".into());
        v.push(f.clone());
    }
    if let Some(t) = &a.to {
        v.push("--to".into());
        v.push(t.clone());
    }
    if let Some(c) = &a.commit {
        v.push("--commit".into());
        v.push(c.clone());
    }
    if let Some(b) = &a.background {
        v.push("--background".into());
        v.push(b.clone());
    }
    if a.preview {
        v.push("--preview".into());
    }
    if a.agent {
        v.push("--audience".into());
        v.push("agent".into());
    }
    if let Some(r) = &a.repo {
        v.push("--repo".into());
        v.push(r.display().to_string());
    }
    if matches!(a.output, OutputFormat::Json | OutputFormat::Jsonl) {
        v.push("--format".into());
        v.push("json".into());
    }
    v
}

pub async fn run_review(args: ReviewArgs) -> Result<()> {
    if ocr::check_available().await.is_none() {
        anyhow::bail!(
            "`ocr` (OpenCodeReview) is not installed.\n  \
             Install it: {}\n  \
             Then configure the review LLM once: `ocr config` (model + auth token).\n  \
             `neoth review` wraps it. Upstream: {}",
            ocr::install_command().join(" "),
            ocr::OCR_GITHUB,
        );
    }
    ocr::run(&build_ocr_argv(&args)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ReviewArgs {
        ReviewArgs {
            from: None,
            to: None,
            commit: None,
            background: None,
            preview: false,
            agent: false,
            repo: None,
            output: OutputFormat::Table,
        }
    }

    #[test]
    fn no_flags_reviews_working_tree() {
        assert_eq!(build_ocr_argv(&base()), vec!["review"]);
    }

    #[test]
    fn branch_mode_maps_from_to() {
        let a = ReviewArgs {
            from: Some("main".into()),
            to: Some("dev".into()),
            ..base()
        };
        assert_eq!(
            build_ocr_argv(&a),
            vec!["review", "--from", "main", "--to", "dev"]
        );
    }

    #[test]
    fn commit_and_agent_and_json() {
        let a = ReviewArgs {
            commit: Some("abc123".into()),
            agent: true,
            output: OutputFormat::Json,
            ..base()
        };
        let v = build_ocr_argv(&a);
        assert_eq!(&v[0..3], &["review", "--commit", "abc123"]);
        assert!(v.windows(2).any(|w| w == ["--audience", "agent"]));
        assert!(v.windows(2).any(|w| w == ["--format", "json"]));
    }

    #[test]
    fn preview_and_background() {
        let a = ReviewArgs {
            preview: true,
            background: Some("auth refactor".into()),
            ..base()
        };
        let v = build_ocr_argv(&a);
        assert!(v.contains(&"--preview".to_string()));
        assert!(v.windows(2).any(|w| w == ["--background", "auth refactor"]));
    }
}
