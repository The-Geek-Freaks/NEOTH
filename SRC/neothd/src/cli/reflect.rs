//! `neoth reflect` — self-reflection surfaces. `tech-news` pulls trending
//! Hacker News topics and flags the ones the operator's installed skills +
//! recent memory don't cover yet (a "tech-currency" gap). The feed adapter
//! lives in `crate::sources::hackernews`.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::memory::store;
use crate::sources::hackernews;

#[derive(Args, Debug, Clone)]
pub struct ReflectArgs {
    #[command(subcommand)]
    pub action: ReflectAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ReflectAction {
    /// Scan trending Hacker News stories and show which topics your installed
    /// skills + recent memory don't cover yet (tech-currency self-reflection).
    TechNews {
        /// How many top HN stories to scan (capped at 100).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Maximum gaps to surface.
        #[arg(long, default_value_t = 7)]
        max_gaps: usize,
    },
}

pub async fn run_reflect(args: ReflectArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        ReflectAction::TechNews { limit, max_gaps } => tech_news(limit, max_gaps, output).await,
    }
}

async fn tech_news(limit: usize, max_gaps: usize, output: OutputFormat) -> Result<()> {
    let stories = hackernews::top_stories(limit)
        .await
        .context("fetch Hacker News top stories")?;
    let covered = collect_covered();
    let gaps = hackernews::tech_currency_gaps(&stories, &covered, max_gaps);

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "scanned": stories.len(),
                "covered_terms": covered.len(),
                "gaps": gaps,
                "reflection": hackernews::render_tech_currency_reflection(&gaps),
            })
        );
        return Ok(());
    }

    println!(
        "Tech-currency self-reflection ({} HN stories scanned):",
        stories.len()
    );
    if gaps.is_empty() {
        println!("  — keine Lücken: deine Skills/Memory decken die aktuellen Trends ab. ✓");
        return Ok(());
    }
    for g in &gaps {
        println!(
            "  • {} ({}×) — z.B. \"{}\"",
            g.term, g.mentions, g.example_title
        );
    }
    if let Some(line) = hackernews::render_tech_currency_reflection(&gaps) {
        println!("\n{line}");
    }
    Ok(())
}

/// The operator's "covered" surface: installed skill dir-names + manifest ids +
/// the top recent conversation topics. Best-effort — a missing skills dir or
/// `views.db` just yields fewer covered terms (more gaps surface, never panics).
fn collect_covered() -> Vec<String> {
    let mut covered = Vec::new();
    let skills_dir = crate::skills::installer::default_skills_dir();
    for e in crate::skills::installer::list_installed(&skills_dir) {
        covered.push(e.dir_name);
        if let Some(id) = e.manifest_id {
            covered.push(id);
        }
    }
    if let Ok(conn) = store::open(&store::default_path()) {
        let now_ns = crate::time::now_unix_ns_i64();
        if let Ok(topics) = crate::reflection::top_topics_last_7_days(&conn, now_ns, 20) {
            covered.extend(topics);
        }
    }
    covered
}
