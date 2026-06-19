//! GOLD-ADAPT-MEMGRAPH-02 — `neoth memory-eval` CLI surface.
//!
//! Builds a fresh temp DB, seeds it with the default eval suite, runs
//! the decay/consolidation pass, and reports recall precision.  The real
//! operator memory DB is never touched — the harness is entirely self-
//! contained and safe to run at any time or in CI.

use anyhow::Result;
use clap::Args;
use tempfile::tempdir;

use crate::memory::{eval_harness, store};

#[derive(Args, Debug, Clone)]
pub struct MemoryEvalArgs {
    /// Emit the report as JSON instead of a human-readable table.
    #[arg(long)]
    pub json: bool,
}

/// Entry point called from the `Commands` dispatch match.
pub async fn run_memory_eval_cmd(args: MemoryEvalArgs) -> Result<()> {
    // Always run against a fresh temp DB so the real operator store is
    // never touched.  The harness seeds its own episodes.
    let dir = tempdir()?;
    let db_path = dir.path().join("memory_eval.db");
    let mut conn = store::open(&db_path)?;

    let suite = eval_harness::default_eval_suite();
    let n_cases = suite.len();
    let report = eval_harness::run_memory_eval(&mut conn, &suite)?;

    if args.json {
        let json = serde_json::to_string_pretty(&report)?;
        println!("{json}");
    } else {
        println!();
        println!("  neoth memory-eval  ({n_cases} built-in cases)");
        println!();
        println!("  episodes injected : {}", report.episodes_injected);
        println!("  queries run       : {}", report.queries_run);
        println!("  hits              : {}", report.hits);
        println!("  misses            : {}", report.misses);
        println!(
            "  recall precision  : {:.1}%",
            report.recall_precision * 100.0
        );
        println!();
        if report.recall_precision >= 0.8 {
            println!("  PASS — recall precision ≥ 80 %");
        } else {
            println!(
                "  WARN — recall precision {:.1}% < 80 % (check decay thresholds / FTS config)",
                report.recall_precision * 100.0
            );
        }
        println!();
    }

    Ok(())
}
