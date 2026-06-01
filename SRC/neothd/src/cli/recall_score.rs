//! `neoth recall-score` — ARCH-05/SPEC-08 recall-parity gate runner.
//!
//! The operator-facing entry to the Jarvis→NEOTH migration gate. Loads the
//! grader sheets (NEOTH + reference, scored offline by the 4-grader protocol),
//! computes the inter-rater kappa + kappa-adjusted weighted-harmonic parity +
//! per-query CRITICAL divergences, prints the report, emits a WAL
//! `0x3E EVAL_CRITICAL_DIVERGENCE` per flagged query (durable abort evidence),
//! and **exits non-zero if the gate fails** so a cutover script can gate on it.
//!
//! 100% offline: it scores grade FILES — no live Jarvis, no LLM, no grading
//! here (the grading is the operator's run; the file format is the contract).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::recall::goldset::{GraderGrade, load_goldset, load_grades};
use crate::recall::parity_run::{ParityRunResult, compute_parity_run};

#[derive(Args, Debug, Clone)]
pub struct RecallScoreArgs {
    /// Grader-sheet JSONL file(s) (each line a GraderGrade: query_id, grader_id,
    /// system, 5×Likert). Pass one per grader; all are merged. Need ≥ 2 graders.
    #[arg(long = "grades", required = true, num_args = 1..)]
    pub grades: Vec<PathBuf>,
    /// Optional goldset JSONL — validated + its query count reported (the
    /// scoring runs off the grades, not the goldset).
    #[arg(long)]
    pub goldset: Option<PathBuf>,
    /// Don't emit `0x3E` WAL frames (dry scoring; the report still prints).
    #[arg(long)]
    pub no_audit: bool,
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_recall_score(args: RecallScoreArgs) -> Result<()> {
    if let Some(gs) = &args.goldset {
        let entries = load_goldset(gs).with_context(|| "load --goldset")?;
        if matches!(args.output, OutputFormat::Table) {
            println!("# goldset: {} queries", entries.len());
        }
    }

    let mut all_grades: Vec<GraderGrade> = Vec::new();
    for path in &args.grades {
        let g = load_grades(path).with_context(|| format!("load grades {}", path.display()))?;
        all_grades.extend(g);
    }

    let result = compute_parity_run(&all_grades).context("compute parity run")?;

    if !args.no_audit && !result.critical_queries.is_empty() {
        emit_critical_divergences(&result).await;
    }

    render(&result, &args.output);

    // The gate is the contract: a failed parity run is a non-zero exit so a
    // cutover script (`neoth cutover execute`) and CI can hard-gate on it.
    if !result.verdict.passed {
        anyhow::bail!(
            "recall-parity gate FAILED: aggregate {:.4} (threshold {:.2}), {} CRITICAL divergence(s)",
            result.verdict.aggregate,
            result.verdict.threshold,
            result.verdict.critical_count
        );
    }
    Ok(())
}

fn render(r: &ParityRunResult, output: &OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "aggregate": r.aggregate,
                "threshold": r.verdict.threshold,
                "mean_kappa": r.mean_kappa,
                "passed": r.verdict.passed,
                "critical_count": r.verdict.critical_count,
                "dimension_kappas": r.dimension_kappas.iter()
                    .map(|(d, k)| serde_json::json!({ "dimension": d.as_str(), "kappa": k }))
                    .collect::<Vec<_>>(),
                "dimension_parity_kappa": r.dimension_parity_kappa.iter()
                    .map(|(d, p)| serde_json::json!({ "dimension": d.as_str(), "parity_kappa": p }))
                    .collect::<Vec<_>>(),
                "critical_queries": r.critical_queries.iter()
                    .map(|(q, reason)| serde_json::json!({ "query_id": q, "reason": format!("{reason:?}") }))
                    .collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
        }
        OutputFormat::Table => {
            println!("# Recall-parity gate (ARCH-05 / SPEC-08)");
            println!("  verdict       : {}", if r.verdict.passed { "PASS" } else { "FAIL" });
            println!("  aggregate     : {:.4}  (threshold {:.2})", r.aggregate, r.verdict.threshold);
            println!("  mean kappa    : {:.4}  (reliability gate >= 0.60)", r.mean_kappa);
            println!("  CRITICAL      : {}", r.verdict.critical_count);
            println!("  per dimension :");
            for ((d, k), (_, pk)) in r.dimension_kappas.iter().zip(r.dimension_parity_kappa.iter()) {
                println!("    {:<13} kappa={:.3}  parity_kappa={:.3}", d.as_str(), k, pk);
            }
            if !r.critical_queries.is_empty() {
                println!("  CRITICAL queries (a single one aborts cutover):");
                for (q, reason) in &r.critical_queries {
                    println!("    {q}: {reason:?}");
                }
            }
        }
    }
}

/// Emit one `0x3E EVAL_CRITICAL_DIVERGENCE` per CRITICAL query (HF-01 one-shot
/// pattern: skip if `neothd serve` owns the WAL; else open one writer for the batch).
async fn emit_critical_divergences(r: &ParityRunResult) {
    let pidfile = crate::daemon::pidfile::default_pidfile();
    if let Ok(Some(_)) = crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        tracing::debug!("recall-score: 0x3E audit skipped — neothd serve owns the WAL");
        return;
    }
    let segment = crate::config::FreedomConfig::default_neoth_home()
        .join("wal")
        .join("000001.wal");
    if let Some(parent) = segment.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let now = now_unix();
    match crate::wal::spawn(segment) {
        Ok((writer, join)) => {
            for (query_id, reason) in &r.critical_queries {
                let payload = serde_json::json!({
                    "query_id": query_id,
                    "reason": format!("{reason:?}"),
                    "ts_unix": now,
                })
                .to_string()
                .into_bytes();
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_EVAL_CRITICAL_DIVERGENCE,
                    &payload,
                )
                .build();
                if let Err(e) = writer.append(header, payload).await {
                    tracing::warn!(error = %e, "recall-score: 0x3E append failed");
                }
            }
            drop(writer);
            let _ = join.await;
        }
        Err(e) => tracing::warn!(error = %e, "recall-score: could not open WAL writer for 0x3E"),
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
